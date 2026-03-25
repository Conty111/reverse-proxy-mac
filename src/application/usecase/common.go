package usecase

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

const (
	macLabelParts      = 4
	maxConfidentiality = 255
)

var (
	errEmptyHTTPMethod = errors.New("HTTP method cannot be empty")
	errHostNotFound    = errors.New("host not found")
	errUserNotFound    = errors.New("user not found")
)

type macLabel struct {
	ConfMin uint8
	CatsMin uint64
	ConfMax uint8
	CatsMax uint64
}

// parseMacLabel parses a MAC label string in format "confidentiality-min:categories-min:confidentiality-max:categories-max".
// Example: "2:0x1:3:0xFF" represents confMin=2, catsMin=0x1, confMax=3, catsMax=0xFF
func parseMacLabel(mac string) (*macLabel, error) {
	parts := strings.Split(mac, ":")
	if len(parts) != macLabelParts {
		return nil, fmt.Errorf("invalid MAC label '%s': expected format confMin:catsMin:confMax:catsMax", mac)
	}

	var label macLabel
	var confMinTmp, confMaxTmp uint64

	if _, err := fmt.Sscanf(parts[0], "%d", &confMinTmp); err != nil {
		return nil, fmt.Errorf("invalid confidentiality-min '%s': %w", parts[0], err)
	}
	if confMinTmp > maxConfidentiality {
		return nil, fmt.Errorf("confidentiality-min value %d exceeds maximum %d", confMinTmp, maxConfidentiality)
	}
	label.ConfMin = uint8(confMinTmp)

	if _, err := fmt.Sscanf(parts[1], "%x", &label.CatsMin); err != nil {
		return nil, fmt.Errorf("invalid categories-min '%s': %w", parts[1], err)
	}

	if _, err := fmt.Sscanf(parts[2], "%d", &confMaxTmp); err != nil {
		return nil, fmt.Errorf("invalid confidentiality-max '%s': %w", parts[2], err)
	}
	if confMaxTmp > maxConfidentiality {
		return nil, fmt.Errorf("confidentiality-max value %d exceeds maximum %d", confMaxTmp, maxConfidentiality)
	}
	label.ConfMax = uint8(confMaxTmp)

	if _, err := fmt.Sscanf(parts[3], "%x", &label.CatsMax); err != nil {
		return nil, fmt.Errorf("invalid categories-max '%s': %w", parts[3], err)
	}

	return &label, nil
}

func GetHostSecurityContext(ctx context.Context, cl *ldap.Client, fqdn string) (*auth.HostSecurityContext, error) {
	hostEntries, err := cl.Search(ctx, fmt.Sprintf("(fqdn=%s)", fqdn), auth.AllMacHostAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search host in LDAP: %w", err)
	}
	if len(hostEntries) == 0 {
		return nil, errHostNotFound
	}
	if len(hostEntries) > 1 {
		cl.Logger.Warn(ctx, "multiple hosts found", map[string]interface{}{
			"count": len(hostEntries),
		})
	}
	hostEntry := hostEntries[0]

	macValue := hostEntry.GetAttributeValue(auth.HostMacAttribute)
	if macValue == "" {
		return nil, fmt.Errorf("host MAC attribute '%s' is empty or not found", auth.HostMacAttribute)
	}

	label, err := parseMacLabel(macValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC label for host: %w", err)
	}

	var integrityCategories uint32 = 0
	categoryAttribute := hostEntry.GetAttributeValue(auth.HostIntegrityCategoriesAttribute)
	if categoryAttribute != "" {
		category, err := strconv.ParseUint(categoryAttribute, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse integrity categories for host: %w", err)
		}
		integrityCategories = uint32(category)
	}

	return &auth.HostSecurityContext{
		ConfidentialityMin:  label.ConfMin,
		CategoriesMin:       label.CatsMin,
		ConfidentialityMax:  label.ConfMax,
		CategoriesMax:       label.CatsMax,
		IntegrityCategories: integrityCategories,
	}, nil
}

func checkMACAccess(subject, object auth.SecurityContext, isWriteOperation bool) (bool, string) {
	objectConfMin := object.GetConfidentialityMin()
	objectConfMax := object.GetConfidentialityMax()
	objectCatsMin := object.GetCategoriesMin()

	subjectConfMin := subject.GetConfidentialityMin()
	subjectConfMax := subject.GetConfidentialityMax()
	subjectCatsMin := subject.GetCategoriesMin()
	subjectCatsMax := subject.GetCategoriesMax()

	if isWriteOperation {
		// Write operations: exact match required for confidentiality and categories
		if subjectConfMin != objectConfMin || subjectConfMax != objectConfMax {
			return false, fmt.Sprintf("MAC: write operation denied - user confidentiality range [%d, %d] != object range [%d, %d]",
				subjectConfMin, subjectConfMax, objectConfMin, objectConfMax)
		}
		if subjectCatsMin != objectCatsMin {
			return false, fmt.Sprintf("MAC: write operation denied - user categories min 0x%x != object categories min 0x%x",
				subjectCatsMin, objectCatsMin)
		}
	} else {
		// Read operations: ranges must overlap
		// object.ConfMin <= user.ConfMax AND user.ConfMin <= object.ConfMax
		if objectConfMin > subjectConfMax || subjectConfMin > objectConfMax {
			return false, fmt.Sprintf("MAC: read operation denied - user confidentiality range [%d, %d] does not overlap with object range [%d, %d]",
				subjectConfMin, subjectConfMax, objectConfMin, objectConfMax)
		}

		// User must have all categories that the object requires (min categories)
		// (user.CategoriesMax & object.CategoriesMin) == object.CategoriesMin
		if (subjectCatsMax & objectCatsMin) != objectCatsMin {
			return false, fmt.Sprintf("MAC: read operation denied - user categories max 0x%x do not include all required object categories min 0x%x",
				subjectCatsMax, objectCatsMin)
		}
	}

	// Check integrity categories
	// User's integrity categories must include all bits of object's integrity categories
	subjectIntegrityCategories := subject.GetIntegrityCategories()
	objectIntegrityCategories := object.GetIntegrityCategories()
	if (subjectIntegrityCategories & objectIntegrityCategories) != objectIntegrityCategories {
		return false, fmt.Sprintf("MAC: access denied - user integrity categories 0x%x do not include all required object integrity categories 0x%x",
			subjectIntegrityCategories, objectIntegrityCategories)
	}

	return true, "MAC: access granted - all security checks passed"
}
