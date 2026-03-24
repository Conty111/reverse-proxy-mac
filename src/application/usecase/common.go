package usecase

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

const (
	macLabelParts      = 4
	maxConfidentiality = 255
	maxIntegrity       = 0xFFFFFFFF
)

var (
	errEmptyHTTPMethod = errors.New("HTTP method cannot be empty")
	errHostNotFound    = errors.New("host not found")
	errUserNotFound    = errors.New("user not found")
)

type macLabel struct {
	Confidentiality uint8
	Categories      uint64
	Integrity       uint32
	Capabilities    uint64
}

// parseMacLabel parses a MAC label string in format "confidentiality:categories:capabilities:integrity".
// Example: "2:3F:100:1A" represents confidentiality=2, categories=0x3F, capabilities=100, integrity=0x1A
func parseMacLabel(mac string) (*macLabel, error) {
	parts := strings.Split(mac, ":")
	if len(parts) != macLabelParts {
		return nil, fmt.Errorf("invalid MAC label '%s': expected format confidentiality:cats:caps:integrity", mac)
	}

	var label macLabel
	var confidentialityTmp, integrityTmp uint64

	if _, err := fmt.Sscanf(parts[0], "%d", &confidentialityTmp); err != nil {
		return nil, fmt.Errorf("invalid confidentiality '%s': %w", parts[0], err)
	}
	if confidentialityTmp > maxConfidentiality {
		return nil, fmt.Errorf("confidentiality value %d exceeds maximum %d", confidentialityTmp, maxConfidentiality)
	}
	label.Confidentiality = uint8(confidentialityTmp)

	if _, err := fmt.Sscanf(parts[1], "%x", &label.Categories); err != nil {
		return nil, fmt.Errorf("invalid categories '%s': %w", parts[1], err)
	}

	if _, err := fmt.Sscanf(parts[2], "%d", &label.Capabilities); err != nil {
		return nil, fmt.Errorf("invalid capabilities '%s': %w", parts[2], err)
	}

	if _, err := fmt.Sscanf(parts[3], "%x", &integrityTmp); err != nil {
		return nil, fmt.Errorf("invalid integrity '%s': %w", parts[3], err)
	}
	if integrityTmp > maxIntegrity {
		return nil, fmt.Errorf("integrity value %d exceeds maximum %d", integrityTmp, maxIntegrity)
	}
	label.Integrity = uint32(integrityTmp)

	return &label, nil
}

var validHTTPMethods = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"DELETE":  {},
	"PATCH":   {},
	"HEAD":    {},
	"OPTIONS": {},
	"TRACE":   {},
	"CONNECT": {},
}

func validateHTTPMethod(method string) error {
	if method == "" {
		return errEmptyHTTPMethod
	}

	if _, ok := validHTTPMethods[strings.ToUpper(method)]; !ok {
		return fmt.Errorf("invalid HTTP method: %s", method)
	}

	return nil
}

// extractHostFromRequest extracts the FQDN from the authorization request.
// The Host header may contain port number (e.g., "example.com:8080"), which is stripped.
func extractHostFromRequest(req *auth.AuthRequest) (string, error) {
	hostHeader, ok := req.HTTPHeaders["host"]
	if !ok || hostHeader == "" {
		return "", errors.New("host header not present or empty in request")
	}

	parsed, err := url.Parse("http://" + hostHeader)
	if err != nil {
		return "", fmt.Errorf("failed to parse host header: %w", err)
	}

	return parsed.Hostname(), nil
}

func GetHostSecurityContext(ctx context.Context, cl *ldap.Client, fqdn string) (*auth.HostSecurityContext, error) {
	hostEntry, err := cl.Search(ctx, fmt.Sprintf("(fqdn=%s)", fqdn), auth.AllMacHostAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search host in LDAP: %w", err)
	}
	if hostEntry == nil {
		return nil, errHostNotFound
	}

	macValue := hostEntry.GetAttributeValue(auth.HostMacAttribute)
	if macValue == "" {
		return nil, fmt.Errorf("host MAC attribute '%s' is empty or not found", auth.HostMacAttribute)
	}

	label, err := parseMacLabel(macValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC label for host: %w", err)
	}

	return &auth.HostSecurityContext{
		Categories:      label.Categories,
		Confidentiality: label.Confidentiality,
		Capabilities:    label.Capabilities,
		Integrity:       label.Integrity,
	}, nil
}

// parseMatchType converts the raw LDAP string value of x-ald-uri-match-type to a URIMatchType.
// Absent or unrecognised values default to URIMatchExact.
func parseMatchType(raw string) auth.URIMatchType {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(auth.URIMatchPrefix):
		return auth.URIMatchPrefix
	case string(auth.URIMatchRegex):
		return auth.URIMatchRegex
	default:
		return auth.URIMatchExact
	}
}

// GetURIMACRules retrieves all URI MAC rules from LDAP that are bound to the given host FQDN.
// Rules are stored as aldURIMACRule structural entries and carry a MAC label for a URI path.
// URI MAC rules are bound to hosts/host-groups.
func GetURIMACRules(ctx context.Context, cl *ldap.Client, hostFQDN string) ([]*auth.URIMACRule, error) {
	filter := fmt.Sprintf(
		"(&(objectClass=aldURIMACRule)(x-ald-uri-host=%s))",
		goldap.EscapeFilter(hostFQDN),
	)

	entries, err := cl.SearchAll(ctx, filter, auth.AllURIMACRuleAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search URI MAC rules in LDAP: %w", err)
	}

	rules := make([]*auth.URIMACRule, 0, len(entries))
	for _, entry := range entries {
		macValue := entry.GetAttributeValue(auth.URIMacAttribute)
		if macValue == "" {
			continue
		}

		label, err := parseMacLabel(macValue)
		if err != nil {
			cl.Logger.Warn(ctx, "Skipping URI MAC rule with invalid label", map[string]interface{}{
				"dn":    entry.DN,
				"error": err.Error(),
			})
			continue
		}

		uriPath := entry.GetAttributeValue(auth.URIPathAttribute)
		if uriPath == "" {
			continue
		}

		matchType := parseMatchType(entry.GetAttributeValue(auth.URIMatchTypeAttribute))

		// Pre-validate regex patterns at load time so we don't fail at match time.
		if matchType == auth.URIMatchRegex {
			if _, err := regexp.Compile(uriPath); err != nil {
				cl.Logger.Warn(ctx, "Skipping URI MAC rule with invalid regex", map[string]interface{}{
					"dn":    entry.DN,
					"path":  uriPath,
					"error": err.Error(),
				})
				continue
			}
		}

		rule := &auth.URIMACRule{
			CN:        entry.GetAttributeValue("cn"),
			URIPath:   uriPath,
			MatchType: matchType,
			MACLabel: auth.URISecurityContext{
				Path:            uriPath,
				Confidentiality: label.Confidentiality,
				Categories:      label.Categories,
				Capabilities:    label.Capabilities,
				Integrity:       label.Integrity,
			},
			HostFQDNs:   entry.GetAttributeValues(auth.URIHostAttribute),
			HostGroups:  entry.GetAttributeValues(auth.URIHostGroupAttribute),
			Description: entry.GetAttributeValue(auth.URIDescriptionAttribute),
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// MatchURIMACRule finds the most specific URI MAC rule that matches the given URI path.
//
// Match type priority (highest to lowest):
//  1. Exact match
//  2. Prefix match (longest prefix wins)
//  3. Regex match (longest pattern string wins as a tiebreaker)
//
// Returns nil if no rule matches.
func MatchURIMACRule(rules []*auth.URIMACRule, uriPath string) *auth.URIMACRule {
	var bestExact *auth.URIMACRule
	var bestPrefix *auth.URIMACRule
	var bestRegex *auth.URIMACRule

	for _, rule := range rules {
		switch rule.MatchType {
		case auth.URIMatchExact:
			if rule.URIPath == uriPath {
				bestExact = rule
			}

		case auth.URIMatchPrefix:
			// The request path must start with the rule prefix.
			// A prefix "/api" matches "/api", "/api/", "/api/foo" but not "/apifoo".
			prefix := rule.URIPath
			if strings.HasPrefix(uriPath, prefix) {
				rest := uriPath[len(prefix):]
				if rest == "" || rest[0] == '/' {
					if bestPrefix == nil || len(prefix) > len(bestPrefix.URIPath) {
						bestPrefix = rule
					}
				}
			}

		case auth.URIMatchRegex:
			matched, err := regexp.MatchString("^(?:"+rule.URIPath+")$", uriPath)
			if err == nil && matched {
				if bestRegex == nil || len(rule.URIPath) > len(bestRegex.URIPath) {
					bestRegex = rule
				}
			}
		}
	}

	if bestExact != nil {
		return bestExact
	}
	if bestPrefix != nil {
		return bestPrefix
	}
	return bestRegex
}

func checkMACAccess(subject, object auth.SecurityContext, isWriteOperation bool) (bool, string) {
	objectLevel := object.GetConfidentiality()
	userLevel := subject.GetConfidentiality()

	if isWriteOperation {
		// Write operations: user level must equal host level
		if userLevel != objectLevel {
			return false, fmt.Sprintf("MAC: write operation denied - user level %d != host level %d",
				userLevel, objectLevel)
		}
	} else {
		// Read operations: user level must be >= host level
		if userLevel < objectLevel {
			return false, fmt.Sprintf("MAC: read operation denied - user level %d < host level %d",
				userLevel, objectLevel)
		}
	}

	// User must have all categories that the host requires
	// Categories are represented as bitmasks
	requiredCategories := object.GetCategories()
	userCategories := subject.GetCategories()

	// Check if user has all required categories (bitwise AND should equal required categories)
	if (userCategories & requiredCategories) != requiredCategories {
		return false, fmt.Sprintf("MAC: access denied - user categories 0x%x do not include all required categories 0x%x",
			userCategories, requiredCategories)
	}

	// Check integrity level (MIC - Mandatory Integrity Control)
	// User's integrity level must be >= host's integrity level
	if subject.GetIntegrity() < object.GetIntegrity() {
		return false, fmt.Sprintf("MAC: access denied - user integrity 0x%x < host integrity 0x%x",
			subject.GetIntegrity(), object.GetIntegrity())
	}

	// Check capabilities
	// User must have all capabilities that the host requires
	requiredCapabilities := object.GetCapabilities()
	userCapabilities := subject.GetCapabilities()

	if (userCapabilities & requiredCapabilities) != requiredCapabilities {
		return false, fmt.Sprintf("MAC: access denied - user capabilities 0x%x do not include all required capabilities 0x%x",
			userCapabilities, requiredCapabilities)
	}

	return true, "MAC: access granted - all security checks passed"
}
