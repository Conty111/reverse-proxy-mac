package usecase

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

type macLabel struct {
	Confidentiality uint8
	Categories      uint64
	Integrity       uint32
	Capabilities    uint64
}

// parseMacLabel parses a MAC (Mandatory Access Control) label string in the format:
// "confidentiality:categories:capabilities:integrity" where:
//   - confidentiality: decimal uint8 (0-255)
//   - categories: hexadecimal uint64 (e.g., 0x3F)
//   - capabilities: decimal uint64
//   - integrity: hexadecimal uint32 (e.g., 0x1A)
//
// Example: "2:3F:100:1A" represents confidentiality=2, categories=0x3F, capabilities=100, integrity=0x1A
func parseMacLabel(mac string) (*macLabel, error) {
	var label macLabel

	parts := strings.Split(mac, ":")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid MAC label '%s': expected format confidentiality:cats:caps:integrity", mac)
	}

	var confidentialityTmp, integrityTmp uint64

	_, err := fmt.Sscanf(parts[0], "%d", &confidentialityTmp)
	if err != nil || confidentialityTmp > 255 {
		return nil, fmt.Errorf("invalid confidentiality '%s': %w", parts[0], err)
	}
	label.Confidentiality = uint8(confidentialityTmp)

	if _, err := fmt.Sscanf(parts[1], "%x", &label.Categories); err != nil {
		return nil, fmt.Errorf("invalid categories '%s': %w", parts[1], err)
	}

	if _, err := fmt.Sscanf(parts[2], "%d", &label.Capabilities); err != nil {
		return nil, fmt.Errorf("invalid capabilities '%s': %w", parts[2], err)
	}

	_, err = fmt.Sscanf(parts[3], "%x", &integrityTmp)
	if err != nil || integrityTmp > 0xFFFFFFFF {
		return nil, fmt.Errorf("invalid integrity '%s': %w", parts[3], err)
	}
	label.Integrity = uint32(integrityTmp)

	return &label, nil
}

// validateHTTPMethod validates that the HTTP method is one of the standard methods
func validateHTTPMethod(method string) error {
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
		"TRACE":   true,
		"CONNECT": true,
	}

	if method == "" {
		return fmt.Errorf("HTTP method cannot be empty")
	}

	upperMethod := strings.ToUpper(method)
	if !validMethods[upperMethod] {
		return fmt.Errorf("invalid HTTP method: %s", method)
	}

	return nil
}

// extractHostFromHeader extracts the FQDN from the authorization request
// The Host header may contain port number (e.g., "example.com:8080"), which is stripped
func extractHostFromRequest(req *auth.AuthRequest) (string, error) {
	hostHeader, hasHostHeader := req.HTTPHeaders["host"]

	if !hasHostHeader {
		return "", fmt.Errorf("host header not present in request")
	}

	if hostHeader == "" {
		return "", fmt.Errorf("host header is empty")
	}

	host, err := url.Parse("http://" + hostHeader)
	if err != nil {
		return "", fmt.Errorf("failed to parse host: %w", err)
	}

	return host.Hostname(), nil
}

func GetHostSecurityContext(ctx context.Context, cl *ldap.Client, fqdn string) (*auth.HostSecurityContext, error) {
	hostEntry, err := cl.Search(ctx, fmt.Sprintf("(fqdn=%s)", fqdn), auth.AllMacHostAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search host in LDAP: %w", err)
	}
	if hostEntry == nil {
		return nil, fmt.Errorf("host not found")
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
