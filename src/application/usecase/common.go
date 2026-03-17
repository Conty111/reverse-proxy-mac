package usecase

import (
	"context"
	"fmt"
	"strings"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

// parseMacLabel parses a MAC (Mandatory Access Control) label string in the format:
// "level:categories:capabilities:integrity" where:
//   - level: decimal uint8 (0-255)
//   - categories: hexadecimal uint64 (e.g., 0x3F)
//   - capabilities: decimal uint64
//   - integrity: hexadecimal uint32 (e.g., 0x1A)
//
// Example: "2:3F:100:1A" represents level=2, categories=0x3F, capabilities=100, integrity=0x1A
func parseMacLabel(mac string) (level uint8, cats uint64, caps uint64, integrity uint32, err error) {
	parts := strings.Split(mac, ":")
	if len(parts) != 4 {
		return 0, 0, 0, 0, fmt.Errorf("invalid MAC label '%s': expected format level:cats:caps:integrity", mac)
	}

	var levelTmp, integrityTmp uint64

	if _, err := fmt.Sscanf(parts[0], "%d", &levelTmp); err != nil || levelTmp > 255 {
		return 0, 0, 0, 0, fmt.Errorf("invalid level '%s': %w", parts[0], err)
	}
	if _, err := fmt.Sscanf(parts[1], "%x", &cats); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid categories '%s': %w", parts[1], err)
	}
	if _, err := fmt.Sscanf(parts[2], "%d", &caps); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid capabilities '%s': %w", parts[2], err)
	}
	if _, err := fmt.Sscanf(parts[3], "%x", &integrityTmp); err != nil || integrityTmp > 0xFFFFFFFF {
		return 0, 0, 0, 0, fmt.Errorf("invalid integrity '%s': %w", parts[3], err)
	}

	return uint8(levelTmp), cats, caps, uint32(integrityTmp), nil
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

	// Remove port if present (e.g., "example.com:8080" -> "example.com")
	host := hostHeader
	if colonIndex := strings.LastIndex(hostHeader, ":"); colonIndex != -1 {
		// Check if it's IPv6 address (contains multiple colons)
		if strings.Count(hostHeader, ":") > 1 {
			// IPv6 address - remove brackets if present
			host = strings.Trim(hostHeader, "[]")
		} else {
			// Regular hostname with port
			host = hostHeader[:colonIndex]
		}
	}

	host = strings.TrimSpace(host)

	if host == "" {
		return "", fmt.Errorf("invalid Host header format: %s", hostHeader)
	}

	return host, nil
}

func GetHostSecurityContext(ctx context.Context, cl *ldap.Client, fqdn string) (*auth.HostSecurityContext, error) {
	hostEntry, err := cl.Search(ctx, fmt.Sprintf("(fqdn=%s)", fqdn), auth.AllMacHostAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search host in LDAP: %w", err)
	}
	if hostEntry == nil {
		return nil, fmt.Errorf("host not found")
	}

	var level uint8
	var categories uint64
	var capabilities uint64
	var integrityLevel uint32

	macValue := hostEntry.GetAttributeValue(auth.HostMacAttribute)
	if macValue == "" {
		return nil, fmt.Errorf("host MAC attribute '%s' is empty or not found", auth.HostMacAttribute)
	}

	level, categories, capabilities, integrityLevel, err = parseMacLabel(macValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC label for host: %w", err)
	}

	return &auth.HostSecurityContext{
		Categories:   categories,
		Level:        level,
		Capabilities: capabilities,
		Integrity:    integrityLevel,
	}, nil
}

func checkMACAccess(subject, object auth.SecurityContext, isWriteOperation bool) (bool, string) {
	objectLevel := object.GetLevel()
	userLevel := subject.GetLevel()

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
