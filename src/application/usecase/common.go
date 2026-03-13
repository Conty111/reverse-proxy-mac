package usecase

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

func parseMacLabel(mac string) (level uint8, cats uint64, err error) {
	parts := strings.Split(mac, ":")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("invalid MAC label format")
	}
	fmt.Sscanf(parts[0], "%d", &level)
	fmt.Sscanf(parts[1], "%x", &cats)
	return
}

func GetHostSecurityContext(ctx context.Context, cl ldap.Client, fqdn string) (*auth.HostSecurityContext, error) {
	hostEntry, err := cl.Search(ctx, fmt.Sprintf("(fqdn=%s)", fqdn), auth.AllMacHostAttributes)
	if err != nil {
		return nil, fmt.Errorf("Failed to search host in LDAP: %w", err)
	}
	if hostEntry == nil {
		return nil, fmt.Errorf("Host not found")
	}

	var level uint8
	var categories uint64
	var capabilities int = 0
	var integrityLevel int = 0

	level, categories, err = parseMacLabel(hostEntry.GetAttributeValue(auth.HostMacAttribute))
	if err != nil {
		return nil, fmt.Errorf("Failed to parse MAC label for host: %w", err)
	}

	caps := hostEntry.GetAttributeValue(auth.HostCapabilitiesAttribute)
	if caps != "" {
		capabilities, err = strconv.Atoi(caps)
		if err != nil {
			return nil, fmt.Errorf("Failed to convert HostCapabilitiesAttribute to int: %w", err)
		}
	}

	// TODO: parse mic-levet attribute as a bitmask string (example - "0x3F")
	// micLevel := hostEntry.GetAttributeValue(auth.HostIntegrityLevelAttribute)
	// if micLevel != "" {
	// 	integrityLevel, err = strconv.Atoi(micLevel)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Failed to convert HostIntegrityLevelAttribute to int: %w", err)
	// 	}
	// }

	return &auth.HostSecurityContext{
		Categories: categories,
		Level: level,
		Capabilities: uint64(capabilities),
		Integrity: uint32(integrityLevel),
	}, nil
}

func GetUserHTTPSecurityContext(ctx context.Context, cl ldap.Client, username, httpMethod string) (*auth.UserHTTPSecurityContext, error) {
	userEntry, err := cl.Search(ctx, fmt.Sprintf("(uid=%s)", username), auth.AllMacHostAttributes)
	if err != nil {
		return nil, fmt.Errorf("Failed to search user in LDAP: %w", err)
	}
	if userEntry == nil {
		return nil, fmt.Errorf("User not found")
	}

	var level uint8
	var categories uint64
	var capabilities int = 0
	var integrityLevel int = 0

	level, categories, err = parseMacLabel(userEntry.GetAttributeValue(auth.UserMacAttribute))
	if err != nil {
		return nil, fmt.Errorf("Failed to parse MAC label for user: %w", err)
	}

	caps := userEntry.GetAttributeValue(auth.UserCapabilitiesAttribute)
	if caps != "" {
		capabilities, err = strconv.Atoi(caps)
		if err != nil {
			return nil, fmt.Errorf("Failed to convert HostCapabilitiesAttribute to int: %w", err)
		}
	}

	// TODO: parse mic-levet attribute as a bitmask string (example - "0x3F")
	// micLevel := userEntry.GetAttributeValue(auth.UserIntegrityLevelAttribute)
	// if micLevel != "" {
	// 	integrityLevel, err = strconv.Atoi(micLevel)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Failed to convert HostIntegrityLevelAttribute to int: %w", err)
	// 	}
	// }

	// TODO: validate httpMethod

	return &auth.UserHTTPSecurityContext{
		RequestMethod: httpMethod,
		Categories: categories,
		Level: level,
		Capabilities: uint64(capabilities),
		Integrity: uint32(integrityLevel),
	}, nil
}