package cache

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bitset"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
	ldapclient "reverse-proxy-mac/src/infrastructure/ldap"
)

// CachedURIRule is the in-memory representation of a URIMACRule entry.
type CachedURIRule struct {
	ID        RuleID
	CN        string
	URIPath   string
	MatchType auth.URIMatchType
	MACLabel  auth.URISecurityContext
	// CompiledRegex is non-nil only for URIMatchRegex rules.
	CompiledRegex *regexp.Regexp
	// serviceRefs holds the lowercase FQDNs extracted from x-ald-uri-service-ref
	// attributes. Used during snapshot build to populate the host→ruleIDs map.
	serviceRefs []string
}

// snapshot is an immutable, fully-built cache state swapped in atomically.
type snapshot struct {
	hosts    *HostTrie
	uriTrie  *URITrie
	// regexRules contains only URIMatchRegex rules.
	regexRules []*CachedURIRule
	// allRules is the flat slice indexed by RuleID, used for O(1) rule lookup.
	allRules []*CachedURIRule
}

// parseMacLabel parses "confMin:catsMin:confMax:catsMax" (hex or decimal).
func parseMacLabel(mac string) (confMin, confMax uint8, catsMin, catsMax uint64, err error) {
	parts := strings.Split(mac, ":")
	if len(parts) != 4 {
		return 0, 0, 0, 0, fmt.Errorf("invalid MAC label %q: expected confMin:catsMin:confMax:catsMax", mac)
	}
	var tmp uint64
	if tmp, err = strconv.ParseUint(parts[0], 0, 8); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid confMin %q: %w", parts[0], err)
	}
	confMin = uint8(tmp)
	if catsMin, err = strconv.ParseUint(parts[1], 0, 64); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid catsMin %q: %w", parts[1], err)
	}
	if tmp, err = strconv.ParseUint(parts[2], 0, 8); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid confMax %q: %w", parts[2], err)
	}
	confMax = uint8(tmp)
	if catsMax, err = strconv.ParseUint(parts[3], 0, 64); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid catsMax %q: %w", parts[3], err)
	}
	return confMin, confMax, catsMin, catsMax, nil
}

// loadSnapshot fetches all hosts and URI rules from LDAP and builds a new
// immutable snapshot ready to be swapped into the cache.
func loadSnapshot(ctx context.Context, cl *ldapclient.Client, log logger.Logger) (*snapshot, error) {
	// ------------------------------------------------------------------ URI rules
	uriEntries, err := cl.Search(ctx, "(objectClass=aldURIMACRule)", auth.AllURIMACAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search URI MAC rules: %w", err)
	}

	allRules := make([]*CachedURIRule, 0, len(uriEntries))
	uriTrie := NewURITrie()
	var regexRules []*CachedURIRule

	for _, entry := range uriEntries {
		uriPath := entry.GetAttributeValue(auth.URIPathAttribute)
		if uriPath == "" {
			continue
		}
		macValue := entry.GetAttributeValue(auth.URIMacAttribute)
		if macValue == "" {
			continue
		}

		matchType := auth.URIMatchType(entry.GetAttributeValue(auth.URIMatchTypeAttribute))
		if matchType == "" {
			matchType = auth.URIMatchExact
		}

		confMin, confMax, catsMin, catsMax, err := parseMacLabel(macValue)
		if err != nil {
			log.Warn(ctx, "cache loader: skipping URI rule with invalid MAC label", map[string]interface{}{
				"cn":    entry.GetAttributeValue("cn"),
				"error": err.Error(),
			})
			continue
		}

		var integrityCategories uint32
		micValue := entry.GetAttributeValue(auth.URIIntegrityCategoriesAttribute)
		if micValue != "" {
			parsed, err := strconv.ParseUint(micValue, 0, 32)
			if err != nil {
				log.Warn(ctx, "cache loader: skipping URI rule with invalid integrity categories", map[string]interface{}{
					"cn":    entry.GetAttributeValue("cn"),
					"error": err.Error(),
				})
				continue
			}
			integrityCategories = uint32(parsed)
		}

		// Extract service-ref FQDNs now, while we have the entry.
		rawRefs := entry.GetAttributeValues(auth.URIServiceRefAttribute)
		fqdns := make([]string, 0, len(rawRefs))
		for _, ref := range rawRefs {
			if fqdn := extractFQDNFromServiceRef(ref); fqdn != "" {
				fqdns = append(fqdns, fqdn)
			}
		}

		id := RuleID(len(allRules))
		rule := &CachedURIRule{
			ID:        id,
			CN:        entry.GetAttributeValue("cn"),
			URIPath:   uriPath,
			MatchType: matchType,
			MACLabel: auth.URISecurityContext{
				Path:                uriPath,
				ConfidentialityMin:  confMin,
				CategoriesMin:       catsMin,
				ConfidentialityMax:  confMax,
				CategoriesMax:       catsMax,
				IntegrityCategories: integrityCategories,
			},
			serviceRefs: fqdns,
		}

		switch matchType {
		case auth.URIMatchExact:
			uriTrie.AddExact(uriPath, id)
		case auth.URIMatchPrefix:
			uriTrie.AddPrefix(uriPath, id)
		case auth.URIMatchRegex:
			re, err := regexp.Compile(uriPath)
			if err != nil {
				log.Warn(ctx, "cache loader: skipping URI rule with invalid regex", map[string]interface{}{
					"cn":      rule.CN,
					"pattern": uriPath,
					"error":   err.Error(),
				})
				continue
			}
			rule.CompiledRegex = re
			regexRules = append(regexRules, rule)
		}

		allRules = append(allRules, rule)
	}

	log.Info(ctx, "cache loader: URI rules loaded", map[string]interface{}{
		"total": len(allRules),
		"regex": len(regexRules),
	})

	// ------------------------------------------------------------------ Build host→ruleIDs map
	// hostRuleMap: lowercase FQDN → bitset of rule IDs bound to that host.
	hostRuleMap := make(map[string]*bitset.BitSet, len(allRules))
	for _, rule := range allRules {
		for _, fqdn := range rule.serviceRefs {
			bs, ok := hostRuleMap[fqdn]
			if !ok {
				bs = bitset.New(uint(len(allRules)))
				hostRuleMap[fqdn] = bs
			}
			bs.Set(rule.ID)
		}
	}

	// ------------------------------------------------------------------ Hosts
	hostEntries, err := cl.Search(ctx, fmt.Sprintf("(%s=*)", auth.HostMacAttribute), auth.AllMacHostAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search hosts: %w", err)
	}

	hostTrie := NewHostTrie()

	for _, entry := range hostEntries {
		// The host FQDN is stored in the "fqdn" attribute.
		fqdn := entry.GetAttributeValue("fqdn")
		if fqdn == "" {
			fqdn = entry.GetAttributeValue("cn")
		}
		if fqdn == "" {
			continue
		}

		macValue := entry.GetAttributeValue(auth.HostMacAttribute)
		if macValue == "" {
			continue
		}

		confMin, confMax, catsMin, catsMax, err := parseMacLabel(macValue)
		if err != nil {
			log.Warn(ctx, "cache loader: skipping host with invalid MAC label", map[string]interface{}{
				"fqdn":  fqdn,
				"error": err.Error(),
			})
			continue
		}

		var integrityCategories uint32
		micValue := entry.GetAttributeValue(auth.HostIntegrityCategoriesAttribute)
		if micValue != "" {
			parsed, err := strconv.ParseUint(micValue, 0, 32)
			if err != nil {
				log.Warn(ctx, "cache loader: skipping host with invalid integrity categories", map[string]interface{}{
					"fqdn":  fqdn,
					"error": err.Error(),
				})
				continue
			}
			integrityCategories = uint32(parsed)
		}

		ruleIDs := hostRuleMap[strings.ToLower(fqdn)]
		if ruleIDs == nil {
			ruleIDs = bitset.New(0)
		}

		hostTrie.Add(fqdn, &CachedHost{
			SecurityContext: auth.HostSecurityContext{
				ConfidentialityMin:  confMin,
				CategoriesMin:       catsMin,
				ConfidentialityMax:  confMax,
				CategoriesMax:       catsMax,
				IntegrityCategories: integrityCategories,
			},
			RuleIDs: ruleIDs,
		})
	}

	log.Info(ctx, "cache loader: hosts loaded", map[string]interface{}{
		"total": len(hostEntries),
	})

	return &snapshot{
		hosts:      hostTrie,
		uriTrie:    uriTrie,
		regexRules: regexRules,
		allRules:   allRules,
	}, nil
}

// extractFQDNFromServiceRef extracts the host FQDN from a Kerberos principal DN.
// Example input: "krbprincipalname=HTTP/api.example.com@REALM,cn=services,dc=example,dc=com"
// Returns "api.example.com" (lowercase).
func extractFQDNFromServiceRef(ref string) string {
	ref = strings.ToLower(ref)
	// Find "http/" prefix inside the DN value.
	const prefix = "http/"
	idx := strings.Index(ref, prefix)
	if idx < 0 {
		return ""
	}
	rest := ref[idx+len(prefix):]
	// The FQDN ends at '@' (realm separator) or ',' (next DN component).
	end := strings.IndexAny(rest, "@,")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
