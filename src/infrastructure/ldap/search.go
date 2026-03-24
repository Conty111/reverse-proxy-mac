package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func realmToDN(realm string) string {
	parts := strings.Split(strings.ToLower(realm), ".")
	dnParts := make([]string, len(parts))
	for i, part := range parts {
		dnParts[i] = "dc=" + part
	}
	return strings.Join(dnParts, ",")
}

func (cl *Client) Search(ctx context.Context, filter string, attributes []string) (*ldap.Entry, error) {
	baseDN := cl.baseDN
	if baseDN == "" {
		baseDN = realmToDN(cl.kerberosRealm)
	}

	cl.Logger.Info(ctx, "Search request in LDAP", map[string]interface{}{
		"filter":     filter,
		"basedn":     baseDN,
		"attributes": attributes,
	})
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)
	result, err := cl.ldapConnection.Search(searchRequest)
	if err != nil {
		cl.Logger.Error(ctx, "LDAP search request failed", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		cl.Logger.Warn(ctx, "Empty search request result", map[string]interface{}{})
		return nil, nil
	}

	if len(result.Entries) > 1 {
		cl.Logger.Warn(ctx, "Multiple LDAP entries found", map[string]interface{}{
			"count": len(result.Entries),
		})
	}

	// Log all attributes returned from LDAP for debugging
	entry := result.Entries[0]
	attrs := make(map[string]interface{})
	for _, attr := range entry.Attributes {
		if len(attr.Values) > 0 {
			attrs[attr.Name] = attr.Values
		}
	}
	cl.Logger.Debug(ctx, "LDAP entry attributes", map[string]interface{}{
		"dn":         entry.DN,
		"attributes": attrs,
	})

	return entry, nil
}

// SearchAll performs an LDAP search and returns all matching entries.
func (cl *Client) SearchAll(ctx context.Context, filter string, attributes []string) ([]*ldap.Entry, error) {
	baseDN := cl.baseDN
	if baseDN == "" {
		baseDN = realmToDN(cl.kerberosRealm)
	}

	cl.Logger.Info(ctx, "SearchAll request in LDAP", map[string]interface{}{
		"filter":     filter,
		"basedn":     baseDN,
		"attributes": attributes,
	})
	
	cl.Logger.Debug(ctx, "LDAP client configuration", map[string]interface{}{
		"host": cl.host,
		"port": cl.port,
		"baseDN": cl.baseDN,
		"kerberosRealm": cl.kerberosRealm,
		"useTLS": cl.useTLS,
	})

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	result, err := cl.ldapConnection.Search(searchRequest)
	if err != nil {
		cl.Logger.Error(ctx, "LDAP search request failed", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	cl.Logger.Info(ctx, "LDAP search completed", map[string]interface{}{
		"entries_count": len(result.Entries),
	})

	// Debug: Try a broader search to see if there are any entries at all
	if len(result.Entries) == 0 {
		cl.Logger.Debug(ctx, "No entries found with specific filter, trying broader search", map[string]interface{}{
			"original_filter": filter,
		})
		
		// Try searching for any object to verify connection and base DN
		testSearchRequest := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"*"},
			nil,
		)
		testResult, testErr := cl.ldapConnection.Search(testSearchRequest)
		if testErr != nil {
			cl.Logger.Warn(ctx, "Base object search failed", map[string]interface{}{
				"error": testErr.Error(),
			})
		} else {
			cl.Logger.Debug(ctx, "Base object search result", map[string]interface{}{
				"entries_count": len(testResult.Entries),
			})
		}
	}

	return result.Entries, nil
}
