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

func (cl *Client) Search(ctx context.Context, filter string, attributes []string) ([]*ldap.Entry, error) {
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

	return result.Entries, nil
}
