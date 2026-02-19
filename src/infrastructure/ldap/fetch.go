package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func (cl *Client) SearchUser(ctx context.Context, username string) (*UserInfo, error) {
	cl.logger.Debug(ctx, "Starting LDAP user search", map[string]interface{}{
		"username": username,
	})

	searchFilter := fmt.Sprintf(cl.userFilter, ldap.EscapeFilter(username))

	searchRequest := ldap.NewSearchRequest(
		cl.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		searchFilter,
		[]string{"mail", "userPrincipalName", "sAMAccountName"},
		nil,
	)

	cl.logger.Debug(ctx, "Searching for user in LDAP", map[string]interface{}{
		"username": username,
		"filter":   searchFilter,
		"base_dn":  cl.baseDN,
	})

	result, err := cl.ldapConnection.Search(searchRequest)
	if err != nil {
		cl.logger.Error(ctx, "LDAP search query failed", map[string]interface{}{
			"username": username,
			"filter":   searchFilter,
			"base_dn":  cl.baseDN,
			"error":    err.Error(),
		})
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		cl.logger.Warn(ctx, "User not found in LDAP directory", map[string]interface{}{
			"username": username,
			"filter":   searchFilter,
			"base_dn":  cl.baseDN,
		})
		return nil, fmt.Errorf("user not found: %s", username)
	}

	if len(result.Entries) > 1 {
		cl.logger.Warn(ctx, "Multiple LDAP entries found for user", map[string]interface{}{
			"username": username,
			"count":    len(result.Entries),
		})
	}

	entry := result.Entries[0]

	// Extract email - try mail attribute first, then userPrincipalName
	email := entry.GetAttributeValue("mail")
	if email == "" {
		email = entry.GetAttributeValue("userPrincipalName")
	}

	cl.logger.Info(ctx, "User found in LDAP", map[string]interface{}{
		"username": username,
		"dn":       entry.DN,
		"email":    email,
	})

	return &UserInfo{
		Email: email,
	}, nil
}
