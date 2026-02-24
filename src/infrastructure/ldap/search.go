package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

var defaultUserAttributes []string = []string{
	"dn",
	"uid",
	"cn",
	"sn",
	"mail",
	"memberOf",
	"uidNumber",
	"gidNumber",
	"krbPrincipalName",
}

// https://www.aldpro.ru/professional/ALD_Pro_Module_13/ALD_Pro_mac_mic.html#freeipa
var macUserAttributes []string = []string{
	"x-ald-aud-mask",
	"x-ald-aud-type",
	"x-ald-user-mac",
	"x-ald-user-cap",
	"x-ald-user-caps",
	"x-ald-user-mic-level",
	"x-ald-user-mac",
	"xaldusermacmax",
	"xaldusermacmin",
}

func (cl *Client) SearchUser(ctx context.Context, username string, baseDN string) (*UserInfo, error) {
	cl.logger.Debug(ctx, "Starting LDAP user search", map[string]interface{}{
		"username": username,
	})

	searchFilter := fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username))
	allUserAttributes := append(defaultUserAttributes, macUserAttributes...)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		searchFilter,
		// allUserAttributes,
		allUserAttributes, // Tempory DEBUG
		nil,
	)

	cl.logger.Debug(ctx, "Searching for user in LDAP", map[string]interface{}{
		"username": username,
		"filter":   searchFilter,
	})

	result, err := cl.ldapConnection.Search(searchRequest)
	if err != nil {
		cl.logger.Error(ctx, "LDAP search query failed", map[string]interface{}{
			"username": username,
			"filter":   searchFilter,
			"error":    err.Error(),
		})
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		cl.logger.Warn(ctx, "User not found in LDAP directory", map[string]interface{}{
			"username": username,
			"filter":   searchFilter,
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

	cl.logger.Debug(ctx, "=== ALL ATTRIBUTES RETURNED BY LDAP ===", nil)
	for _, attr := range entry.Attributes {
		cl.logger.Debug(ctx, fmt.Sprintf("Attribute: %s", attr.Name), map[string]interface{}{
			"values": attr.Values,
			"count":  len(attr.Values),
		})
	}
	cl.logger.Debug(ctx, "=== END OF ATTRIBUTES ===", nil)

	cl.logger.Info(ctx, "User found in LDAP", map[string]interface{}{
		"username": username,
		"dn":       entry.DN,
	})
	info := make(map[string]interface{})
	for _, attr := range allUserAttributes {
		info[attr] = entry.GetAttributeValue(attr)
	}
	cl.logger.Debug(ctx, "User info:", info)

	return &UserInfo{
		DN:   entry.DN,
		UID:  entry.GetAttributeValue("uid"),
		Name: entry.GetAttributeValue("name"),
	}, nil
}
