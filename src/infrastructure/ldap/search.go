package ldap

import (
	"context"
	"fmt"
	"strings"
	"time"

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
		0, 0, false,
		filter, attributes, nil,
	)

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryDelay(attempt - 1)
			cl.Logger.Info(ctx, "Retrying LDAP search", map[string]interface{}{
				"attempt": attempt,
				"delay":   delay.String(),
			})
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		cl.connMu.RLock()
		conn := cl.ldapConnection
		cl.connMu.RUnlock()

		result, err := conn.Search(searchRequest)
		if err == nil {
			return result.Entries, nil
		}

		lastErr = err
		cl.Logger.Error(ctx, "LDAP search failed", map[string]interface{}{
			"error":   err.Error(),
			"attempt": attempt,
		})

		if !conn.IsClosing() {
			break
		}

		if reconnErr := cl.reconnect(ctx); reconnErr != nil {
			cl.Logger.Error(ctx, "LDAP reconnect failed", map[string]interface{}{
				"error": reconnErr.Error(),
			})
			lastErr = reconnErr
		}
	}

	return nil, fmt.Errorf("LDAP search failed: %w", lastErr)
}
