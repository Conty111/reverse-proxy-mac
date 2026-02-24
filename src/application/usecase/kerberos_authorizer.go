package usecase

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

type KerberosAuthorizer struct {
	logger     logger.Logger
	ldapClient ldap.LDAPClient
}

type TicketInfo struct {
	Principal string
	Realm     string
	AuthTime  string
	Valid     bool
}

func NewKerberosAuthorizer(log logger.Logger, ldapClient ldap.LDAPClient) (*KerberosAuthorizer, error) {
	return &KerberosAuthorizer{
		logger:     log,
		ldapClient: ldapClient,
	}, nil
}

func (a *KerberosAuthorizer) Authorize(ctx context.Context, req *auth.AuthRequest) (*auth.AuthResponse, error) {
	authHeader, exists := req.HTTPHeaders["authorization"]
	if !exists {
		return a.createUnauthorizedResponse(), nil
	}

	if !strings.HasPrefix(authHeader, "Negotiate ") {
		return a.createUnauthorizedResponse(), nil
	}

	tokenStr := strings.TrimPrefix(authHeader, "Negotiate ")
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		a.logger.Error(ctx, "Failed to decode Kerberos token", map[string]interface{}{"error": err.Error()})
		return a.createUnauthorizedResponse(), nil
	}

	ticket, err := a.ldapClient.VerifyKerberosTicket(ctx, tokenBytes)
	if err != nil {
		a.logger.Error(ctx, "Kerberos ticket verification failed", map[string]interface{}{
			"error":  err.Error(),
			"reason": "Invalid or expired Kerberos ticket",
		})
		return a.createUnauthorizedResponse(), nil
	}

	principal := ticket.CName().PrincipalNameString()
	realm := ticket.Realm()

	a.logger.Info(ctx, "Kerberos ticket verified successfully", map[string]interface{}{
		"principal": principal,
		"realm":     realm,
	})

	responseHeaders := map[string]string{
		"X-Authenticated-User": ticket.CName().PrincipalNameString(),
		"X-Auth-Realm":         ticket.Realm(),
	}

	baseDN := fmt.Sprintf("%s", realmToDN(realm))
	_, err = a.ldapClient.SearchUser(ctx, principal, baseDN)
	if err != nil {
		a.logger.Warn(ctx, "LDAP user lookup failed after successful Kerberos authentication", map[string]interface{}{
			"principal": principal,
			"realm":     realm,
			"error":     err.Error(),
			"impact":    "User authenticated but additional attributes unavailable",
		})
	} else {
		a.logger.Info(ctx, "LDAP user lookup successful", map[string]interface{}{
			"principal": principal,
		})
	}

	return &auth.AuthResponse{
		Decision: auth.DecisionAllow,
		Reason:   fmt.Sprintf("Kerberos authentication successful for %s", ticket.CName().PrincipalNameString()),
		Headers:  responseHeaders,
	}, nil
}

func (a *KerberosAuthorizer) createUnauthorizedResponse() *auth.AuthResponse {
	return &auth.AuthResponse{
		Decision:      auth.DecisionDeny,
		Reason:        "Kerberos authentication required",
		DeniedStatus:  401,
		DeniedMessage: "Unauthorized",
		Headers: map[string]string{
			"WWW-Authenticate": "Negotiate",
		},
	}
}

func realmToDN(realm string) string {
	parts := strings.Split(strings.ToLower(realm), ".")
	dnParts := make([]string, len(parts))
	for i, part := range parts {
		dnParts[i] = "dc=" + part
	}
	return strings.Join(dnParts, ",")
}
