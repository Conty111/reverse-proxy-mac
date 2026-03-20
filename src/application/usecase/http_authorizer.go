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

type HTTPAuthorizer struct {
	logger     logger.Logger
	ldapClient *ldap.Client
}

func NewHTTPAuthorizer(log logger.Logger, ldapClient *ldap.Client) (*HTTPAuthorizer, error) {
	return &HTTPAuthorizer{
		logger:     log,
		ldapClient: ldapClient,
	}, nil
}

func (a *HTTPAuthorizer) Authorize(ctx context.Context, req *auth.AuthRequest) (*auth.AuthResponse, error) {
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
		a.logger.Error(ctx, "failed to decode Kerberos token", map[string]interface{}{"error": err.Error()})
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

	// Get user security context
	userSecCtx, err := GetUserHTTPSecurityContext(ctx, a.ldapClient, principal, req.HTTPMethod)
	if err != nil {
		a.logger.Error(ctx, "Failed to GetUserHTTPSecurityContext", map[string]interface{}{
			"error": err.Error(),
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        fmt.Sprintf("Failed to retrieve user security context: %s", err.Error()),
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - MAC context unavailable",
		}, nil
	}

	a.logger.Debug(ctx, "User security context retrieved", map[string]interface{}{
		"principal":    principal,
		"level":        userSecCtx.Confidentiality,
		"categories":   fmt.Sprintf("0x%x", userSecCtx.Categories),
		"capabilities": userSecCtx.Capabilities,
		"integrity":    fmt.Sprintf("0x%x", userSecCtx.Integrity),
	})

	hostFQDN, err := extractHostFromRequest(req)
	if err != nil {
		a.logger.Warn(ctx, "Failed to extract host FQDN from the request", map[string]interface{}{
			"error": err.Error(),
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        fmt.Sprintf("Failed to extract host FQDN from the request: %s", err.Error()),
			DeniedStatus:  400,
			DeniedMessage: "Bad Request - Invalid Host header",
		}, nil
	}

	hostSecCtx, err := GetHostSecurityContext(ctx, a.ldapClient, hostFQDN)
	if err != nil {
		a.logger.Error(ctx, "Failed to GetHostSecurityContext", map[string]interface{}{
			"fqdn":  hostFQDN,
			"error": err.Error(),
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        fmt.Sprintf("Failed to retrieve host security context: %s", err.Error()),
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - MAC context unavailable",
		}, nil
	}

	a.logger.Debug(ctx, "Host security context retrieved", map[string]interface{}{
		"fqdn":         hostFQDN,
		"level":        hostSecCtx.Confidentiality,
		"categories":   fmt.Sprintf("0x%x", hostSecCtx.Categories),
		"capabilities": hostSecCtx.Capabilities,
		"integrity":    fmt.Sprintf("0x%x", hostSecCtx.Integrity),
	})

	// Perform MAC authorization check
	allowed, reason := checkAccessHTTP(userSecCtx, hostSecCtx)
	if !allowed {
		a.logger.Warn(ctx, "MAC authorization denied", map[string]interface{}{
			"principal": principal,
			"fqdn":      hostFQDN,
			"reason":    reason,
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        reason,
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - MAC policy violation",
		}, nil
	}

	a.logger.Info(ctx, "MAC authorization granted", map[string]interface{}{
		"principal": principal,
		"fqdn":      hostFQDN,
		"reason":    reason,
	})

	return &auth.AuthResponse{
		Decision: auth.DecisionAllow,
		Reason:   fmt.Sprintf("HTTP authentication and MAC authorization successful for %s", ticket.CName().PrincipalNameString()),
		Headers:  responseHeaders,
	}, nil
}

func (a *HTTPAuthorizer) createUnauthorizedResponse() *auth.AuthResponse {
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

var writeHTTPMethods = map[string]struct{}{
	"POST":   {},
	"PUT":    {},
	"DELETE": {},
	"PATCH":  {},
}

// checkAccessHTTP performs Mandatory Access Control (MAC) authorization check.
// Based on Bell-LaPadula model: "no read up, no write down".
func checkAccessHTTP(userCtx *auth.UserHTTPSecurityContext, hostCtx *auth.HostSecurityContext) (bool, string) {
	_, isWriteOperation := writeHTTPMethods[userCtx.RequestMethod]
	return checkMACAccess(userCtx, hostCtx, isWriteOperation)
}

func GetUserHTTPSecurityContext(ctx context.Context, cl *ldap.Client, username, httpMethod string) (*auth.UserHTTPSecurityContext, error) {
	if err := validateHTTPMethod(httpMethod); err != nil {
		return nil, err
	}

	userEntry, err := cl.Search(ctx, fmt.Sprintf("(uid=%s)", username), auth.AllMacUserAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search user in LDAP: %w", err)
	}
	if userEntry == nil {
		return nil, errUserNotFound
	}

	attrs := make(map[string]interface{}, len(userEntry.Attributes))
	for _, attr := range userEntry.Attributes {
		attrs[attr.Name] = attr.Values
	}
	cl.Logger.Debug(ctx, "user found in LDAP", attrs)

	macValue := userEntry.GetAttributeValue(auth.UserMacAttribute)
	if macValue == "" {
		return nil, fmt.Errorf("user MAC attribute '%s' is empty or not found", auth.UserMacAttribute)
	}

	label, err := parseMacLabel(macValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC label for user: %w", err)
	}

	return &auth.UserHTTPSecurityContext{
		RequestMethod:   httpMethod,
		Categories:      label.Categories,
		Confidentiality: label.Confidentiality,
		Capabilities:    label.Capabilities,
		Integrity:       label.Integrity,
	}, nil
}
