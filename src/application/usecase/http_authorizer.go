package usecase

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
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
		"principal":      principal,
		"conf_min":       userSecCtx.ConfidentialityMin,
		"cats_min":       fmt.Sprintf("0x%x", userSecCtx.CategoriesMin),
		"conf_max":       userSecCtx.ConfidentialityMax,
		"cats_max":       fmt.Sprintf("0x%x", userSecCtx.CategoriesMax),
		"integrity_cats": fmt.Sprintf("0x%x", userSecCtx.IntegrityCategories),
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
		"fqdn":           hostFQDN,
		"conf_min":       hostSecCtx.ConfidentialityMin,
		"cats_min":       fmt.Sprintf("0x%x", hostSecCtx.CategoriesMin),
		"conf_max":       hostSecCtx.ConfidentialityMax,
		"cats_max":       fmt.Sprintf("0x%x", hostSecCtx.CategoriesMax),
		"integrity_cats": fmt.Sprintf("0x%x", hostSecCtx.IntegrityCategories),
	})

	// Perform host-level MAC authorization check
	allowed, reason := checkAccessHTTP(userSecCtx, hostSecCtx)
	if !allowed {
		a.logger.Warn(ctx, "Host-level MAC authorization denied", map[string]interface{}{
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

	userEntries, err := cl.Search(ctx, fmt.Sprintf("(uid=%s)", username), auth.AllMacUserAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search user in LDAP: %w", err)
	}
	if len(userEntries) == 0 {
		return nil, errUserNotFound
	}
	if len(userEntries) > 1 {
		cl.Logger.Warn(ctx, "multiple users found", map[string]interface{}{
			"count": len(userEntries),
		})
	}
	userEntry := userEntries[0]

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
	integrity := userEntry.GetAttributeValue(auth.UserIntegrityLevelAttribute)
	if integrity == "" {
		return nil, fmt.Errorf("user integrity categories attribute '%s' is empty or not found", auth.UserIntegrityLevelAttribute)
	}
	integrityCategories, err := strconv.ParseUint(integrity, 0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse integrity categories for user: %w", err)
	}

	return &auth.UserHTTPSecurityContext{
		RequestMethod:       httpMethod,
		ConfidentialityMin:  label.ConfMin,
		CategoriesMin:       label.CatsMin,
		ConfidentialityMax:  label.ConfMax,
		CategoriesMax:       label.CatsMax,
		IntegrityCategories: uint32(integrityCategories),
	}, nil
}

// extractHostFromRequest extracts the FQDN from the authorization request.
// The Host header may contain port number (e.g., "example.com:8080"), which is stripped.
func extractHostFromRequest(req *auth.AuthRequest) (string, error) {
	hostHeader, ok := req.HTTPHeaders["host"]
	if !ok || hostHeader == "" {
		return "", errors.New("host header not present or empty in request")
	}

	parsed, err := url.Parse("http://" + hostHeader)
	if err != nil {
		return "", fmt.Errorf("failed to parse host header: %w", err)
	}

	return parsed.Hostname(), nil
}

var validHTTPMethods = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"DELETE":  {},
	"PATCH":   {},
	"HEAD":    {},
	"OPTIONS": {},
	"TRACE":   {},
	"CONNECT": {},
}

func validateHTTPMethod(method string) error {
	if method == "" {
		return errEmptyHTTPMethod
	}

	if _, ok := validHTTPMethods[strings.ToUpper(method)]; !ok {
		return fmt.Errorf("invalid HTTP method: %s", method)
	}

	return nil
}
