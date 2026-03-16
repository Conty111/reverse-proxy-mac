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
		"level":        userSecCtx.Level,
		"categories":   fmt.Sprintf("0x%x", userSecCtx.Categories),
		"capabilities": userSecCtx.Capabilities,
		"integrity":    fmt.Sprintf("0x%x", userSecCtx.Integrity),
	})

	hostFQDN, err := extractHostFromRequest(req)
	if err != nil {
		a.logger.Warn(ctx, "Failed to extract host FQDN from the request", map[string]interface{}{
			"error":       err.Error(),
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
		"level":        hostSecCtx.Level,
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

// checkAccessHTTP performs Mandatory Access Control (MAC) authorization check
// Based on Bell-LaPadula model: "no read up, no write down"
// Returns true if access is allowed, false otherwise
func checkAccessHTTP(userCtx *auth.UserHTTPSecurityContext, hostCtx *auth.HostSecurityContext) (bool, string) {
	// Check level-based access control
	// User's level must be >= host's level for read access
	// For write operations (POST, PUT, DELETE, PATCH), user's level must equal host's level
	isWriteOperation := userCtx.RequestMethod == "POST" ||
		userCtx.RequestMethod == "PUT" ||
		userCtx.RequestMethod == "DELETE" ||
		userCtx.RequestMethod == "PATCH"
	
	
	
	allowed, msg := checkMACAccess(userCtx, hostCtx, isWriteOperation)
	if !allowed {
		return allowed, msg
	}

	// TODO: get URL security context and check user access to URL

	return allowed, msg
}

func GetUserHTTPSecurityContext(ctx context.Context, cl *ldap.Client, username, httpMethod string) (*auth.UserHTTPSecurityContext, error) {

	if err := validateHTTPMethod(httpMethod); err != nil {
		return nil, fmt.Errorf("Invalid HTTP method: %w", err)
	}

	userEntry, err := cl.Search(ctx, fmt.Sprintf("(uid=%s)", username), auth.AllMacUserAttributes)
	if err != nil {
		return nil, fmt.Errorf("Failed to search user in LDAP: %w", err)
	}
	if userEntry == nil {
		return nil, fmt.Errorf("User not found")
	}

	attrs := make(map[string]interface{})
	for _, attr := range userEntry.Attributes {
		attrs[attr.Name] = attr.Values
	}
	cl.Logger.Debug(ctx, "User found in LDAP", attrs)

	var level uint8
	var categories uint64
	var capabilities uint64
	var integrityLevel uint32

	macValue := userEntry.GetAttributeValue(auth.UserMacAttribute)
	if macValue == "" {
		return nil, fmt.Errorf("User MAC attribute '%s' is empty or not found", auth.UserMacAttribute)
	}

	level, categories, capabilities, integrityLevel, err = parseMacLabel(macValue)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse MAC label for user: %w", err)
	}

	return &auth.UserHTTPSecurityContext{
		RequestMethod: httpMethod,
		Categories: categories,
		Level: level,
		Capabilities: capabilities,
		Integrity: integrityLevel,
	}, nil
}