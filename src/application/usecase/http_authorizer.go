package usecase

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
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
	// Validate authorization header
	authHeader, exists := req.HTTPHeaders["authorization"]
	if !exists || !strings.HasPrefix(authHeader, "Negotiate ") {
		return a.createUnauthorizedResponse(), nil
	}

	// Decode Kerberos token
	tokenStr := strings.TrimPrefix(authHeader, "Negotiate ")
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		a.logger.Error(ctx, "failed to decode Kerberos token", map[string]interface{}{"error": err.Error()})
		return a.createUnauthorizedResponse(), nil
	}

	// Verify Kerberos ticket
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
		"X-Authenticated-User": principal,
		"X-Auth-Realm":         realm,
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

	// Extract host FQDN from request
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

	// Get host security context
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

	a.logger.Info(ctx, "Host-level MAC authorization granted", map[string]interface{}{
		"principal": principal,
		"fqdn":      hostFQDN,
		"reason":    reason,
	})

	// Perform URI-level MAC authorization check against all matching rules.
	// If no URI rule is found for the requested path, access is allowed (URI rules are optional).
	uriSecCtxs, err := GetMatchingURISecurityContexts(ctx, a.ldapClient, hostFQDN, req.HTTPPath)
	if err != nil {
		a.logger.Error(ctx, "Failed to GetMatchingURISecurityContexts", map[string]interface{}{
			"fqdn":  hostFQDN,
			"path":  req.HTTPPath,
			"error": err.Error(),
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        fmt.Sprintf("Failed to retrieve URI security context: %s", err.Error()),
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - MAC context unavailable",
		}, nil
	}

	// Check URI-level MAC authorization if any rules matched
	if len(uriSecCtxs) > 0 {
		a.logger.Debug(ctx, "URI MAC rules matched for path", map[string]interface{}{
			"fqdn":        hostFQDN,
			"path":        req.HTTPPath,
			"rules_count": len(uriSecCtxs),
		})

		for _, uriSecCtx := range uriSecCtxs {
			a.logger.Debug(ctx, "Checking URI MAC rule", map[string]interface{}{
				"fqdn":           hostFQDN,
				"req_path":       req.HTTPPath,
				"rule_path":      uriSecCtx.Path,
				"conf_min":       uriSecCtx.ConfidentialityMin,
				"cats_min":       fmt.Sprintf("0x%x", uriSecCtx.CategoriesMin),
				"conf_max":       uriSecCtx.ConfidentialityMax,
				"cats_max":       fmt.Sprintf("0x%x", uriSecCtx.CategoriesMax),
				"integrity_cats": fmt.Sprintf("0x%x", uriSecCtx.IntegrityCategories),
			})

			allowed, reason := checkAccessHTTP(userSecCtx, uriSecCtx)
			if !allowed {
				a.logger.Warn(ctx, "URI-level MAC authorization denied", map[string]interface{}{
					"principal": principal,
					"fqdn":      hostFQDN,
					"path":      req.HTTPPath,
					"rule_path": uriSecCtx.Path,
					"reason":    reason,
				})
				return &auth.AuthResponse{
					Decision:      auth.DecisionDeny,
					Reason:        reason,
					DeniedStatus:  403,
					DeniedMessage: "Forbidden - MAC policy violation",
				}, nil
			}
		}

		a.logger.Info(ctx, "URI-level MAC authorization granted", map[string]interface{}{
			"principal":   principal,
			"fqdn":        hostFQDN,
			"path":        req.HTTPPath,
			"rules_count": len(uriSecCtxs),
			"reason":      reason,
		})
	} else {
		a.logger.Debug(ctx, "No URI MAC rules found for path, skipping URI-level check", map[string]interface{}{
			"fqdn": hostFQDN,
			"path": req.HTTPPath,
		})
	}

	return &auth.AuthResponse{
		Decision: auth.DecisionAllow,
		Reason:   fmt.Sprintf("HTTP authentication and MAC authorization successful for %s", principal),
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

func GetUserHTTPSecurityContext(ctx context.Context, cl *ldap.Client, username, httpMethod string) (*auth.UserHTTPSecurityContext, error) {
	if err := validateHTTPMethod(httpMethod); err != nil {
		return nil, err
	}

	// Search for user in LDAP
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

	// Log user attributes for debugging
	attrs := make(map[string]interface{}, len(userEntry.Attributes))
	for _, attr := range userEntry.Attributes {
		attrs[attr.Name] = attr.Values
	}
	cl.Logger.Debug(ctx, "user found in LDAP", attrs)

	// Parse MAC label
	macValue := userEntry.GetAttributeValue(auth.UserMacAttribute)
	if macValue == "" {
		return nil, fmt.Errorf("user MAC attribute '%s' is empty or not found", auth.UserMacAttribute)
	}

	label, err := parseMacLabel(macValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC label for user: %w", err)
	}

	// Parse integrity categories
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


// GetMatchingURISecurityContexts searches LDAP for all aldURIMACRule entries bound to
// the given host service principal whose path matches requestPath (exact, prefix, or
// regex). All matching rules are returned as URISecurityContext.
//
// NOTE: The x-ald-uri-service-ref attribute stores full Kerberos principal DNs
// (e.g. "krbprincipalname=HTTP/host.domain@REALM,cn=services,..."). OpenLDAP may
// define this attribute with only an EQUALITY matching rule, which means substring
// filters (*hostname*) silently return no results. To work around this, we fetch all
// aldURIMACRule entries and perform the service-ref filtering in Go.
func GetMatchingURISecurityContexts(ctx context.Context, cl *ldap.Client, hostFQDN, requestPath string) ([]*auth.URISecurityContext, error) {
	// Search for all URI MAC rules in LDAP
	entries, err := cl.Search(ctx, "(objectClass=aldURIMACRule)", auth.AllURIMACAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search URI MAC rules in LDAP: %w", err)
	}

	var matched []*auth.URISecurityContext

	for _, entry := range entries {
		// Filter by service ref: the attribute value is a full DN that contains the
		// host FQDN as part of the Kerberos principal name. We check all values of
		// the multi-valued attribute for a case-insensitive substring match.
		serviceRefs := entry.GetAttributeValues(auth.URIServiceRefAttribute)
		refMatched := false
		for _, ref := range serviceRefs {
			if strings.Contains(strings.ToLower(ref), strings.ToLower(hostFQDN)) {
				refMatched = true
				break
			}
		}
		if !refMatched {
			continue
		}

		// Get URI path
		uriPath := entry.GetAttributeValue(auth.URIPathAttribute)
		if uriPath == "" {
			continue
		}

		// Get MAC value
		macValue := entry.GetAttributeValue(auth.URIMacAttribute)
		if macValue == "" {
			continue
		}

		// Determine match type
		matchType := auth.URIMatchType(entry.GetAttributeValue(auth.URIMatchTypeAttribute))
		if matchType == "" {
			matchType = auth.URIMatchExact
		}

		// Check if path matches based on match type
		switch matchType {
		case auth.URIMatchExact:
			if requestPath != uriPath {
				continue
			}
		case auth.URIMatchPrefix:
			if !strings.HasPrefix(requestPath, uriPath) {
				continue
			}
		case auth.URIMatchRegex:
			ok, err := regexp.MatchString(uriPath, requestPath)
			if err != nil {
				cl.Logger.Warn(ctx, "invalid URI regex pattern, skipping rule", map[string]interface{}{
					"cn":      entry.GetAttributeValue("cn"),
					"pattern": uriPath,
					"error":   err.Error(),
				})
				continue
			}
			if !ok {
				continue
			}
		}

		// Parse MAC label
		label, err := parseMacLabel(macValue)
		if err != nil {
			cl.Logger.Warn(ctx, "failed to parse URI MAC label, skipping rule", map[string]interface{}{
				"cn":    entry.GetAttributeValue("cn"),
				"error": err.Error(),
			})
			continue
		}

		// Parse integrity categories
		var integrityCategories uint32
		micValue := entry.GetAttributeValue(auth.URIIntegrityCategoriesAttribute)
		if micValue != "" {
			parsed, err := strconv.ParseUint(micValue, 0, 32)
			if err != nil {
				cl.Logger.Warn(ctx, "failed to parse URI integrity categories, skipping rule", map[string]interface{}{
					"cn":    entry.GetAttributeValue("cn"),
					"error": err.Error(),
				})
				continue
			}
			integrityCategories = uint32(parsed)
		}

		// Create URI security context
		uriCtx := &auth.URISecurityContext{
			Path:                uriPath,
			ConfidentialityMin:  label.ConfMin,
			CategoriesMin:       label.CatsMin,
			ConfidentialityMax:  label.ConfMax,
			CategoriesMax:       label.CatsMax,
			IntegrityCategories: integrityCategories,
		}

		matched = append(matched, uriCtx)
	}
	return matched, nil
}

var writeHTTPMethods = map[string]struct{}{
	"POST":   {},
	"PUT":    {},
	"DELETE": {},
	"PATCH":  {},
}

// checkAccessHTTP performs Mandatory Access Control (MAC) authorization check.
// Based on Bell-LaPadula model: "no read up, no write down".
func checkAccessHTTP(userCtx *auth.UserHTTPSecurityContext, resourceCtx auth.SecurityContext) (bool, string) {
	_, isWriteOperation := writeHTTPMethods[userCtx.RequestMethod]
	return checkMACAccess(userCtx, resourceCtx, isWriteOperation)
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
