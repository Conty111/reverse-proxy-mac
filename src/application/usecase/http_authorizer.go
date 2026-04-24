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

	"github.com/jcmturner/gokrb5/v8/credentials"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
	"reverse-proxy-mac/src/infrastructure/cache"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

type HTTPAuthorizer struct {
	logger     logger.Logger
	ldapClient *ldap.Client
	cache      *cache.Store
}

func NewHTTPAuthorizer(log logger.Logger, ldapClient *ldap.Client, store *cache.Store) (*HTTPAuthorizer, error) {
	return &HTTPAuthorizer{
		logger:     log,
		ldapClient: ldapClient,
		cache:      store,
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

	// Get user security context (cache-first)
	userSecCtx, err := GetUserHTTPSecurityContext(ctx, a.ldapClient, a.cache, ticket, req.HTTPMethod)
	if err != nil {
		a.logger.Error(ctx, "Failed to GetUserHTTPSecurityContext", map[string]interface{}{
			"error": err.Error(),
		})
		return auth.NewDeniedAuthResponse(
			403,
			auth.DenyReasonUserContext,
			fmt.Sprintf("Failed to retrieve user security context: %s", err.Error()),
		), nil
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
		return auth.NewDeniedAuthResponse(
			400,
			auth.DenyReasonBadRequest,
			fmt.Sprintf("Failed to extract host FQDN from the request: %s", err.Error()),
		), nil
	}

	// Get host security context (cache-first)
	hostSecCtx, err := GetHostSecurityContext(ctx, a.ldapClient, a.cache, hostFQDN)
	if err != nil {
		a.logger.Error(ctx, "Failed to GetHostSecurityContext", map[string]interface{}{
			"fqdn":  hostFQDN,
			"error": err.Error(),
		})
		return auth.NewDeniedAuthResponse(
			403,
			auth.DenyReasonHostContext,
			fmt.Sprintf("Failed to retrieve host security context: %s", err.Error()),
		), nil
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
	result := checkAccessHTTP(userSecCtx, hostSecCtx,
		auth.DenyReasonHostConfidentiality,
		auth.DenyReasonHostCategories,
		auth.DenyReasonHostIntegrity,
	)
	if !result.Allowed {
		a.logger.Warn(ctx, "Host-level MAC authorization denied", map[string]interface{}{
			"principal":   principal,
			"fqdn":        hostFQDN,
			"reason":      result.Message,
			"deny_reason": string(result.DenyReason),
		})
		return auth.NewDeniedAuthResponse(403, result.DenyReason, result.Message), nil
	}

	a.logger.Info(ctx, "Host-level MAC authorization granted", map[string]interface{}{
		"principal": principal,
		"fqdn":      hostFQDN,
		"reason":    result.Message,
	})

	// Perform URI-level MAC authorization check against all matching rules.
	// If no URI rule is found for the requested path, access is allowed (URI rules are optional).
	uriSecCtxs, err := GetMatchingURISecurityContexts(ctx, a.ldapClient, a.cache, hostFQDN, req.HTTPPath)
	if err != nil {
		a.logger.Error(ctx, "Failed to GetMatchingURISecurityContexts", map[string]interface{}{
			"fqdn":  hostFQDN,
			"path":  req.HTTPPath,
			"error": err.Error(),
		})
		return auth.NewDeniedAuthResponse(
			403,
			auth.DenyReasonURIContext,
			fmt.Sprintf("Failed to retrieve URI security context: %s", err.Error()),
		), nil
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

			uriResult := checkAccessHTTP(userSecCtx, uriSecCtx,
				auth.DenyReasonURIConfidentiality,
				auth.DenyReasonURICategories,
				auth.DenyReasonURIIntegrity,
			)
			if !uriResult.Allowed {
				a.logger.Warn(ctx, "URI-level MAC authorization denied", map[string]interface{}{
					"principal":   principal,
					"fqdn":        hostFQDN,
					"path":        req.HTTPPath,
					"rule_path":   uriSecCtx.Path,
					"reason":      uriResult.Message,
					"deny_reason": string(uriResult.DenyReason),
				})
				return auth.NewDeniedAuthResponse(403, uriResult.DenyReason, uriResult.Message), nil
			}
		}

		a.logger.Info(ctx, "URI-level MAC authorization granted", map[string]interface{}{
			"principal":   principal,
			"fqdn":        hostFQDN,
			"path":        req.HTTPPath,
			"rules_count": len(uriSecCtxs),
			"reason":      result.Message,
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
	return auth.NewDeniedAuthResponseWithHeaders(
		401,
		auth.DenyReasonAuthentication,
		"Kerberos authentication required",
		map[string]string{
			"WWW-Authenticate": "Negotiate",
		},
	)
}

func GetUserHTTPSecurityContext(ctx context.Context, cl *ldap.Client, store *cache.Store, userTicket *credentials.Credentials, httpMethod string) (*auth.UserHTTPSecurityContext, error) {
	if err := validateHTTPMethod(httpMethod); err != nil {
		return nil, err
	}

	uid := userTicket.CName().PrincipalNameString()

	// Fast path: cache hit.
	if store != nil {
		if cached := store.LookupUser(uid); cached != nil {
			return &auth.UserHTTPSecurityContext{
				RequestMethod:       httpMethod,
				ConfidentialityMin:  cached.ConfidentialityMin,
				CategoriesMin:       cached.CategoriesMin,
				ConfidentialityMax:  cached.ConfidentialityMax,
				CategoriesMax:       cached.CategoriesMax,
				IntegrityCategories: cached.IntegrityCategories,
			}, nil
		}
	}

	// Slow path: try Kerberos ticket attributes first, then LDAP.
	var macValue, integrityValue string
	attrs := userTicket.Attributes()
	macValue, macValueOk := attrs[auth.UserMacAttribute].(string)
	integrityValue, integrityValueOk := attrs[auth.UserIntegrityLevelAttribute].(string)
	if !macValueOk || !integrityValueOk {
		// Search for user in LDAP
		userEntries, err := cl.Search(ctx, fmt.Sprintf("(uid=%s)", uid), auth.AllMacUserAttributes)
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

		macValue = userEntry.GetAttributeValue(auth.UserMacAttribute)
		if macValue == "" {
			return nil, fmt.Errorf("user MAC attribute '%s' is empty or not found", auth.UserMacAttribute)
		}

		integrityValue = userEntry.GetAttributeValue(auth.UserIntegrityLevelAttribute)
		if integrityValue == "" {
			cl.Logger.Warn(ctx, fmt.Sprintf("user integrity categories attribute '%s' is empty or not found, setting default", auth.UserIntegrityLevelAttribute), map[string]interface{}{})
			integrityValue = defaultIntegrityValue
		}
	}

	label, err := parseMacLabel(macValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC label for user: %w", err)
	}

	integrityCategories, err := strconv.ParseUint(integrityValue, 0, 32)
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

// GetMatchingURISecurityContexts returns all URI security contexts that match
// the given host FQDN and request path.
//
// When a cache.Store is provided it uses the fast trie+bitset algorithm
// (see store.MatchingURIRules). On a cache miss (host not in cache) or when
// store is nil it falls back to a full LDAP scan.
func GetMatchingURISecurityContexts(ctx context.Context, cl *ldap.Client, store *cache.Store, hostFQDN, requestPath string) ([]*auth.URISecurityContext, error) {
	// Fast path: cache lookup.
	if store != nil {
		ctxs, found := store.MatchingURIRules(hostFQDN, requestPath)
		if found {
			return ctxs, nil
		}
		// Host not in cache — fall through to LDAP.
	}

	// Slow path: full LDAP scan (same logic as before, kept as fallback).
	entries, err := cl.Search(ctx, "(objectClass=aldURIMACRule)", auth.AllURIMACAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search URI MAC rules in LDAP: %w", err)
	}

	var matched []*auth.URISecurityContext

	for _, entry := range entries {
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

		uriPath := entry.GetAttributeValue(auth.URIPathAttribute)
		if uriPath == "" {
			continue
		}

		macValue := entry.GetAttributeValue(auth.URIMacAttribute)
		if macValue == "" {
			continue
		}

		matchType := auth.URIMatchType(entry.GetAttributeValue(auth.URIMatchTypeAttribute))
		if matchType == "" {
			matchType = auth.URIMatchExact
		}

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

		label, err := parseMacLabel(macValue)
		if err != nil {
			cl.Logger.Warn(ctx, "failed to parse URI MAC label, skipping rule", map[string]interface{}{
				"cn":    entry.GetAttributeValue("cn"),
				"error": err.Error(),
			})
			continue
		}

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
// The caller provides the deny reasons to use for confidentiality, categories,
// and integrity violations so that host-level and URI-level checks produce
// distinct DenyReason values.
func checkAccessHTTP(userCtx *auth.UserHTTPSecurityContext, resourceCtx auth.SecurityContext, confDenyReason, catsDenyReason, integrityDenyReason auth.DenyReason) MACCheckResult {
	_, isWriteOperation := writeHTTPMethods[userCtx.RequestMethod]
	result := checkMACAccess(userCtx, resourceCtx, isWriteOperation, confDenyReason, catsDenyReason)
	if result.Allowed && isWriteOperation {
		result = checkIntegrity(userCtx, resourceCtx, integrityDenyReason)
	}
	return result
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
