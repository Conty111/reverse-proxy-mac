// Package auth defines the core authentication and authorization domain types.
package auth

import (
	"context"
	"encoding/json"
	"time"
)

// Decision represents the outcome of an authorization check.
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionDeny
)

// String returns the string representation of the decision.
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "ALLOW"
	case DecisionDeny:
		return "DENY"
	default:
		return "UNKNOWN"
	}
}

// DenyReason identifies the specific reason why access was denied.
// Each value corresponds to a distinct MAC policy check stage.
type DenyReason string

const (
	// DenyReasonNone indicates no denial (access allowed).
	DenyReasonNone DenyReason = ""

	// DenyReasonAuthentication indicates the user failed Kerberos authentication
	// (missing or invalid Negotiate token).
	DenyReasonAuthentication DenyReason = "AUTHENTICATION_REQUIRED"

	// DenyReasonUserContext indicates the user's MAC security context could not
	// be retrieved from LDAP (user not found, missing attributes, etc.).
	DenyReasonUserContext DenyReason = "USER_CONTEXT_UNAVAILABLE"

	// DenyReasonHostContext indicates the target host's MAC security context
	// could not be retrieved from LDAP or cache.
	DenyReasonHostContext DenyReason = "HOST_CONTEXT_UNAVAILABLE"

	// DenyReasonURIContext indicates the URI MAC rule security context could
	// not be retrieved from LDAP or cache.
	DenyReasonURIContext DenyReason = "URI_CONTEXT_UNAVAILABLE"

	// DenyReasonHostConfidentiality indicates the user's confidentiality level
	// range does not satisfy the host's confidentiality requirements.
	DenyReasonHostConfidentiality DenyReason = "HOST_CONFIDENTIALITY_VIOLATION"

	// DenyReasonHostCategories indicates the user's security categories do not
	// include all categories required by the host.
	DenyReasonHostCategories DenyReason = "HOST_CATEGORIES_VIOLATION"

	// DenyReasonHostIntegrity indicates the user's integrity categories do not
	// include all integrity categories required by the host.
	DenyReasonHostIntegrity DenyReason = "HOST_INTEGRITY_VIOLATION"

	// DenyReasonURIConfidentiality indicates the user's confidentiality level
	// range does not satisfy the URI rule's confidentiality requirements.
	DenyReasonURIConfidentiality DenyReason = "URI_CONFIDENTIALITY_VIOLATION"

	// DenyReasonURICategories indicates the user's security categories do not
	// include all categories required by the URI rule.
	DenyReasonURICategories DenyReason = "URI_CATEGORIES_VIOLATION"

	// DenyReasonURIIntegrity indicates the user's integrity categories do not
	// include all integrity categories required by the URI rule.
	DenyReasonURIIntegrity DenyReason = "URI_INTEGRITY_VIOLATION"

	// DenyReasonBadRequest indicates the request itself is malformed
	// (e.g. missing Host header).
	DenyReasonBadRequest DenyReason = "BAD_REQUEST"

	// DenyReasonTransportConfidentiality indicates the source host's
	// confidentiality range does not satisfy the destination host's requirements
	// at the transport (L3/L4) level.
	DenyReasonTransportConfidentiality DenyReason = "TRANSPORT_CONFIDENTIALITY_VIOLATION"

	// DenyReasonTransportCategories indicates the source host's categories do
	// not include all categories required by the destination host at the
	// transport (L3/L4) level.
	DenyReasonTransportCategories DenyReason = "TRANSPORT_CATEGORIES_VIOLATION"

	// DenyReasonTransportResolution indicates that IP-to-FQDN resolution failed
	// for a transport-level authorization request.
	DenyReasonTransportResolution DenyReason = "TRANSPORT_RESOLUTION_FAILED"

	// DenyReasonTransportHostContext indicates the host's MAC security context
	// could not be retrieved during transport-level authorization.
	DenyReasonTransportHostContext DenyReason = "TRANSPORT_HOST_CONTEXT_UNAVAILABLE"

	// DenyReasonInternal indicates an unexpected internal error.
	DenyReasonInternal DenyReason = "INTERNAL_ERROR"
)

// DenyResponse is the structured JSON body returned to the client when access
// is denied. It provides a machine-readable status code, a deny reason
// identifier, and a human-readable message.
type DenyResponse struct {
	// Status is the HTTP status code (e.g. 401, 403).
	Status int `json:"status"`
	// Reason is the machine-readable deny reason identifier.
	Reason DenyReason `json:"reason"`
	// Message is a human-readable description of why access was denied.
	Message string `json:"message"`
}

// ToJSON serializes the DenyResponse to a JSON string.
// On marshalling failure it returns a minimal fallback JSON.
func (dr *DenyResponse) ToJSON() string {
	data, err := json.Marshal(dr)
	if err != nil {
		return `{"status":500,"reason":"INTERNAL_ERROR","message":"failed to serialize deny response"}`
	}
	return string(data)
}

type AuthRequest struct {
	RequestID   string
	Timestamp   time.Time
	SourceIP    string
	SourcePort  int32
	DestIP      string
	DestPort    int32
	Protocol    string
	HTTPMethod  string
	HTTPPath    string
	HTTPHeaders map[string]string
}

type AuthResponse struct {
	Decision      Decision
	Reason        string
	DenyReason    DenyReason
	DeniedBody    string
	DeniedStatus  int32
	DeniedMessage string
	Headers       map[string]string
}

// NewDeniedAuthResponse creates an AuthResponse for a denied request with a
// structured JSON body. It builds a DenyResponse, serializes it, and populates
// both the legacy DeniedMessage field and the new DeniedBody field.
func NewDeniedAuthResponse(httpStatus int32, denyReason DenyReason, message string) *AuthResponse {
	dr := &DenyResponse{
		Status:  int(httpStatus),
		Reason:  denyReason,
		Message: message,
	}
	return &AuthResponse{
		Decision:      DecisionDeny,
		Reason:        message,
		DenyReason:    denyReason,
		DeniedStatus:  httpStatus,
		DeniedMessage: message,
		DeniedBody:    dr.ToJSON(),
	}
}

// NewDeniedAuthResponseWithHeaders is like NewDeniedAuthResponse but also
// attaches response headers (e.g. WWW-Authenticate for 401).
func NewDeniedAuthResponseWithHeaders(httpStatus int32, denyReason DenyReason, message string, headers map[string]string) *AuthResponse {
	resp := NewDeniedAuthResponse(httpStatus, denyReason, message)
	resp.Headers = headers
	return resp
}

type Authorizer interface {
	Authorize(ctx context.Context, req *AuthRequest) (*AuthResponse, error)
}
