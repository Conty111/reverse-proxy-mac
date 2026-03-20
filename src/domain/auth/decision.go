// Package auth defines the core authentication and authorization domain types.
package auth

import (
	"context"
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
	DeniedStatus  int32
	DeniedMessage string
	Headers       map[string]string
}

type Authorizer interface {
	Authorize(ctx context.Context, req *AuthRequest) (*AuthResponse, error)
}
