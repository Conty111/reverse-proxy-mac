package auth

import (
	"context"
	"time"
)

// Decision represents the authorization decision
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionDeny
)

// AuthRequest represents a generic authorization request
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

// AuthResponse represents the authorization response
type AuthResponse struct {
	Decision      Decision
	Reason        string
	DeniedStatus  int32
	DeniedMessage string
	Headers       map[string]string
}

// Authorizer defines the interface for authorization logic
type Authorizer interface {
	Authorize(ctx context.Context, req *AuthRequest) (*AuthResponse, error)
}
