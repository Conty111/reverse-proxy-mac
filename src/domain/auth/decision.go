package auth

import (
	"context"
	"time"
)

type Decision int

const (
	DecisionAllow Decision = iota
	DecisionDeny
)

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
