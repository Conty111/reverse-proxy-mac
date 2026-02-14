package usecase

import (
	"context"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
)

// AllowAllAuthorizer implements an authorizer that allows all requests
type AllowAllAuthorizer struct {
	logger logger.Logger
}

// NewAllowAllAuthorizer creates a new AllowAllAuthorizer
func NewAllowAllAuthorizer(log logger.Logger) *AllowAllAuthorizer {
	return &AllowAllAuthorizer{
		logger: log,
	}
}

// Authorize logs the request and allows it
func (a *AllowAllAuthorizer) Authorize(ctx context.Context, req *auth.AuthRequest) (*auth.AuthResponse, error) {
	fields := map[string]interface{}{
		"request_id":  req.RequestID,
		"source_ip":   req.SourceIP,
		"source_port": req.SourcePort,
		"dest_ip":     req.DestIP,
		"dest_port":   req.DestPort,
		"protocol":    req.Protocol,
	}

	// Add HTTP-specific fields if present
	if req.HTTPMethod != "" {
		fields["http_method"] = req.HTTPMethod
		fields["http_path"] = req.HTTPPath
		fields["http_headers_count"] = len(req.HTTPHeaders)
	}

	a.logger.Info(ctx, "Authorization request received - ALLOWING", fields)

	return &auth.AuthResponse{
		Decision: auth.DecisionAllow,
		Reason:   "Allow all policy",
	}, nil
}

