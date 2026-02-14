package grpc

import (
	"context"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
)

// AuthServiceV3 implements Envoy External Authorization API v3 for HTTP (L7)
type AuthServiceV3 struct {
	envoy_auth.UnimplementedAuthorizationServer
	authorizer auth.Authorizer
	logger     logger.Logger
}

// NewAuthServiceV3 creates a new L7 authorization service
func NewAuthServiceV3(authorizer auth.Authorizer, log logger.Logger) *AuthServiceV3 {
	return &AuthServiceV3{
		authorizer: authorizer,
		logger:     log,
	}
}

// Check performs authorization check for HTTP requests (L7)
func (s *AuthServiceV3) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	s.logger.Debug(ctx, "Received L7 (HTTP) authorization check", map[string]interface{}{
		"request_id": req.GetAttributes().GetRequest().GetHttp().GetId(),
	})

	// Convert Envoy request to domain request
	authReq := s.convertToAuthRequest(req)

	// Perform authorization
	authResp, err := s.authorizer.Authorize(ctx, authReq)
	if err != nil {
		s.logger.Error(ctx, "Authorization failed", map[string]interface{}{
			"error": err.Error(),
		})
		return s.createDeniedResponse(codes.Internal, "Internal authorization error"), nil
	}

	// Convert domain response to Envoy response
	return s.convertToEnvoyResponse(authResp), nil
}

func (s *AuthServiceV3) convertToAuthRequest(req *envoy_auth.CheckRequest) *auth.AuthRequest {
	attrs := req.GetAttributes()
	httpReq := attrs.GetRequest().GetHttp()
	source := attrs.GetSource()
	dest := attrs.GetDestination()

	authReq := &auth.AuthRequest{
		RequestID: httpReq.GetId(),
		Protocol:  httpReq.GetProtocol(),
	}

	// Source information
	if source != nil {
		authReq.SourceIP = source.GetAddress().GetSocketAddress().GetAddress()
		authReq.SourcePort = int32(source.GetAddress().GetSocketAddress().GetPortValue())
	}

	// Destination information
	if dest != nil {
		authReq.DestIP = dest.GetAddress().GetSocketAddress().GetAddress()
		authReq.DestPort = int32(dest.GetAddress().GetSocketAddress().GetPortValue())
	}

	// HTTP-specific information
	authReq.HTTPMethod = httpReq.GetMethod()
	authReq.HTTPPath = httpReq.GetPath()
	authReq.HTTPHeaders = make(map[string]string)
	for k, v := range httpReq.GetHeaders() {
		authReq.HTTPHeaders[k] = v
	}

	return authReq
}

func (s *AuthServiceV3) convertToEnvoyResponse(authResp *auth.AuthResponse) *envoy_auth.CheckResponse {
	if authResp.Decision == auth.DecisionAllow {
		return &envoy_auth.CheckResponse{
			Status: &status.Status{
				Code: int32(codes.OK),
			},
			HttpResponse: &envoy_auth.CheckResponse_OkResponse{
				OkResponse: &envoy_auth.OkHttpResponse{},
			},
		}
	}

	return s.createDeniedResponse(codes.PermissionDenied, authResp.DeniedMessage)
}

func (s *AuthServiceV3) createDeniedResponse(code codes.Code, message string) *envoy_auth.CheckResponse {
	return &envoy_auth.CheckResponse{
		Status: &status.Status{
			Code:    int32(code),
			Message: message,
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Forbidden,
				},
				Body: message,
			},
		},
	}
}

