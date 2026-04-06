package grpc

import (
	"context"
	"time"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
)

// AuthServiceV3 implements the Envoy ext_authz gRPC Authorization service.
// It dispatches incoming Check requests to either the HTTP authorizer or the
// transport (network-level) authorizer based on whether the request contains
// HTTP attributes. The network ext_authz filter sends requests without HTTP
// data, while the HTTP ext_authz filter includes full HTTP attributes.
type AuthServiceV3 struct {
	envoy_auth.UnimplementedAuthorizationServer
	httpAuthorizer      auth.Authorizer
	transportAuthorizer auth.Authorizer
	logger              logger.Logger
}

// NewAuthServiceV3 creates a new composite auth service that handles both
// HTTP-level and transport-level ext_authz Check requests on a single gRPC server.
// The httpAuthorizer handles requests from envoy.filters.http.ext_authz,
// the transportAuthorizer handles requests from envoy.filters.network.ext_authz.
func NewAuthServiceV3(httpAuthorizer auth.Authorizer, transportAuthorizer auth.Authorizer, log logger.Logger) *AuthServiceV3 {
	return &AuthServiceV3{
		httpAuthorizer:      httpAuthorizer,
		transportAuthorizer: transportAuthorizer,
		logger:              log,
	}
}

func (s *AuthServiceV3) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	// Dispatch based on whether the request contains HTTP attributes.
	// The network ext_authz filter sends only source/destination addresses
	// without HTTP request data, while the HTTP ext_authz filter includes
	// full HTTP attributes (method, path, headers, etc.).
	if s.isTransportRequest(req) {
		return s.handleTransportCheck(ctx, req)
	}
	return s.handleHTTPCheck(ctx, req)
}

// isTransportRequest returns true when the Check request originates from
// the network-level ext_authz filter (no HTTP attributes present).
func (s *AuthServiceV3) isTransportRequest(req *envoy_auth.CheckRequest) bool {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	// Network ext_authz filter does not populate HTTP request attributes.
	// If method is empty, this is a transport-level request.
	return httpReq == nil || httpReq.GetMethod() == ""
}

// handleTransportCheck processes transport-layer (L3/L4) authorization requests.
func (s *AuthServiceV3) handleTransportCheck(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	authReq := s.convertToTransportAuthRequest(req)

	s.logger.Debug(ctx, "Dispatching to transport authorizer", map[string]interface{}{
		"source_ip":   authReq.SourceIP,
		"source_port": authReq.SourcePort,
		"dest_ip":     authReq.DestIP,
		"dest_port":   authReq.DestPort,
	})

	authResp, err := s.transportAuthorizer.Authorize(ctx, authReq)
	if err != nil {
		s.logger.Error(ctx, "Transport authorization failed", map[string]interface{}{"error": err.Error()})
		return s.createDeniedResponse(codes.Internal, "Internal transport authorization error"), nil
	}

	return s.convertToEnvoyResponse(authResp), nil
}

// handleHTTPCheck processes HTTP-layer (L7) authorization requests.
func (s *AuthServiceV3) handleHTTPCheck(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	authReq := s.convertToHTTPAuthRequest(req)

	authResp, err := s.httpAuthorizer.Authorize(ctx, authReq)
	if err != nil {
		s.logger.Error(ctx, "HTTP authorization failed", map[string]interface{}{"error": err.Error()})
		return s.createDeniedResponse(codes.Internal, "Internal authorization error"), nil
	}

	return s.convertToEnvoyResponse(authResp), nil
}

// convertToTransportAuthRequest extracts source/destination address info
// from a network-level ext_authz Check request.
func (s *AuthServiceV3) convertToTransportAuthRequest(req *envoy_auth.CheckRequest) *auth.AuthRequest {
	attrs := req.GetAttributes()
	source := attrs.GetSource()
	dest := attrs.GetDestination()

	authReq := &auth.AuthRequest{
		Timestamp: time.Now(),
		Protocol:  "TCP",
	}

	if source != nil {
		authReq.SourceIP = source.GetAddress().GetSocketAddress().GetAddress()
		authReq.SourcePort = int32(source.GetAddress().GetSocketAddress().GetPortValue())
	}

	if dest != nil {
		authReq.DestIP = dest.GetAddress().GetSocketAddress().GetAddress()
		authReq.DestPort = int32(dest.GetAddress().GetSocketAddress().GetPortValue())
	}

	return authReq
}

// convertToHTTPAuthRequest extracts full HTTP attributes from an
// HTTP-level ext_authz Check request.
func (s *AuthServiceV3) convertToHTTPAuthRequest(req *envoy_auth.CheckRequest) *auth.AuthRequest {
	attrs := req.GetAttributes()
	httpReq := attrs.GetRequest().GetHttp()
	source := attrs.GetSource()
	dest := attrs.GetDestination()

	authReq := &auth.AuthRequest{
		RequestID:   httpReq.GetId(),
		Protocol:    httpReq.GetProtocol(),
		HTTPMethod:  httpReq.GetMethod(),
		HTTPPath:    httpReq.GetPath(),
		HTTPHeaders: make(map[string]string),
	}

	// Extract source information
	if source != nil {
		authReq.SourceIP = source.GetAddress().GetSocketAddress().GetAddress()
		authReq.SourcePort = int32(source.GetAddress().GetSocketAddress().GetPortValue())
	}

	// Extract destination information
	if dest != nil {
		authReq.DestIP = dest.GetAddress().GetSocketAddress().GetAddress()
		authReq.DestPort = int32(dest.GetAddress().GetSocketAddress().GetPortValue())
	}

	// Copy headers from Envoy request
	for k, v := range httpReq.GetHeaders() {
		authReq.HTTPHeaders[k] = v
	}

	// Envoy sends Host header as httpReq.Host field, not in headers map
	// Add it to headers for easier access
	if httpReq.GetHost() != "" {
		authReq.HTTPHeaders["host"] = httpReq.GetHost()
	}

	return authReq
}

func (s *AuthServiceV3) convertToEnvoyResponse(authResp *auth.AuthResponse) *envoy_auth.CheckResponse {
	// Handle allowed responses
	if authResp.Decision == auth.DecisionAllow {
		var headers []*envoy_core.HeaderValueOption
		for k, v := range authResp.Headers {
			headers = append(headers, &envoy_core.HeaderValueOption{
				Header: &envoy_core.HeaderValue{
					Key:   k,
					Value: v,
				},
			})
		}

		return &envoy_auth.CheckResponse{
			Status: &status.Status{
				Code: int32(codes.OK),
			},
			HttpResponse: &envoy_auth.CheckResponse_OkResponse{
				OkResponse: &envoy_auth.OkHttpResponse{
					Headers: headers,
				},
			},
		}
	}

	// Handle different types of denied responses
	switch authResp.DeniedStatus {
	case 302:
		return s.createRedirectResponse(authResp.Headers["Location"], authResp.DeniedMessage)
	case 401:
		return s.createUnauthorizedResponse(authResp.DeniedMessage, authResp.Headers)
	default:
		return s.createDeniedResponse(codes.PermissionDenied, authResp.DeniedMessage)
	}
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

func (s *AuthServiceV3) createUnauthorizedResponse(message string, headers map[string]string) *envoy_auth.CheckResponse {
	var headerOptions []*envoy_core.HeaderValueOption
	for k, v := range headers {
		headerOptions = append(headerOptions, &envoy_core.HeaderValueOption{
			Header: &envoy_core.HeaderValue{
				Key:   k,
				Value: v,
			},
		})
	}

	return &envoy_auth.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.Unauthenticated),
			Message: message,
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Unauthorized,
				},
				Headers: headerOptions,
				Body:    message,
			},
		},
	}
}

func (s *AuthServiceV3) createRedirectResponse(location string, message string) *envoy_auth.CheckResponse {
	headers := []*envoy_core.HeaderValueOption{
		{
			Header: &envoy_core.HeaderValue{
				Key:   "Location",
				Value: location,
			},
		},
	}

	return &envoy_auth.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.Unauthenticated),
			Message: message,
		},
		HttpResponse: &envoy_auth.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Found,
				},
				Headers: headers,
				Body:    message,
			},
		},
	}
}
