package grpc

import (
	"context"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
)

type AuthServiceV3 struct {
	envoy_auth.UnimplementedAuthorizationServer
	authorizer auth.Authorizer
	logger     logger.Logger
}

func NewAuthServiceV3(authorizer auth.Authorizer, log logger.Logger) *AuthServiceV3 {
	return &AuthServiceV3{
		authorizer: authorizer,
		logger:     log,
	}
}

func (s *AuthServiceV3) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	authReq := s.convertToAuthRequest(req)
	authResp, err := s.authorizer.Authorize(ctx, authReq)
	if err != nil {
		s.logger.Error(ctx, "Authorization failed", map[string]interface{}{"error": err.Error()})
		return s.createDeniedResponse(codes.Internal, "Internal authorization error"), nil
	}

	return s.convertToEnvoyResponse(authResp), nil
}

func (s *AuthServiceV3) convertToAuthRequest(req *envoy_auth.CheckRequest) *auth.AuthRequest {
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

	if source != nil {
		authReq.SourceIP = source.GetAddress().GetSocketAddress().GetAddress()
		authReq.SourcePort = int32(source.GetAddress().GetSocketAddress().GetPortValue())
	}

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

	if authResp.DeniedStatus == 302 {
		return s.createRedirectResponse(authResp.Headers["Location"], authResp.DeniedMessage)
	}

	if authResp.DeniedStatus == 401 {
		return s.createUnauthorizedResponse(authResp.DeniedMessage, authResp.Headers)
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
