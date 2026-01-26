package main

import (
	"context"
	"fmt"
	"net"

	envoy_api_v3_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"reverse-proxy-mac/src/internal/application/authentication"
	"reverse-proxy-mac/src/internal/application/authorization"
	"reverse-proxy-mac/src/internal/domain/entities"
	"reverse-proxy-mac/src/internal/domain/ports"
)

// ExtAuthServer implements Envoy's external authorization service
type ExtAuthServer struct {
	envoy_service_auth_v3.UnimplementedAuthorizationServer
	authService  *authentication.Service
	authzService *authorization.Service
	logger       ports.Logger
	grpcServer   *grpc.Server
}

// NewExtAuthServer creates a new external auth server
func NewExtAuthServer(authService *authentication.Service, authzService *authorization.Service, logger ports.Logger) *ExtAuthServer {
	server := &ExtAuthServer{
		authService:  authService,
		authzService: authzService,
		logger:       logger,
	}

	grpcServer := grpc.NewServer()
	envoy_service_auth_v3.RegisterAuthorizationServer(grpcServer, server)
	server.grpcServer = grpcServer

	return server
}

// Check implements the authorization check
func (s *ExtAuthServer) Check(ctx context.Context, req *envoy_service_auth_v3.CheckRequest) (*envoy_service_auth_v3.CheckResponse, error) {
	// Extract request attributes
	attrs := req.GetAttributes()
	httpAttrs := attrs.GetRequest().GetHttp()

	// Get authorization header
	authHeader := httpAttrs.GetHeaders()["authorization"]
	if authHeader == "" {
		s.logger.Warn("No authorization header found")
		return s.denyResponse("Missing authorization header"), nil
	}

	// Authenticate user
	user, err := s.authService.Authenticate(ctx, authHeader)
	if err != nil {
		s.logger.Error("Authentication failed", "error", err)
		return s.denyResponse("Authentication failed"), nil
	}

	// Authorize user based on MAC policy
	authorized, err := s.authzService.AuthorizeUser(ctx, user)
	if err != nil || !authorized {
		s.logger.Warn("Authorization failed", "username", user.Username, "error", err)
		return s.denyResponse("Authorization failed"), nil
	}

	// Log L4 traffic if available
	if source := attrs.GetSource(); source != nil {
		if dest := attrs.GetDestination(); dest != nil {
			srcIP := source.GetAddress().GetSocketAddress().GetAddress()
			dstIP := dest.GetAddress().GetSocketAddress().GetAddress()
			srcPort := int(source.GetAddress().GetSocketAddress().GetPortValue())
			dstPort := int(dest.GetAddress().GetSocketAddress().GetPortValue())
			
			s.authzService.LogL4Traffic(ctx, srcIP, dstIP, srcPort, dstPort)
		}
	}

	// Return success with user headers
	return s.allowResponse(user), nil
}

// allowResponse creates an allow response with user headers
func (s *ExtAuthServer) allowResponse(user *entities.User) *envoy_service_auth_v3.CheckResponse {
	headers := []*envoy_api_v3_core.HeaderValueOption{
		{
			Header: &envoy_api_v3_core.HeaderValue{
				Key:   "x-authenticated-user",
				Value: user.FullName(),
			},
		},
		{
			Header: &envoy_api_v3_core.HeaderValue{
				Key:   "x-username",
				Value: user.Username,
			},
		},
		{
			Header: &envoy_api_v3_core.HeaderValue{
				Key:   "x-realm",
				Value: user.Realm,
			},
		},
		{
			Header: &envoy_api_v3_core.HeaderValue{
				Key:   "x-ald-mac-user",
				Value: fmt.Sprintf("%x", user.MACLabel),
			},
		},
	}

	return &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{
			Code: int32(codes.OK),
		},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
			OkResponse: &envoy_service_auth_v3.OkHttpResponse{
				Headers: headers,
			},
		},
	}
}

// denyResponse creates a deny response
func (s *ExtAuthServer) denyResponse(message string) *envoy_service_auth_v3.CheckResponse {
	return &envoy_service_auth_v3.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.PermissionDenied),
			Message: message,
		},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode_Unauthorized,
				},
				Body: message,
			},
		},
	}
}

// Serve starts the gRPC server
func (s *ExtAuthServer) Serve(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

// GracefulStop stops the server gracefully
func (s *ExtAuthServer) GracefulStop() {
	s.grpcServer.GracefulStop()
}
