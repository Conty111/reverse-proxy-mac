package server

import (
	"context"
	"fmt"
	"net"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_proc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"reverse-proxy-mac/src/domain/logger"
)

type GRPCServer struct {
	server     *grpc.Server
	listener   net.Listener
	logger     logger.Logger
	host       string
	port       int
	authSvc    envoy_auth.AuthorizationServer
	extProcSvc ext_proc.ExternalProcessorServer
}

func NewGRPCServer(
	host string,
	port int,
	authSvc envoy_auth.AuthorizationServer,
	extProcSvc ext_proc.ExternalProcessorServer,
	log logger.Logger,
) *GRPCServer {
	return &GRPCServer{
		host:       host,
		port:       port,
		authSvc:    authSvc,
		extProcSvc: extProcSvc,
		logger:     log,
	}
}

func (s *GRPCServer) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(1000),
	}
	s.server = grpc.NewServer(opts...)

	envoy_auth.RegisterAuthorizationServer(s.server, s.authSvc)
	ext_proc.RegisterExternalProcessorServer(s.server, s.extProcSvc)

	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s.server, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	reflection.Register(s.server)

	s.logger.Info(ctx, "gRPC server starting", map[string]interface{}{"address": addr})

	go func() {
		if err := s.server.Serve(listener); err != nil {
			s.logger.Error(ctx, "gRPC server error", map[string]interface{}{"error": err.Error()})
		}
	}()

	s.logger.Info(ctx, "gRPC server started successfully", map[string]interface{}{"address": addr})

	return nil
}

func (s *GRPCServer) Stop(ctx context.Context) error {
	s.logger.Info(ctx, "Stopping gRPC server", nil)

	if s.server != nil {
		s.server.GracefulStop()
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.logger.Info(ctx, "gRPC server stopped", nil)
	return nil
}
