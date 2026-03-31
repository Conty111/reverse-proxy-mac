package server

import (
	"context"
	"fmt"
	"net"
	"sync"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_proc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"reverse-proxy-mac/src/domain/logger"
)

const (
	// defaultMaxConcurrentStreams sets the maximum number of concurrent streams per connection
	defaultMaxConcurrentStreams = 1000
)

type GRPCServer struct {
	server       *grpc.Server
	listener     net.Listener
	logger       logger.Logger
	host         string
	port         int
	authSvc      envoy_auth.AuthorizationServer
	extProcSvc   ext_proc.ExternalProcessorServer
	healthServer *health.Server
	mu           sync.Mutex
	running      bool
}

// NewGRPCServer creates a new gRPC server instance with the specified configuration.
// Registers both the Authorization service and the ExternalProcessor service.
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

// NewAuthOnlyGRPCServer creates a gRPC server that registers only the Authorization service.
// Used for transport-level ext_authz on a dedicated port.
func NewAuthOnlyGRPCServer(
	host string,
	port int,
	authSvc envoy_auth.AuthorizationServer,
	log logger.Logger,
) *GRPCServer {
	return &GRPCServer{
		host:    host,
		port:    port,
		authSvc: authSvc,
		logger:  log,
	}
}

func (s *GRPCServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if server is already running
	if s.running {
		return fmt.Errorf("server is already running")
	}

	// Create listener
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	// Create gRPC server with options
	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(defaultMaxConcurrentStreams),
	}
	s.server = grpc.NewServer(opts...)

	// Always register the Authorization service
	envoy_auth.RegisterAuthorizationServer(s.server, s.authSvc)

	// Register ExternalProcessor service only when provided
	if s.extProcSvc != nil {
		ext_proc.RegisterExternalProcessorServer(s.server, s.extProcSvc)
	}

	// Register health service
	s.healthServer = health.NewServer()
	grpc_health_v1.RegisterHealthServer(s.server, s.healthServer)
	s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	s.logger.Info(ctx, "gRPC server starting", map[string]interface{}{"address": addr})

	s.running = true

	// Start server in background goroutine
	go func() {
		if err := s.server.Serve(listener); err != nil {
			s.logger.Error(context.Background(), "gRPC server error", map[string]interface{}{"error": err.Error()})
		}
	}()

	s.logger.Info(ctx, "gRPC server started successfully", map[string]interface{}{"address": addr})

	return nil
}

// Stop gracefully shuts down the gRPC server
func (s *GRPCServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If server is not running, nothing to do
	if !s.running {
		return nil
	}

	s.logger.Info(ctx, "Stopping gRPC server", nil)

	// Update health status to not serving
	if s.healthServer != nil {
		s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	}

	// Gracefully stop the server
	if s.server != nil {
		s.server.GracefulStop()
		s.server = nil
	}

	s.running = false
	s.logger.Info(ctx, "gRPC server stopped", nil)
	return nil
}

// IsRunning returns true if the server is currently running.
func (s *GRPCServer) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
