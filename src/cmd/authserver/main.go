package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"reverse-proxy-mac/src/application/usecase"
	"reverse-proxy-mac/src/infrastructure/cache"
	"reverse-proxy-mac/src/infrastructure/config"
	"reverse-proxy-mac/src/infrastructure/grpc"
	"reverse-proxy-mac/src/infrastructure/ldap"
	"reverse-proxy-mac/src/infrastructure/logging"
	"reverse-proxy-mac/src/presentation/server"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	log := logging.NewConsoleLogger(cfg.Log.GetLogLevel(), cfg.Log.JSONFormat)

	log.Info(ctx, "Starting mac-authserver", map[string]interface{}{
		"config_path":         *configPath,
		"grpc_port":           cfg.Server.GRPCPort,
		"http_port":           cfg.Server.HTTPPort,
		"log_level":           cfg.Log.Level,
	})

	ldapClient, err := ldap.NewClient(
		&cfg.LDAP,
		log,
	)
	if err != nil {
		log.Error(ctx, "Failed to initialize LDAP client", map[string]interface{}{"error": err.Error()})
		return err
	}
	defer func() {
		if err := ldapClient.Close(); err != nil {
			log.Error(ctx, "Error closing LDAP client", map[string]interface{}{"error": err.Error()})
		}
	}()

	// Build the in-memory cache with an initial synchronous load from LDAP.
	cacheTTL := time.Duration(cfg.LDAP.CacheTTLSeconds) * time.Second
	macCache, err := cache.NewStore(ctx, ldapClient, log, cacheTTL)
	if err != nil {
		log.Error(ctx, "Failed to initialize MAC policy cache", map[string]interface{}{"error": err.Error()})
		return err
	}
	// Start the background refresh goroutine; it stops when ctx is cancelled.
	macCache.Start(ctx)

	httpAuthHandler, err := usecase.NewHTTPAuthorizer(log, ldapClient, macCache)
	if err != nil {
		log.Error(ctx, "Failed to initialize httpAuthHandler", map[string]interface{}{"error": err.Error()})
		return err
	}

	transportAuthHandler, err := usecase.NewTransportAuthorizer(log, ldapClient, macCache)
	if err != nil {
		log.Error(ctx, "Failed to initialize transportAuthHandler", map[string]interface{}{"error": err.Error()})
		return err
	}

	authService := grpc.NewAuthServiceV3(httpAuthHandler, transportAuthHandler, log)
	extProcService := grpc.NewExtProcServiceV3(transportAuthHandler, log)

	grpcServer := server.NewGRPCServer(cfg.Server.Host, cfg.Server.GRPCPort, authService, extProcService, log)
	if err := grpcServer.Start(ctx); err != nil {
		log.Error(ctx, "Failed to start gRPC server", map[string]interface{}{"error": err.Error()})
		return err
	}

	// Start HTTP server for health checks and metrics
	httpServer := server.NewHTTPServer(cfg.Server.Host, cfg.Server.HTTPPort, log)

	// Register health checkers
	httpServer.RegisterHealthChecker("grpc", &grpcHealthChecker{grpcServer: grpcServer})
	httpServer.RegisterHealthChecker("ldap", &ldapHealthChecker{ldapClient: ldapClient})

	if err := httpServer.Start(ctx); err != nil {
		log.Error(ctx, "Failed to start HTTP server", map[string]interface{}{"error": err.Error()})
		return err
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Info(ctx, "Service is running. Send TERMINATION signal to stop (Ctrl+C)", nil)
	<-sigChan

	log.Info(ctx, "Shutdown signal received", nil)

	// Graceful shutdown
	if err := httpServer.Stop(ctx); err != nil {
		log.Error(ctx, "Error stopping HTTP server", map[string]interface{}{"error": err.Error()})
	}

	if err := grpcServer.Stop(ctx); err != nil {
		log.Error(ctx, "Error stopping gRPC server", map[string]interface{}{"error": err.Error()})
	}

	// if err := transportGRPCServer.Stop(ctx); err != nil {
	// 	log.Error(ctx, "Error stopping transport gRPC server", map[string]interface{}{"error": err.Error()})
	// }

	log.Info(ctx, "Service stopped successfully", nil)
	return nil
}

// grpcHealthChecker implements server.HealthChecker for gRPC server.
type grpcHealthChecker struct {
	grpcServer *server.GRPCServer
}

func (c *grpcHealthChecker) IsHealthy(ctx context.Context) bool {
	return c.grpcServer.IsRunning()
}

// ldapHealthChecker implements server.HealthChecker for LDAP client.
type ldapHealthChecker struct {
	ldapClient *ldap.Client
}

func (c *ldapHealthChecker) IsHealthy(ctx context.Context) bool {
	return c.ldapClient.IsConnected()
}
