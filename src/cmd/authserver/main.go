package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"reverse-proxy-mac/src/application/usecase"
	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/infrastructure/config"
	"reverse-proxy-mac/src/infrastructure/grpc"
	"reverse-proxy-mac/src/infrastructure/logging"
	"reverse-proxy-mac/src/presentation/server"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logging.NewConsoleLogger(cfg.Log.GetLogLevel(), cfg.Log.JSONFormat)
	ctx := context.Background()

	log.Info(ctx, "Starting Envoy External Auth Service", map[string]interface{}{
		"config_path": *configPath,
		"grpc_port":   cfg.Server.GRPCPort,
		"log_level":   cfg.Log.Level,
	})

	// Initialize use case (business logic)
	var authorizer auth.Authorizer
	var kerberosErr error
	
	if cfg.Kerberos.Enabled {
		log.Info(ctx, "Initializing Kerberos authorizer", map[string]interface{}{
			"keytab":            cfg.Kerberos.Keytab,
			"service_principal": cfg.Kerberos.ServicePrincipal,
			"login_page_url":    cfg.Kerberos.LoginPageURL,
		})
		authorizer, kerberosErr = usecase.NewKerberosAuthorizer(
			log,
			cfg.Kerberos.Keytab,
			cfg.Kerberos.ServicePrincipal,
			cfg.Kerberos.LoginPageURL,
			cfg.Kerberos.Enabled,
		)
		if kerberosErr != nil {
			log.Error(ctx, "Failed to initialize Kerberos authorizer", map[string]interface{}{
				"error": kerberosErr.Error(),
			})
			os.Exit(1)
		}
	} else {
		log.Info(ctx, "Kerberos disabled, using allow-all authorizer", nil)
		authorizer = usecase.NewAllowAllAuthorizer(log)
	}

	// Initialize gRPC services
	authServiceV3 := grpc.NewAuthServiceV3(authorizer, log)
	extProcServiceV3 := grpc.NewExtProcServiceV3(authorizer, log)

	// Initialize gRPC server
	grpcServer := server.NewGRPCServer(
		cfg.Server.Host,
		cfg.Server.GRPCPort,
		authServiceV3,
		extProcServiceV3,
		log,
	)

	// Start server
	if err := grpcServer.Start(ctx); err != nil {
		log.Error(ctx, "Failed to start gRPC server", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Info(ctx, "Service is running. Press Ctrl+C to stop.", nil)
	<-sigChan

	log.Info(ctx, "Shutdown signal received", nil)

	// Graceful shutdown
	if err := grpcServer.Stop(ctx); err != nil {
		log.Error(ctx, "Error during shutdown", map[string]interface{}{
			"error": err.Error(),
		})
		os.Exit(1)
	}

	log.Info(ctx, "Service stopped successfully", nil)
}

