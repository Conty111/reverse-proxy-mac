package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"reverse-proxy-mac/src/application/usecase"
	"reverse-proxy-mac/src/infrastructure/config"
	"reverse-proxy-mac/src/infrastructure/grpc"
	"reverse-proxy-mac/src/infrastructure/ldap"
	"reverse-proxy-mac/src/infrastructure/logging"
	"reverse-proxy-mac/src/presentation/server"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	log := logging.NewConsoleLogger(cfg.Log.GetLogLevel(), cfg.Log.JSONFormat)
	ctx := context.Background()

	log.Info(ctx, "Starting mac-authserver", map[string]interface{}{
		"config_path": *configPath,
		"grpc_port":   cfg.Server.GRPCPort,
		"log_level":   cfg.Log.Level,
	})

	ldapClient, err := ldap.NewClient(
		&cfg.LDAP,
		log,
	)
	if err != nil {
		log.Error(ctx, "Failed to initialize LDAP client", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	httpAuthHandler, err := usecase.NewHTTPAuthorizer(
		log,
		ldapClient,
	)
	if err != nil {
		log.Error(ctx, "Failed to initialize kerberosAuthHandler", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	transportAuthHandler, err := usecase.NewTransportAuthorizer(log, ldapClient)
	if err != nil {
		log.Error(ctx, "Failed to initialize transportAuthHandler", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	httpAuthService := grpc.NewAuthServiceV3(httpAuthHandler, log)
	transportAuthService := grpc.NewExtProcServiceV3(transportAuthHandler, log)

	grpcServer := server.NewGRPCServer(cfg.Server.Host, cfg.Server.GRPCPort, httpAuthService, transportAuthService, log)

	if err := grpcServer.Start(ctx); err != nil {
		log.Error(ctx, "Failed to start gRPC server", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	log.Info(ctx, "Service is running. Send TERMINATION signal to stop (Ctrl+C)", nil)
	<-sigChan

	log.Info(ctx, "Shutdown signal received", nil)

	// Graceful shutdown
	if err := grpcServer.Stop(ctx); err != nil {
		log.Error(ctx, "Error stopping gRPC server", map[string]interface{}{"error": err.Error()})
	}

	// Close LDAP client
	if err := ldapClient.Close(); err != nil {
		log.Error(ctx, "Error closing LDAP client", map[string]interface{}{"error": err.Error()})
	}

	log.Info(ctx, "Service stopped successfully", nil)
}
