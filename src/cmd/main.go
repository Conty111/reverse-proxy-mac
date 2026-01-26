package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"reverse-proxy-mac/src/config"
	"reverse-proxy-mac/src/internal/application/authentication"
	"reverse-proxy-mac/src/internal/application/authorization"
	"reverse-proxy-mac/src/pkg/auth"
	"reverse-proxy-mac/src/pkg/ldap"
	"reverse-proxy-mac/src/pkg/logger"
)

func main() {
	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.json"
	}

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	appLogger := logger.NewLogger(cfg.Logging.Level)
	appLogger.Info("Starting Reverse Proxy MAC service", "version", "1.0.0")

	// Initialize LDAP service
	ldapSvc, err := ldap.NewLDAPService(&cfg.LDAP, appLogger)
	if err != nil {
		appLogger.Fatal("Failed to initialize LDAP service", "error", err)
	}
	defer ldapSvc.Close()

	// Initialize authentication services based on configuration
	var authSvc *authentication.Service
	
	if cfg.Auth.Kerberos.Enabled && cfg.Auth.Default == "kerberos" {
		kerbSvc, err := auth.NewKerberosService(&cfg.Auth.Kerberos, ldapSvc, appLogger)
		if err != nil {
			appLogger.Fatal("Failed to initialize Kerberos service", "error", err)
		}
		authSvc = authentication.NewService(kerbSvc, ldapSvc, appLogger)
		appLogger.Info("Kerberos authentication enabled")
	} else {
		appLogger.Fatal("No authentication method configured")
	}

	// Initialize authorization service
	authzSvc := authorization.NewService(&cfg.MAC, ldapSvc, appLogger)

	// Start gRPC server for Envoy ext_authz
	grpcAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.GRPCPort)
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		appLogger.Fatal("Failed to listen", "address", grpcAddr, "error", err)
	}

	// Create ext_authz server
	extAuthServer := NewExtAuthServer(authSvc, authzSvc, appLogger)
	
	appLogger.Info("Starting gRPC server", "address", grpcAddr)
	
	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := extAuthServer.Serve(lis); err != nil {
			appLogger.Fatal("gRPC server failed", "error", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	appLogger.Info("Shutting down gracefully...")
	extAuthServer.GracefulStop()
	appLogger.Info("Server stopped")
}
