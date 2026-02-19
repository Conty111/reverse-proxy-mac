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

	ldapClient := initLDAPClient(ctx, cfg, log)

	kerberosAuthHandler := initKerberosAuthHandler(ctx, cfg, log, ldapClient)
	transportAuthHandler := initTransportAuthHandler(ctx, cfg, log, ldapClient)

	httpAuthService := grpc.NewAuthServiceV3(kerberosAuthHandler, log)
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

	if err := grpcServer.Stop(ctx); err != nil {
		log.Error(ctx, "Error during shutdown", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	log.Info(ctx, "Service stopped successfully", nil)
}

func initLDAPClient(ctx context.Context, cfg *config.Config, log *logging.ConsoleLogger) ldap.LDAPClient {
	log.Info(ctx, "Initializing LDAP client", map[string]interface{}{
		"host":        cfg.Kerberos.LDAP.Host,
		"port":        cfg.Kerberos.LDAP.Port,
		"base_dn":     cfg.Kerberos.LDAP.BaseDN,
		"tls":         cfg.Kerberos.LDAP.TLS,
		"user_filter": cfg.Kerberos.LDAP.UserFilter,
	})

	client, err := ldap.NewClient(
		cfg.Kerberos.LDAP.Host,
		cfg.Kerberos.LDAP.Port,
		cfg.Kerberos.LDAP.BaseDN,
		cfg.Kerberos.LDAP.UserFilter,
		cfg.Kerberos.LDAP.TLS,
		true, // use_kerberos - always true when LDAP is configured
		cfg.Kerberos.Keytab,
		"", // kerberos_principal - not needed, will be derived from keytab
		"", // kerberos_realm - not needed, will be derived from keytab
		log,
	)
	if err != nil {
		log.Error(ctx, "Failed to initialize LDAP client", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	return client
}

func initKerberosAuthHandler(ctx context.Context, cfg *config.Config, log *logging.ConsoleLogger, ldapClient ldap.LDAPClient) auth.Authorizer {
	log.Info(ctx, "Initializing Kerberos authorizer", map[string]interface{}{
		"keytab":            cfg.Kerberos.Keytab,
		"service_principal": cfg.Kerberos.ServicePrincipal,
	})

	authHandler, err := usecase.NewKerberosAuthorizer(
		log,
		cfg.Kerberos.Keytab,
		cfg.Kerberos.ServicePrincipal,
		ldapClient,
	)
	if err != nil {
		log.Error(ctx, "Failed to initialize Kerberos authorizer", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	return authHandler
}

func initTransportAuthHandler(ctx context.Context, cfg *config.Config, log *logging.ConsoleLogger, ldapClient ldap.LDAPClient) auth.Authorizer {
	log.Info(ctx, "Initializing Kerberos authorizer", map[string]interface{}{
		"keytab":            cfg.Kerberos.Keytab,
		"service_principal": cfg.Kerberos.ServicePrincipal,
	})

	authHandler, err := usecase.NewTransportAuthorizer(
		log,
		cfg.Kerberos.Keytab,
		cfg.Kerberos.ServicePrincipal,
		ldapClient,
	)
	if err != nil {
		log.Error(ctx, "Failed to initialize Kerberos authorizer", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	return authHandler
}
