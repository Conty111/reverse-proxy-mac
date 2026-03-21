package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"reverse-proxy-mac/src/domain/logger"
)

// Default configuration values.
const (
	DefaultGRPCPort  = 9001
	DefaultHTTPPort  = 8080
	DefaultHost      = "0.0.0.0"
	DefaultLogLevel  = "info"
	DefaultLDAPPort  = 389
	DefaultLDAPSPort = 636
)

type Config struct {
	Server ServerConfig `json:"server"`
	Log    LogConfig    `json:"log"`
	LDAP   LDAPConfig   `json:"ldap"`
}

type ServerConfig struct {
	GRPCPort int    `json:"grpc_port"`
	HTTPPort int    `json:"http_port"`
	Host     string `json:"host"`
}

type LogConfig struct {
	Level      string `json:"level"`
	JSONFormat bool   `json:"json_format"`
}

type LDAPConfig struct {
	TLS           bool           `json:"tls"`
	Port          int            `json:"port"`
	Host          string         `json:"host"`
	TLSSkipVerify bool           `json:"tls_skip_verify"`
	TLSCACertFile string         `json:"tls_ca_cert_file"`
	Kerberos      KerberosConfig `json:"kerberos"`
}

type KerberosConfig struct {
	Keytab     string `json:"keytab"`
	Principal  string `json:"principal"`
	Realm      string `json:"realm"`
	ConfigPath string `json:"config_path"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.setDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Server.GRPCPort == 0 {
		c.Server.GRPCPort = DefaultGRPCPort
	}
	if c.Server.HTTPPort == 0 {
		c.Server.HTTPPort = DefaultHTTPPort
	}
	if c.Server.Host == "" {
		c.Server.Host = DefaultHost
	}
	if c.Log.Level == "" {
		c.Log.Level = DefaultLogLevel
	}
	if c.LDAP.Port == 0 {
		if c.LDAP.TLS {
			c.LDAP.Port = DefaultLDAPSPort
		} else {
			c.LDAP.Port = DefaultLDAPPort
		}
	}
}

// Validate checks the configuration for required fields and valid values.
func (c *Config) Validate() error {
	var errs []string

	if c.LDAP.Host == "" {
		errs = append(errs, "ldap.host is required")
	}

	if c.LDAP.Kerberos.Keytab == "" {
		errs = append(errs, "ldap.kerberos.keytab is required")
	}

	if c.LDAP.Kerberos.Principal == "" {
		errs = append(errs, "ldap.kerberos.principal is required")
	}

	if c.LDAP.Kerberos.Realm == "" {
		errs = append(errs, "ldap.kerberos.realm is required")
	}

	if c.Server.GRPCPort < 1 || c.Server.GRPCPort > 65535 {
		errs = append(errs, "server.grpc_port must be between 1 and 65535")
	}

	if c.Server.HTTPPort < 1 || c.Server.HTTPPort > 65535 {
		errs = append(errs, "server.http_port must be between 1 and 65535")
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

func (c *LogConfig) GetLogLevel() logger.Level {
	switch strings.ToLower(c.Level) {
	case "debug":
		return logger.LevelDebug
	case "info":
		return logger.LevelInfo
	case "warn", "warning":
		return logger.LevelWarn
	case "error":
		return logger.LevelError
	default:
		return logger.LevelInfo
	}
}
