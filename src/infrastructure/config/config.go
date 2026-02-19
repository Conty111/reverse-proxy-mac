package config

import (
	"encoding/json"
	"fmt"
	"os"

	"reverse-proxy-mac/src/domain/logger"
)

type Config struct {
	Server   ServerConfig   `json:"server"`
	Log      LogConfig      `json:"log"`
	Kerberos KerberosConfig `json:"kerberos"`
}

type ServerConfig struct {
	GRPCPort int    `json:"grpc_port"`
	Host     string `json:"host"`
}

type LogConfig struct {
	Level      string `json:"level"`
	JSONFormat bool   `json:"json_format"`
}

type KerberosConfig struct {
	Keytab           string     `json:"keytab"`
	ServicePrincipal string     `json:"service_principal"`
	LDAP             LDAPConfig `json:"ldap"`
}

type LDAPConfig struct {
	TLS        bool   `json:"tls"`
	Port       int    `json:"port"`
	Host       string `json:"host"`
	BaseDN     string `json:"base_dn"`
	UserFilter string `json:"user_filter"`
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
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.Server.GRPCPort == 0 {
		c.Server.GRPCPort = 9001
	}
	if c.Server.Host == "" {
		c.Server.Host = "0.0.0.0"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Kerberos.LDAP.Port == 0 {
		if c.Kerberos.LDAP.TLS {
			c.Kerberos.LDAP.Port = 636
		} else {
			c.Kerberos.LDAP.Port = 389
		}
	}
	if c.Kerberos.LDAP.UserFilter == "" {
		c.Kerberos.LDAP.UserFilter = "(sAMAccountName=%s)"
	}
}

func (c *LogConfig) GetLogLevel() logger.Level {
	switch c.Level {
	case "debug":
		return logger.LevelDebug
	case "info":
		return logger.LevelInfo
	case "warn":
		return logger.LevelWarn
	case "error":
		return logger.LevelError
	default:
		return logger.LevelInfo
	}
}
