package config

import (
	"encoding/json"
	"fmt"
	"os"

	"reverse-proxy-mac/src/domain/logger"
)

type Config struct {
	Server ServerConfig `json:"server"`
	Log    LogConfig    `json:"log"`
	LDAP   LDAPConfig   `json:"ldap"`
}

type ServerConfig struct {
	GRPCPort int    `json:"grpc_port"`
	Host     string `json:"host"`
}

type LogConfig struct {
	Level      string `json:"level"`
	JSONFormat bool   `json:"json_format"`
}

type LDAPConfig struct {
	TLS                bool   `json:"tls"`
	Port               int    `json:"port"`
	Host               string `json:"host"`
	TLSSkipVerify      bool   `json:"tls_skip_verify"`
	TLSCACertFile      string `json:"tls_ca_cert_file"`
	Kerberos           KerberosConfig `json:"kerberos"`
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
	if c.LDAP.Port == 0 {
		if c.LDAP.TLS {
			c.LDAP.Port = 636
		} else {
			c.LDAP.Port = 389
		}
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
