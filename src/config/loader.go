package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadFromFile loads configuration from a JSON file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	setDefaults(&config)

	// Validate configuration
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets default values for configuration
func setDefaults(cfg *Config) {
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 9000
	}
	if cfg.Server.GRPCPort == 0 {
		cfg.Server.GRPCPort = 9001
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 30 // seconds
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 30 // seconds
	}

	if cfg.Auth.Default == "" {
		cfg.Auth.Default = "kerberos"
	}

	if cfg.LDAP.Port == 0 {
		if cfg.LDAP.UseTLS {
			cfg.LDAP.Port = 636
		} else {
			cfg.LDAP.Port = 389
		}
	}
	if cfg.LDAP.UserSearchFilter == "" {
		cfg.LDAP.UserSearchFilter = "(sAMAccountName=%s)"
	}
	if cfg.LDAP.HostSearchFilter == "" {
		cfg.LDAP.HostSearchFilter = "(|(cn=%s)(dNSHostName=%s))"
	}
	if cfg.LDAP.MACLabelAttribute == "" {
		cfg.LDAP.MACLabelAttribute = "msDS-AssignedAuthNPolicy"
	}
	if cfg.LDAP.Timeout == 0 {
		cfg.LDAP.Timeout = 10 // seconds
	}

	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}

	if cfg.MAC.HeaderName == "" {
		cfg.MAC.HeaderName = "X-ALD-MAC-User"
	}
}

// validate validates the configuration
func validate(cfg *Config) error {
	// Validate auth configuration
	if cfg.Auth.Default != "kerberos" && cfg.Auth.Default != "oauth2" && cfg.Auth.Default != "oidc" {
		return fmt.Errorf("invalid auth.default: must be 'kerberos', 'oauth2', or 'oidc'")
	}

	// Validate Kerberos config if enabled
	if cfg.Auth.Kerberos.Enabled {
		if cfg.Auth.Kerberos.KDCAddress == "" {
			return fmt.Errorf("kerberos.kdc_address is required when Kerberos is enabled")
		}
		if cfg.Auth.Kerberos.Realm == "" {
			return fmt.Errorf("kerberos.realm is required when Kerberos is enabled")
		}
		if cfg.Auth.Kerberos.ServiceName == "" {
			return fmt.Errorf("kerberos.service_name is required when Kerberos is enabled")
		}
		if cfg.Auth.Kerberos.KeytabPath == "" {
			return fmt.Errorf("kerberos.keytab_path is required when Kerberos is enabled")
		}
	}

	// Validate OAuth2 config if enabled
	if cfg.Auth.OAuth2.Enabled {
		if cfg.Auth.OAuth2.IntrospectionURL == "" {
			return fmt.Errorf("oauth2.introspection_url is required when OAuth2 is enabled")
		}
		if cfg.Auth.OAuth2.ClientID == "" {
			return fmt.Errorf("oauth2.client_id is required when OAuth2 is enabled")
		}
	}

	// Validate OIDC config if enabled
	if cfg.Auth.OIDC.Enabled {
		if cfg.Auth.OIDC.IssuerURL == "" {
			return fmt.Errorf("oidc.issuer_url is required when OIDC is enabled")
		}
		if cfg.Auth.OIDC.ClientID == "" {
			return fmt.Errorf("oidc.client_id is required when OIDC is enabled")
		}
	}

	// Validate LDAP configuration
	if cfg.LDAP.Host == "" {
		return fmt.Errorf("ldap.host is required")
	}
	if cfg.LDAP.BaseDN == "" {
		return fmt.Errorf("ldap.base_dn is required")
	}

	// Validate logging level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[cfg.Logging.Level] {
		return fmt.Errorf("invalid logging.level: must be 'debug', 'info', 'warn', or 'error'")
	}

	return nil
}
