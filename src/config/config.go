package config

// Config represents the main configuration structure
type Config struct {
	Server       ServerConfig       `json:"server"`
	Auth         AuthConfig         `json:"auth"`
	LDAP         LDAPConfig         `json:"ldap"`
	Logging      LoggingConfig      `json:"logging"`
	MAC          MACConfig          `json:"mac"`
}

// ServerConfig contains server-related settings
type ServerConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	GRPCPort     int    `json:"grpc_port"`
	ReadTimeout  int    `json:"read_timeout"`  // seconds
	WriteTimeout int    `json:"write_timeout"` // seconds
}

// AuthConfig contains authentication settings
type AuthConfig struct {
	Kerberos KerberosConfig `json:"kerberos"`
	OAuth2   OAuth2Config   `json:"oauth2"`
	OIDC     OIDCConfig     `json:"oidc"`
	Default  string         `json:"default"` // "kerberos", "oauth2", or "oidc"
}

// KerberosConfig contains Kerberos-specific settings
type KerberosConfig struct {
	Enabled     bool   `json:"enabled"`
	KDCAddress  string `json:"kdc_address"`
	Realm       string `json:"realm"`
	ServiceName string `json:"service_name"`
	KeytabPath  string `json:"keytab_path"`
}

// OAuth2Config contains OAuth2-specific settings
type OAuth2Config struct {
	Enabled          bool   `json:"enabled"`
	TokenURL         string `json:"token_url"`
	IntrospectionURL string `json:"introspection_url"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
}

// OIDCConfig contains OIDC-specific settings
type OIDCConfig struct {
	Enabled      bool   `json:"enabled"`
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
}

// LDAPConfig contains LDAP connection settings
type LDAPConfig struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	BaseDN             string `json:"base_dn"`
	BindDN             string `json:"bind_dn"`
	BindPassword       string `json:"bind_password"`
	UserSearchFilter   string `json:"user_search_filter"`
	MACLabelAttribute  string `json:"mac_label_attribute"`
	HostSearchFilter   string `json:"host_search_filter"`
	UseTLS             bool   `json:"use_tls"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Timeout            int    `json:"timeout"` // seconds
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level  string `json:"level"` // "debug", "info", "warn", "error"
	Format string `json:"format"` // "json", "text"
	Output string `json:"output"` // "stdout", "stderr", or file path
}

// MACConfig contains MAC (Mandatory Access Control) settings
type MACConfig struct {
	Enabled         bool     `json:"enabled"`
	DefaultLabel    int     `json:"default_label"`
	EnforceOnL4     bool     `json:"enforce_on_l4"`
	// AllowedLabels   []string `json:"allowed_labels"`
	HeaderName      string   `json:"header_name"` // Header to add MAC label to
}
