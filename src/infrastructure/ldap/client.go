package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"reverse-proxy-mac/src/domain/logger"
	"reverse-proxy-mac/src/infrastructure/config"
)

type LDAPClient interface {
	SearchUser(ctx context.Context, username string, baseDN string) (*UserInfo, error)
	VerifyKerberosTicket(ctx context.Context, tokenBytes []byte) (*credentials.Credentials, error)
	Close() error
}

type UserInfo struct {
	UID  string
	DN   string
	Name string
}

type Client struct {
	host string
	port int
	useTLS            bool
	keytab            *keytab.Keytab
	kerberosPrincipal string
	kerberosRealm     string

	logger logger.Logger

	gssApiClient   ldap.GSSAPIClient
	ldapConnection *ldap.Conn
}

func NewClient(cfg *config.LDAPConfig, logger logger.Logger) (*Client, error) {

	c := &Client{
		host: cfg.Host,
		port: cfg.Port,
		useTLS: cfg.TLS,
		logger: logger,
	}

	if err := c.initKerberos(&cfg.Kerberos); err != nil {
		return nil, err
	}

	conn, err := c.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	c.ldapConnection = conn

	return c, nil
}

// Close cleans up resources used by the LDAP client
func (cl *Client) Close() error {
	if closeErr := cl.ldapConnection.Close(); closeErr != nil {
		cl.logger.Warn(context.Background(), "Failed to close LDAP connection", map[string]interface{}{
			"error": closeErr.Error(),
		})
	}
	return nil
}

func (cl *Client) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("ldaps://%s:%d", cl.host, cl.port)

	currentTime := time.Now()
	cl.logger.Debug(context.Background(), "Connecting to LDAP server", map[string]interface{}{
		"address":      address,
		"host":         cl.host,
		"port":         cl.port,
		"current_time": currentTime.Format(time.RFC3339),
		"unix_time":    currentTime.Unix(),
	})

	conn, err := ldap.DialURL(
		address,
		ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: true, // TODO: enable verify tls connection
		}))
	if err != nil {
		cl.logger.Error(context.Background(), "Failed to dial LDAP server", map[string]interface{}{
			"error":   err.Error(),
			"address": address,
		})
		return nil, fmt.Errorf("failed to dial LDAP server: %w", err)
	}

	conn.Debug = true
	
	targetSPN := fmt.Sprintf("ldap/%s", cl.host)

	cl.logger.Debug(context.Background(), "Attempting GSSAPI bind", map[string]interface{}{
		"client_principal": cl.kerberosPrincipal,
		"target_spn":       targetSPN,
		"host":             cl.host,
	})
	
	err = conn.GSSAPIBind(cl.gssApiClient, targetSPN, "")
	if err != nil {
		cl.logger.Error(context.Background(), "GSSAPI bind failed", map[string]interface{}{
			"error":     err.Error(),
			"principal": cl.kerberosPrincipal,
			"host":      cl.host,
		})
		if err := conn.Close(); err != nil {
			return nil, fmt.Errorf("GSSAPI connection close failed: %w", err)
		}
		return nil, fmt.Errorf("GSSAPI bind failed: %w", err)
	}

	cl.logger.Info(context.Background(), "GSSAPI bind successful", map[string]interface{}{
		"principal": cl.kerberosPrincipal,
	})

	return conn, nil
}
