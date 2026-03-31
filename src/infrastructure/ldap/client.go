package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/keytab"

	"reverse-proxy-mac/src/domain/logger"
	"reverse-proxy-mac/src/infrastructure/config"
)

const (
	maxRetries     = 3
	retryBaseDelay = 200 * time.Millisecond
	retryMaxDelay  = 2 * time.Second
)

type Client struct {
	host              string
	port              int
	baseDN            string
	useTLS            bool
	tlsConfig         *tls.Config
	keytab            *keytab.Keytab
	kerberosPrincipal string
	kerberosRealm     string

	Logger logger.Logger

	gssApiClient   ldap.GSSAPIClient
	connMu         sync.RWMutex
	ldapConnection *ldap.Conn
}

func NewClient(cfg *config.LDAPConfig, log logger.Logger) (*Client, error) {
	c := &Client{
		host:   cfg.Host,
		port:   cfg.Port,
		baseDN: cfg.BaseDN,
		useTLS: cfg.TLS,
		Logger: log,
	}

	if cfg.TLS {
		tlsConfig, err := c.buildTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		c.tlsConfig = tlsConfig
	}

	if err := c.initKerberos(&cfg.Kerberos); err != nil {
		return nil, fmt.Errorf("failed to initialize Kerberos: %w", err)
	}

	conn, err := c.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	c.ldapConnection = conn

	return c, nil
}

func (cl *Client) Close() error {
	cl.connMu.Lock()
	defer cl.connMu.Unlock()

	if cl.ldapConnection != nil {
		if err := cl.ldapConnection.Close(); err != nil {
			cl.Logger.Warn(context.Background(), "Failed to close LDAP connection", map[string]interface{}{
				"error": err.Error(),
			})
			return err
		}
		cl.ldapConnection = nil
	}
	return nil
}

func (cl *Client) IsConnected() bool {
	cl.connMu.RLock()
	defer cl.connMu.RUnlock()

	return cl.ldapConnection != nil
}

func (cl *Client) reconnect(ctx context.Context) error {
	cl.connMu.Lock()
	defer cl.connMu.Unlock()

	if cl.ldapConnection != nil && !cl.ldapConnection.IsClosing() {
		return nil
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryDelay(attempt - 1)
			cl.Logger.Info(ctx, "Retrying LDAP connection", map[string]interface{}{
				"attempt": attempt,
				"delay":   delay.String(),
			})
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		conn, err := cl.connect()
		if err == nil {
			cl.Logger.Info(ctx, "Reconnected to LDAP server", map[string]interface{}{})
			cl.ldapConnection = conn
			return nil
		}

		lastErr = err
		cl.Logger.Error(ctx, "LDAP connection attempt failed", map[string]interface{}{
			"attempt": attempt,
			"error":   err.Error(),
		})
	}

	return fmt.Errorf("failed to reconnect to LDAP after %d attempts: %w", maxRetries, lastErr)
}

func retryDelay(attempt int) time.Duration {
	delay := retryBaseDelay * (1 << attempt)
	if delay > retryMaxDelay {
		delay = retryMaxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(delay) / 2))
	return delay + jitter
}

func (cl *Client) connect() (*ldap.Conn, error) {
	scheme := "ldap"
	if cl.useTLS {
		scheme = "ldaps"
	}
	address := fmt.Sprintf("%s://%s:%d", scheme, cl.host, cl.port)

	cl.Logger.Debug(context.Background(), "Connecting to LDAP server", map[string]interface{}{
		"address":     address,
		"tls_enabled": cl.useTLS,
	})

	var conn *ldap.Conn
	var err error

	if cl.useTLS && cl.tlsConfig != nil {
		conn, err = ldap.DialURL(address, ldap.DialWithTLSConfig(cl.tlsConfig))
	} else {
		conn, err = ldap.DialURL(address)
	}

	if err != nil {
		cl.Logger.Error(context.Background(), "Failed to dial LDAP server", map[string]interface{}{
			"error":   err.Error(),
			"address": address,
		})
		return nil, fmt.Errorf("failed to dial LDAP server at %s: %w", address, err)
	}

	targetSPN := fmt.Sprintf("ldap/%s", cl.host)

	cl.Logger.Debug(context.Background(), "Attempting GSSAPI bind", map[string]interface{}{
		"client_principal": cl.kerberosPrincipal,
		"target_spn":       targetSPN,
	})

	if err = conn.GSSAPIBind(cl.gssApiClient, targetSPN, ""); err != nil {
		cl.Logger.Error(context.Background(), "GSSAPI bind failed", map[string]interface{}{
			"error":     err.Error(),
			"principal": cl.kerberosPrincipal,
		})
		_ = conn.Close()
		return nil, fmt.Errorf("GSSAPI bind failed: %w", err)
	}

	cl.Logger.Info(context.Background(), "GSSAPI bind successful", map[string]interface{}{
		"principal": cl.kerberosPrincipal,
	})

	return conn, nil
}

func (cl *Client) buildTLSConfig(cfg *config.LDAPConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.TLSSkipVerify,
	}

	if cfg.TLSCACertFile != "" {
		caCert, err := os.ReadFile(cfg.TLSCACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
		tlsConfig.InsecureSkipVerify = false

		cl.Logger.Info(context.Background(), "Loaded custom CA certificate for LDAP TLS", map[string]interface{}{
			"ca_cert_file": cfg.TLSCACertFile,
		})
	} else if cfg.TLSSkipVerify {
		cl.Logger.Warn(context.Background(), "TLS certificate verification is disabled for LDAP connection", map[string]interface{}{
			"host": cfg.Host,
		})
	}

	return tlsConfig, nil
}
