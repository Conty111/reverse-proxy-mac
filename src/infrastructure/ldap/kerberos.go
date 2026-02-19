package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"reverse-proxy-mac/src/infrastructure/config"
)

func (c *Client) initKerberos(cfg *config.KerberosConfig) error {

	// Load keytab file first. All requests to LDAP will be authorized via Kerberos and this keytab
	// Also this keytab may be used to decrypt and authorize users Kerberos tickets
	kt, err := keytab.Load(cfg.Keytab)
	if err != nil {
		return fmt.Errorf("failed to load keytab: %w", err)
	}
	
	// Log keytab entries for diagnostics
	entries := kt.Entries
	c.logger.Info(context.Background(), "Keytab loaded successfully", map[string]interface{}{
		"keytab_path":    cfg.Keytab,
		"entries_count":  len(entries),
	})
	
	// Log encryption types available in keytab
	etypes := make(map[int32]bool)
	for _, entry := range entries {
		etypes[entry.Key.KeyType] = true
	}
	etypesList := make([]int32, 0, len(etypes))
	for etype := range etypes {
		etypesList = append(etypesList, etype)
	}
	c.logger.Debug(context.Background(), "Keytab encryption types", map[string]interface{}{
		"etypes": etypesList,
	})

	c.keytab = kt
	c.kerberosRealm = cfg.Realm
	c.kerberosPrincipal = cfg.Principal

	c.logger.Info(context.Background(), "Initializing Kerberos client", map[string]interface{}{
		"principal":   c.kerberosPrincipal,
		"realm":       c.kerberosRealm,
		"keytab":      cfg.Keytab,
		"config_path": cfg.ConfigPath,
	})

	c.logger.Debug(context.Background(), "Creating GSSAPI client", map[string]interface{}{
		"principal":   c.kerberosPrincipal,
		"realm":       c.kerberosRealm,
		"keytab":      cfg.Keytab,
		"config_path": cfg.ConfigPath,
		"pafx_fast":   "disabled",
	})
	
	gssapiClient, err := gssapi.NewClientWithKeytab(
		c.kerberosPrincipal,
		c.kerberosRealm,
		cfg.Keytab,
		cfg.ConfigPath,
		client.DisablePAFXFAST(true),
	)
	if err != nil {
		c.logger.Error(context.Background(), "Failed to create GSSAPI client", map[string]interface{}{
			"error":     err.Error(),
			"principal": c.kerberosPrincipal,
			"realm":     c.kerberosRealm,
		})
		return fmt.Errorf("failed to create gssapi client: %w", err)
	}

	c.logger.Info(context.Background(), "Attempting GSSAPI client login", map[string]interface{}{
		"principal": c.kerberosPrincipal,
		"realm":     c.kerberosRealm,
	})

	if err := gssapiClient.Login(); err != nil {
		c.logger.Error(context.Background(), "GSSAPI client login failed", map[string]interface{}{
			"error":     err.Error(),
			"principal": c.kerberosPrincipal,
			"realm":     c.kerberosRealm,
		})
		return fmt.Errorf("failed to login with gssapiClient: %w", err)
	}

	c.logger.Info(context.Background(), "GSSAPI client login successful", map[string]interface{}{
		"principal": c.kerberosPrincipal,
		"realm":     c.kerberosRealm,
	})

	c.gssApiClient = gssapiClient

	return nil
}

func (cl *Client) VerifyKerberosTicket(ctx context.Context, tokenBytes []byte) (*credentials.Credentials, error) {
	cl.logger.Debug(ctx, "Starting Kerberos ticket verification", map[string]interface{}{
		"token_size": len(tokenBytes),
	})

	var spnegoToken spnego.SPNEGOToken
	err := spnegoToken.Unmarshal(tokenBytes)
	if err != nil {
		cl.logger.Error(ctx, "Failed to unmarshal SPNEGO token", map[string]interface{}{
			"error":      err.Error(),
			"token_size": len(tokenBytes),
		})
		return nil, fmt.Errorf("failed to unmarshal SPNEGO token: %w", err)
	}

	if !spnegoToken.Init {
		cl.logger.Error(ctx, "Invalid SPNEGO token type", map[string]interface{}{
			"expected": "NegTokenInit",
			"received": "NegTokenResp or other",
		})
		return nil, fmt.Errorf("expected NegTokenInit")
	}

	var krb5Token spnego.KRB5Token
	err = krb5Token.Unmarshal(spnegoToken.NegTokenInit.MechTokenBytes)
	if err != nil {
		cl.logger.Error(ctx, "Failed to unmarshal KRB5 token", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to unmarshal KRB5 token: %w", err)
	}

	if !krb5Token.IsAPReq() {
		cl.logger.Error(ctx, "Invalid KRB5 token type", map[string]interface{}{
			"expected": "AP-REQ",
		})
		return nil, fmt.Errorf("expected AP-REQ token")
	}

	settings := service.NewSettings(cl.keytab)
	valid, creds, err := service.VerifyAPREQ(&krb5Token.APReq, settings)
	if err != nil {
		cl.logger.Error(ctx, "AP-REQ verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to verify AP-REQ: %w", err)
	}

	if !valid {
		cl.logger.Error(ctx, "Kerberos ticket validation failed", map[string]interface{}{
			"reason": "Ticket marked as invalid by verifier",
		})
		return nil, fmt.Errorf("ticket validation failed")
	}

	cl.logger.Debug(ctx, "Kerberos ticket verification completed", map[string]interface{}{
		"principal": creds.CName().PrincipalNameString(),
		"realm":     creds.Realm(),
	})

	return creds, nil
}
