package usecase

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
)

// KerberosAuthorizer implements Kerberos-based authorization for L7 traffic
type KerberosAuthorizer struct {
	logger           logger.Logger
	keytab           *keytab.Keytab
	servicePrincipal string
	loginPageURL     string
	enabled          bool
}

// NewKerberosAuthorizer creates a new KerberosAuthorizer
func NewKerberosAuthorizer(log logger.Logger, keytabPath, servicePrincipal, loginPageURL string, enabled bool) (*KerberosAuthorizer, error) {
	var kt *keytab.Keytab
	var err error

	if enabled && keytabPath != "" {
		kt, err = keytab.Load(keytabPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load keytab: %w", err)
		}
		log.Info(context.Background(), "Keytab loaded successfully", map[string]interface{}{
			"keytab_path":       keytabPath,
			"service_principal": servicePrincipal,
		})
	}

	return &KerberosAuthorizer{
		logger:           log,
		keytab:           kt,
		servicePrincipal: servicePrincipal,
		loginPageURL:     loginPageURL,
		enabled:          enabled,
	}, nil
}

// Authorize performs Kerberos authentication check
func (a *KerberosAuthorizer) Authorize(ctx context.Context, req *auth.AuthRequest) (*auth.AuthResponse, error) {
	// Log the request
	fields := map[string]interface{}{
		"request_id":  req.RequestID,
		"source_ip":   req.SourceIP,
		"source_port": req.SourcePort,
		"dest_ip":     req.DestIP,
		"dest_port":   req.DestPort,
		"protocol":    req.Protocol,
	}

	if req.HTTPMethod != "" {
		fields["http_method"] = req.HTTPMethod
		fields["http_path"] = req.HTTPPath
	}

	a.logger.Info(ctx, "Kerberos authorization request received", fields)

	// If Kerberos is not enabled, allow all
	if !a.enabled {
		a.logger.Info(ctx, "Kerberos authentication disabled - allowing request", nil)
		return &auth.AuthResponse{
			Decision: auth.DecisionAllow,
			Reason:   "Kerberos authentication disabled",
		}, nil
	}

	// Check for Authorization header
	authHeader, exists := req.HTTPHeaders["authorization"]
	if !exists {
		a.logger.Info(ctx, "No Authorization header - returning 401", nil)
		return a.createUnauthorizedResponse(), nil
	}

	// Check if it's a Negotiate (Kerberos/SPNEGO) token
	if !strings.HasPrefix(authHeader, "Negotiate ") {
		a.logger.Warn(ctx, "Authorization header is not Negotiate type - returning 401", map[string]interface{}{
			"auth_header_prefix": authHeader[:min(20, len(authHeader))],
		})
		return a.createUnauthorizedResponse(), nil
	}

	// Extract and decode the Kerberos ticket
	tokenStr := strings.TrimPrefix(authHeader, "Negotiate ")
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		a.logger.Error(ctx, "Failed to decode Kerberos token", map[string]interface{}{
			"error": err.Error(),
		})
		return a.createUnauthorizedResponse(), nil
	}

	// Verify and decrypt the Kerberos ticket
	ticket, err := a.verifyKerberosTicket(ctx, tokenBytes)
	if err != nil {
		a.logger.Error(ctx, "Kerberos ticket verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		return a.createUnauthorizedResponse(), nil
	}

	// Log the decrypted ticket information
	a.logger.Info(ctx, "Kerberos ticket verified successfully", map[string]interface{}{
		"principal":        ticket.Principal,
		"realm":            ticket.Realm,
		"auth_time":        ticket.AuthTime,
		"end_time":         ticket.EndTime,
		"is_valid":         ticket.Valid,
		"session_key_type": ticket.SessionKeyType,
	})

	// Allow the request
	return &auth.AuthResponse{
		Decision: auth.DecisionAllow,
		Reason:   fmt.Sprintf("Kerberos authentication successful for %s", ticket.Principal),
		Headers: map[string]string{
			"X-Authenticated-User": ticket.Principal,
			"X-Auth-Realm":         ticket.Realm,
		},
	}, nil
}

// TicketInfo contains information extracted from a Kerberos ticket
type TicketInfo struct {
	Principal      string
	Realm          string
	AuthTime       string
	EndTime        string
	Valid          bool
	SessionKeyType string
}

func (a *KerberosAuthorizer) verifyKerberosTicket(ctx context.Context, tokenBytes []byte) (*TicketInfo, error) {
	if a.keytab == nil {
		return nil, fmt.Errorf("keytab not loaded")
	}

	// Parse SPNEGO token
	var spnegoToken spnego.SPNEGOToken
	err := spnegoToken.Unmarshal(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SPNEGO token: %w", err)
	}

	if !spnegoToken.Init {
		return nil, fmt.Errorf("expected NegTokenInit")
	}

	// Parse the KRB5 token from MechTokenBytes
	var krb5Token spnego.KRB5Token
	err = krb5Token.Unmarshal(spnegoToken.NegTokenInit.MechTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KRB5 token: %w", err)
	}

	if !krb5Token.IsAPReq() {
		return nil, fmt.Errorf("expected AP-REQ token")
	}

	// Verify the AP-REQ
	settings := service.NewSettings(a.keytab)
	valid, creds, err := service.VerifyAPREQ(&krb5Token.APReq, settings)
	if err != nil {
		return nil, fmt.Errorf("failed to verify AP-REQ: %w", err)
	}

	if !valid {
		return nil, fmt.Errorf("ticket validation failed")
	}

	// Extract ticket information
	ticketInfo := &TicketInfo{
		Principal:      creds.CName().PrincipalNameString(),
		Realm:          creds.Domain(),
		AuthTime:       creds.AuthTime().String(),
		EndTime:        "N/A",
		Valid:          creds.Authenticated(),
		SessionKeyType: "N/A",
	}

	return ticketInfo, nil
}

func (a *KerberosAuthorizer) createUnauthorizedResponse() *auth.AuthResponse {
	return &auth.AuthResponse{
		Decision:      auth.DecisionDeny,
		Reason:        "Kerberos authentication required",
		DeniedStatus:  401,
		DeniedMessage: "Unauthorized",
		Headers: map[string]string{
			"WWW-Authenticate": "Negotiate",
		},
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
