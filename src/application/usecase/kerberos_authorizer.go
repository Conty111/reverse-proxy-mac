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
	"reverse-proxy-mac/src/infrastructure/ldap"
)

type KerberosAuthorizer struct {
	logger           logger.Logger
	keytab           *keytab.Keytab
	servicePrincipal string
	enabled          bool
	ldapClient       ldap.LDAPClient
}

type TicketInfo struct {
	Principal      string
	Realm          string
	AuthTime       string
	EndTime        string
	Valid          bool
	SessionKeyType string
}

func NewKerberosAuthorizer(log logger.Logger, keytabPath, servicePrincipal string, ldapClient ldap.LDAPClient) (*KerberosAuthorizer, error) {
	var kt *keytab.Keytab
	var err error

	if keytabPath != "" {
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
		ldapClient:       ldapClient,
	}, nil
}

func (a *KerberosAuthorizer) Authorize(ctx context.Context, req *auth.AuthRequest) (*auth.AuthResponse, error) {
	if !a.enabled {
		return &auth.AuthResponse{
			Decision: auth.DecisionAllow,
			Reason:   "Kerberos authentication disabled",
		}, nil
	}

	authHeader, exists := req.HTTPHeaders["authorization"]
	if !exists {
		return a.createUnauthorizedResponse(), nil
	}

	if !strings.HasPrefix(authHeader, "Negotiate ") {
		return a.createUnauthorizedResponse(), nil
	}

	tokenStr := strings.TrimPrefix(authHeader, "Negotiate ")
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		a.logger.Error(ctx, "Failed to decode Kerberos token", map[string]interface{}{"error": err.Error()})
		return a.createUnauthorizedResponse(), nil
	}

	ticket, err := a.verifyKerberosTicket(ctx, tokenBytes)
	if err != nil {
		a.logger.Error(ctx, "Kerberos ticket verification failed", map[string]interface{}{"error": err.Error()})
		return a.createUnauthorizedResponse(), nil
	}

	a.logger.Info(ctx, "Kerberos authentication successful", map[string]interface{}{
		"principal": ticket.Principal,
		"realm":     ticket.Realm,
	})

	responseHeaders := map[string]string{
		"X-Authenticated-User": ticket.Principal,
		"X-Auth-Realm":         ticket.Realm,
	}

	if a.ldapClient != nil {
		userInfo, err := a.ldapClient.SearchUser(ctx, ticket.Principal)
		if err != nil {
			a.logger.Warn(ctx, "Failed to lookup user in LDAP", map[string]interface{}{
				"principal": ticket.Principal,
				"error":     err.Error(),
			})
		} else {
			a.logger.Info(ctx, "User information retrieved from LDAP", map[string]interface{}{
				"username":     userInfo.Username,
				"display_name": userInfo.DisplayName,
				"email":        userInfo.Email,
			})
			a.addUserHeadersIfPresent(responseHeaders, userInfo)
		}
	}

	return &auth.AuthResponse{
		Decision: auth.DecisionAllow,
		Reason:   fmt.Sprintf("Kerberos authentication successful for %s", ticket.Principal),
		Headers:  responseHeaders,
	}, nil
}

func (a *KerberosAuthorizer) addUserHeadersIfPresent(headers map[string]string, userInfo *ldap.UserInfo) {
	if userInfo.Username != "" {
		headers["X-ALD-User-SAM"] = userInfo.Username
	}
	if userInfo.DisplayName != "" {
		headers["X-ALD-User-DisplayName"] = userInfo.DisplayName
	}
	if userInfo.Email != "" {
		headers["X-ALD-User-Email"] = userInfo.Email
	}
	if userInfo.Department != "" {
		headers["X-ALD-User-Department"] = userInfo.Department
	}
	if userInfo.Title != "" {
		headers["X-ALD-User-Title"] = userInfo.Title
	}
	if userInfo.Mobile != "" {
		headers["X-ALD-User-Mobile"] = userInfo.Mobile
	}
	if userInfo.EmployeeID != "" {
		headers["X-ALD-User-EmployeeID"] = userInfo.EmployeeID
	}
	if userInfo.DN != "" {
		headers["X-ALD-User-DN"] = userInfo.DN
	}
}

func (a *KerberosAuthorizer) verifyKerberosTicket(ctx context.Context, tokenBytes []byte) (*TicketInfo, error) {
	if a.keytab == nil {
		return nil, fmt.Errorf("keytab not loaded")
	}

	var spnegoToken spnego.SPNEGOToken
	err := spnegoToken.Unmarshal(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SPNEGO token: %w", err)
	}

	if !spnegoToken.Init {
		return nil, fmt.Errorf("expected NegTokenInit")
	}

	var krb5Token spnego.KRB5Token
	err = krb5Token.Unmarshal(spnegoToken.NegTokenInit.MechTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KRB5 token: %w", err)
	}

	if !krb5Token.IsAPReq() {
		return nil, fmt.Errorf("expected AP-REQ token")
	}

	settings := service.NewSettings(a.keytab)
	valid, creds, err := service.VerifyAPREQ(&krb5Token.APReq, settings)
	if err != nil {
		return nil, fmt.Errorf("failed to verify AP-REQ: %w", err)
	}

	if !valid {
		return nil, fmt.Errorf("ticket validation failed")
	}

	return &TicketInfo{
		Principal:      creds.CName().PrincipalNameString(),
		Realm:          creds.Domain(),
		AuthTime:       creds.AuthTime().String(),
		EndTime:        "N/A",
		Valid:          creds.Authenticated(),
		SessionKeyType: "N/A",
	}, nil
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
