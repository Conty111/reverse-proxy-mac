package usecase

import (
	"context"
	"fmt"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

type TransportAuthorizer struct {
	logger     logger.Logger
	ldapClient ldap.LDAPClient
}

func NewTransportAuthorizer(log logger.Logger, keytabPath, servicePrincipal string, ldapClient ldap.LDAPClient) (*TransportAuthorizer, error) {
	log.Info(context.Background(), "TransportAuthorizer initialized", map[string]interface{}{
		"keytab_path":       keytabPath,
		"service_principal": servicePrincipal,
	})

	return &TransportAuthorizer{
		logger:     log,
		ldapClient: ldapClient,
	}, nil
}

func (a *TransportAuthorizer) Authorize(ctx context.Context, req *auth.AuthRequest) (*auth.AuthResponse, error) {
	// Log all provided authorization information
	a.logger.Info(ctx, "TransportAuthorizer: Authorization request received", map[string]interface{}{
		"request_id":  req.RequestID,
		"timestamp":   req.Timestamp,
		"source_ip":   req.SourceIP,
		"source_port": req.SourcePort,
		"dest_ip":     req.DestIP,
		"dest_port":   req.DestPort,
		"protocol":    req.Protocol,
		"http_method": req.HTTPMethod,
		"http_path":   req.HTTPPath,
	})

	// Log all HTTP headers
	if len(req.HTTPHeaders) > 0 {
		a.logger.Info(ctx, "TransportAuthorizer: HTTP Headers", map[string]interface{}{
			"headers": req.HTTPHeaders,
		})
	}

	// For now, just allow all requests and log the information
	return &auth.AuthResponse{
		Decision: auth.DecisionAllow,
		Reason:   fmt.Sprintf("Transport authorization: request from %s:%d to %s:%d", req.SourceIP, req.SourcePort, req.DestIP, req.DestPort),
		Headers:  map[string]string{},
	}, nil
}
