package usecase

import (
	"context"
	"fmt"
	"net"
	"strings"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
	"reverse-proxy-mac/src/infrastructure/ldap"
)

type TransportAuthorizer struct {
	logger     logger.Logger
	ldapClient *ldap.Client
}

func NewTransportAuthorizer(log logger.Logger, ldapClient *ldap.Client) (*TransportAuthorizer, error) {
	return &TransportAuthorizer{
		logger:     log,
		ldapClient: ldapClient,
	}, nil
}

func (a *TransportAuthorizer) Authorize(ctx context.Context, req *auth.AuthRequest) (*auth.AuthResponse, error) {
	a.logger.Info(ctx, "Transport authorization request received", map[string]interface{}{
		"request_id":  req.RequestID,
		"timestamp":   req.Timestamp,
		"source_ip":   req.SourceIP,
		"source_port": req.SourcePort,
		"dest_ip":     req.DestIP,
		"dest_port":   req.DestPort,
		"protocol":    req.Protocol,
	})

	// Resolve source IP to FQDN
	sourceFQDN, err := a.resolveIPToFQDN(ctx, req.SourceIP)
	if err != nil {
		a.logger.Warn(ctx, "Failed to resolve source IP to FQDN", map[string]interface{}{
			"source_ip": req.SourceIP,
			"error":     err.Error(),
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        fmt.Sprintf("Failed to resolve source IP %s to FQDN: %s", req.SourceIP, err.Error()),
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - Source host resolution failed",
		}, nil
	}

	// Resolve destination IP to FQDN
	destFQDN, err := a.resolveIPToFQDN(ctx, req.DestIP)
	if err != nil {
		a.logger.Warn(ctx, "Failed to resolve destination IP to FQDN", map[string]interface{}{
			"dest_ip": req.DestIP,
			"error":   err.Error(),
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        fmt.Sprintf("Failed to resolve destination IP %s to FQDN: %s", req.DestIP, err.Error()),
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - Destination host resolution failed",
		}, nil
	}

	a.logger.Info(ctx, "Resolved IPs to FQDNs", map[string]interface{}{
		"source_ip":   req.SourceIP,
		"source_fqdn": sourceFQDN,
		"dest_ip":     req.DestIP,
		"dest_fqdn":   destFQDN,
	})

	// Get source host security context
	sourceSecCtx, err := GetHostSecurityContext(ctx, a.ldapClient, sourceFQDN)
	if err != nil {
		a.logger.Error(ctx, "Failed to get source host security context", map[string]interface{}{
			"fqdn":  sourceFQDN,
			"error": err.Error(),
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        fmt.Sprintf("Failed to retrieve source host security context: %s", err.Error()),
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - MAC context unavailable",
		}, nil
	}

	a.logger.Debug(ctx, "Source host security context retrieved", map[string]interface{}{
		"fqdn":           sourceFQDN,
		"conf_min":       sourceSecCtx.ConfidentialityMin,
		"cats_min":       fmt.Sprintf("0x%x", sourceSecCtx.CategoriesMin),
		"conf_max":       sourceSecCtx.ConfidentialityMax,
		"cats_max":       fmt.Sprintf("0x%x", sourceSecCtx.CategoriesMax),
		"integrity_cats": fmt.Sprintf("0x%x", sourceSecCtx.IntegrityCategories),
	})

	// Get destination host security context
	destSecCtx, err := GetHostSecurityContext(ctx, a.ldapClient, destFQDN)
	if err != nil {
		a.logger.Error(ctx, "Failed to get destination host security context", map[string]interface{}{
			"fqdn":  destFQDN,
			"error": err.Error(),
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        fmt.Sprintf("Failed to retrieve destination host security context: %s", err.Error()),
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - MAC context unavailable",
		}, nil
	}

	a.logger.Debug(ctx, "Destination host security context retrieved", map[string]interface{}{
		"fqdn":           destFQDN,
		"conf_min":       destSecCtx.ConfidentialityMin,
		"cats_min":       fmt.Sprintf("0x%x", destSecCtx.CategoriesMin),
		"conf_max":       destSecCtx.ConfidentialityMax,
		"cats_max":       fmt.Sprintf("0x%x", destSecCtx.CategoriesMax),
		"integrity_cats": fmt.Sprintf("0x%x", destSecCtx.IntegrityCategories),
	})

	// Perform MAC authorization check (host-to-host)
	// For transport layer, we treat all connections as read operations
	allowed, reason := checkMACAccess(sourceSecCtx, destSecCtx, false)
	if !allowed {
		a.logger.Warn(ctx, "MAC authorization denied", map[string]interface{}{
			"source_fqdn": sourceFQDN,
			"dest_fqdn":   destFQDN,
			"reason":      reason,
		})
		return &auth.AuthResponse{
			Decision:      auth.DecisionDeny,
			Reason:        reason,
			DeniedStatus:  403,
			DeniedMessage: "Forbidden - MAC policy violation",
		}, nil
	}

	a.logger.Info(ctx, "MAC authorization granted", map[string]interface{}{
		"source_fqdn": sourceFQDN,
		"dest_fqdn":   destFQDN,
		"reason":      reason,
	})

	return &auth.AuthResponse{
		Decision: auth.DecisionAllow,
		Reason:   fmt.Sprintf("Transport authorization successful from %s to %s", sourceFQDN, destFQDN),
		Headers:  map[string]string{},
	}, nil
}

// resolveIPToFQDN performs reverse DNS lookup to resolve IP address to FQDN.
func (a *TransportAuthorizer) resolveIPToFQDN(_ context.Context, ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", fmt.Errorf("reverse DNS lookup failed for %s: %w", ip, err)
	}

	if len(names) == 0 {
		return "", fmt.Errorf("no FQDN found for IP %s", ip)
	}

	// Return the first FQDN, removing trailing dot if present
	return strings.TrimSuffix(names[0], "."), nil
}
