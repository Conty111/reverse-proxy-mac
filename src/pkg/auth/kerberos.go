package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"

	"reverse-proxy-mac/src/config"
	"reverse-proxy-mac/src/internal/domain/entities"
	"reverse-proxy-mac/src/internal/domain/ports"
)

type kerberosService struct {
	config     *config.KerberosConfig
	keytab     *keytab.Keytab
	logger     ports.Logger
	ldapSvc    ports.LDAPService
}

// NewKerberosService creates a new Kerberos authentication service
func NewKerberosService(cfg *config.KerberosConfig, ldapSvc ports.LDAPService, logger ports.Logger) (ports.KerberosService, error) {
	kt, err := keytab.Load(cfg.KeytabPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load keytab: %w", err)
	}

	return &kerberosService{
		config:  cfg,
		keytab:  kt,
		logger:  logger,
		ldapSvc: ldapSvc,
	}, nil
}

func (s *kerberosService) Authenticate(ctx context.Context, token string) (*entities.User, error) {
	// Extract token from Authorization header
	token = strings.TrimPrefix(token, "Negotiate ")
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)

	ticketData, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	return s.ValidateTicket(ctx, ticketData)
}

func (s *kerberosService) ValidateTicket(ctx context.Context, ticket []byte) (*entities.User, error) {
	// TODO: Implement full Kerberos SPNEGO validation
	// This is a simplified implementation that needs to be completed
	// with proper gokrb5 SPNEGO validation
	
	s.logger.Warn("Kerberos validation not fully implemented - using stub")
	
	// For now, extract username from context or use placeholder
	// In production, this should:
	// 1. Parse SPNEGO token
	// 2. Verify AP-REQ with keytab
	// 3. Extract principal name and realm from ticket
	
	username := "stub-user" // TODO: Extract from validated ticket
	realm := s.config.Realm

	s.logger.Info("Kerberos ticket validation (stub)", "username", username, "realm", realm)

	// Get MAC label from LDAP
	macLabel, err := s.ldapSvc.GetUserMACLabel(ctx, username)
	if err != nil {
		s.logger.Warn("Failed to get MAC label for user", "username", username, "error", err)
		macLabel = "" // Continue without MAC label
	}

	// Get user groups
	groups, err := s.ldapSvc.GetUserGroups(ctx, username)
	if err != nil {
		s.logger.Warn("Failed to get groups for user", "username", username, "error", err)
		groups = []string{}
	}

	num, err := strconv.ParseInt(macLabel, 16, 10)
	if err != nil {
		s.logger.Error("Failed to convert label into a integer", "label", macLabel, "error", err)
	}

	user := &entities.User{
		Username:  username,
		Realm:     realm,
		MACLabel:  int(num),
		Groups:    groups,
		ExpiresAt: time.Now().Add(8 * time.Hour),
		Metadata:  make(map[string]string),
	}

	return user, nil
}

func (s *kerberosService) ValidateToken(ctx context.Context, token string) (bool, error) {
	_, err := s.Authenticate(ctx, token)
	return err == nil, err
}

func (s *kerberosService) GetAuthType() string {
	return "kerberos"
}
