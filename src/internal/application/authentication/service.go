package authentication

import (
	"context"
	"fmt"
	"strings"

	"reverse-proxy-mac/src/internal/domain/entities"
	"reverse-proxy-mac/src/internal/domain/ports"
)

// Service handles authentication logic
type Service struct {
	authService ports.AuthService
	ldapService ports.LDAPService
	logger      ports.Logger
}

// NewService creates a new authentication service
func NewService(authService ports.AuthService, ldapService ports.LDAPService, logger ports.Logger) *Service {
	return &Service{
		authService: authService,
		ldapService: ldapService,
		logger:      logger,
	}
}

// Authenticate authenticates a user based on the provided authorization header
func (s *Service) Authenticate(ctx context.Context, authHeader string) (*entities.User, error) {
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	// Determine auth type from header
	authType := s.determineAuthType(authHeader)
	s.logger.Debug("Authenticating request", "type", authType)

	// Authenticate using the configured service
	user, err := s.authService.Authenticate(ctx, authHeader)
	if err != nil {
		s.logger.Error("Authentication failed", "error", err, "type", authType)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	s.logger.Info("User authenticated successfully", 
		"username", user.Username, 
		"realm", user.Realm,
		"mac_label", user.MACLabel)

	return user, nil
}

// determineAuthType determines the authentication type from the header
func (s *Service) determineAuthType(authHeader string) string {
	authHeader = strings.ToLower(authHeader)
	
	if strings.HasPrefix(authHeader, "negotiate") {
		return "kerberos"
	} else if strings.HasPrefix(authHeader, "bearer") {
		return "oauth2/oidc"
	} else if strings.HasPrefix(authHeader, "basic") {
		return "basic"
	}
	
	return "unknown"
}
