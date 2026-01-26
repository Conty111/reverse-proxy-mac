package ports

import (
	"context"

	"reverse-proxy-mac/src/internal/domain/entities"
)

// AuthService defines the interface for authentication services
type AuthService interface {
	// Authenticate authenticates a user based on the provided token/credentials
	Authenticate(ctx context.Context, token string) (*entities.User, error)
	
	// ValidateToken validates if a token is valid without full authentication
	ValidateToken(ctx context.Context, token string) (bool, error)
	
	// GetAuthType returns the authentication type (kerberos, oauth2, oidc)
	GetAuthType() string
}

// KerberosService defines Kerberos-specific authentication
type KerberosService interface {
	AuthService
	
	// ValidateTicket validates a Kerberos ticket
	ValidateTicket(ctx context.Context, ticket []byte) (*entities.User, error)
}

// OAuth2Service defines OAuth2-specific authentication
type OAuth2Service interface {
	AuthService
	
	// IntrospectToken introspects an OAuth2 token
	IntrospectToken(ctx context.Context, token string) (map[string]interface{}, error)
}

// OIDCService defines OIDC-specific authentication
type OIDCService interface {
	AuthService
	
	// VerifyIDToken verifies an OIDC ID token
	VerifyIDToken(ctx context.Context, idToken string) (*entities.User, error)
}

