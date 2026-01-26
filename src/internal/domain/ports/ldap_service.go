package ports

import (
	"context"

	"reverse-proxy-mac/src/internal/domain/entities"
)

// LDAPService defines the interface for LDAP operations
type LDAPService interface {
	// GetUserMACLabel retrieves the MAC label for a user
	GetUserMACLabel(ctx context.Context, username string) (string, error)
	
	// GetHostByIP retrieves host information by IP address
	GetHostByIP(ctx context.Context, ipAddress string) (*entities.Host, error)
	
	// GetHostByName retrieves host information by hostname
	GetHostByName(ctx context.Context, hostname string) (*entities.Host, error)
	
	// GetUserGroups retrieves groups for a user
	GetUserGroups(ctx context.Context, username string) ([]string, error)
	
	// Close closes the LDAP connection
	Close() error
}
