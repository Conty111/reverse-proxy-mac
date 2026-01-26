package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"reverse-proxy-mac/src/config"
	"reverse-proxy-mac/src/internal/domain/entities"
	"reverse-proxy-mac/src/internal/domain/ports"
)

type ldapService struct {
	config *config.LDAPConfig
	conn   *ldap.Conn
	logger ports.Logger
}

// NewLDAPService creates a new LDAP service
func NewLDAPService(cfg *config.LDAPConfig, logger ports.Logger) (ports.LDAPService, error) {
	service := &ldapService{
		config: cfg,
		logger: logger,
	}

	if err := service.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}

	return service, nil
}

func (s *ldapService) connect() error {
	address := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	var conn *ldap.Conn
	var err error

	if s.config.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: s.config.InsecureSkipVerify,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return fmt.Errorf("failed to dial LDAP server: %w", err)
	}

	// Bind with credentials
	if s.config.BindDN != "" {
		err = conn.Bind(s.config.BindDN, s.config.BindPassword)
		if err != nil {
			conn.Close()
			return fmt.Errorf("failed to bind to LDAP: %w", err)
		}
	}

	s.conn = conn
	s.logger.Info("Connected to LDAP server", "host", s.config.Host)
	return nil
}

func (s *ldapService) GetUserMACLabel(ctx context.Context, username string) (string, error) {
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return "", err
		}
	}

	searchFilter := fmt.Sprintf(s.config.UserSearchFilter, ldap.EscapeFilter(username))
	searchRequest := ldap.NewSearchRequest(
		s.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		s.config.Timeout,
		false,
		searchFilter,
		[]string{s.config.MACLabelAttribute, "memberOf"},
		nil,
	)

	result, err := s.conn.Search(searchRequest)
	if err != nil {
		s.logger.Error("LDAP search failed", "error", err, "username", username)
		return "", fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("user not found: %s", username)
	}

	entry := result.Entries[0]
	macLabel := entry.GetAttributeValue(s.config.MACLabelAttribute)

	s.logger.Debug("Retrieved MAC label for user", "username", username, "label", macLabel)
	return macLabel, nil
}

func (s *ldapService) GetHostByIP(ctx context.Context, ipAddress string) (*entities.Host, error) {
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return nil, err
		}
	}

	// Try to resolve hostname from IP
	names, err := net.LookupAddr(ipAddress)
	var hostname string
	if err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	// Search by IP or hostname
	var searchFilter string
	if hostname != "" {
		searchFilter = fmt.Sprintf(s.config.HostSearchFilter, 
			ldap.EscapeFilter(hostname), 
			ldap.EscapeFilter(hostname))
	} else {
		searchFilter = fmt.Sprintf("(|(ipHostNumber=%s)(networkAddress=%s))", 
			ldap.EscapeFilter(ipAddress), 
			ldap.EscapeFilter(ipAddress))
	}

	searchRequest := ldap.NewSearchRequest(
		s.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		s.config.Timeout,
		false,
		searchFilter,
		[]string{"cn", "dNSHostName", s.config.MACLabelAttribute, "distinguishedName"},
		nil,
	)

	result, err := s.conn.Search(searchRequest)
	if err != nil {
		s.logger.Error("LDAP host search failed", "error", err, "ip", ipAddress)
		return nil, fmt.Errorf("LDAP host search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		s.logger.Warn("Host not found in LDAP", "ip", ipAddress)
		return &entities.Host{
			IPAddress: ipAddress,
			Hostname:  hostname,
		}, nil
	}

	entry := result.Entries[0]
	host := &entities.Host{
		Hostname:  entry.GetAttributeValue("dNSHostName"),
		IPAddress: ipAddress,
		MACLabel:  entry.GetAttributeValue(s.config.MACLabelAttribute),
		DN:        entry.GetAttributeValue("distinguishedName"),
		Metadata:  make(map[string]string),
	}

	if host.Hostname == "" {
		host.Hostname = entry.GetAttributeValue("cn")
	}

	s.logger.Info("Retrieved host information", "ip", ipAddress, "hostname", host.Hostname, "label", host.MACLabel)
	return host, nil
}

func (s *ldapService) GetHostByName(ctx context.Context, hostname string) (*entities.Host, error) {
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return nil, err
		}
	}

	searchFilter := fmt.Sprintf(s.config.HostSearchFilter, 
		ldap.EscapeFilter(hostname), 
		ldap.EscapeFilter(hostname))

	searchRequest := ldap.NewSearchRequest(
		s.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		s.config.Timeout,
		false,
		searchFilter,
		[]string{"cn", "dNSHostName", s.config.MACLabelAttribute, "distinguishedName", "ipHostNumber"},
		nil,
	)

	result, err := s.conn.Search(searchRequest)
	if err != nil {
		s.logger.Error("LDAP host search failed", "error", err, "hostname", hostname)
		return nil, fmt.Errorf("LDAP host search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("host not found: %s", hostname)
	}

	entry := result.Entries[0]
	host := &entities.Host{
		Hostname:  entry.GetAttributeValue("dNSHostName"),
		IPAddress: entry.GetAttributeValue("ipHostNumber"),
		MACLabel:  entry.GetAttributeValue(s.config.MACLabelAttribute),
		DN:        entry.GetAttributeValue("distinguishedName"),
		Metadata:  make(map[string]string),
	}

	if host.Hostname == "" {
		host.Hostname = entry.GetAttributeValue("cn")
	}

	s.logger.Debug("Retrieved host information", "hostname", hostname, "label", host.MACLabel)
	return host, nil
}

func (s *ldapService) GetUserGroups(ctx context.Context, username string) ([]string, error) {
	if s.conn == nil {
		if err := s.connect(); err != nil {
			return nil, err
		}
	}

	searchFilter := fmt.Sprintf(s.config.UserSearchFilter, ldap.EscapeFilter(username))
	searchRequest := ldap.NewSearchRequest(
		s.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		s.config.Timeout,
		false,
		searchFilter,
		[]string{"memberOf"},
		nil,
	)

	result, err := s.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	entry := result.Entries[0]
	memberOf := entry.GetAttributeValues("memberOf")

	// Extract group names from DNs
	groups := make([]string, 0, len(memberOf))
	for _, dn := range memberOf {
		// Extract CN from DN (e.g., "CN=GroupName,OU=Groups,DC=example,DC=com")
		parts := strings.Split(dn, ",")
		if len(parts) > 0 {
			cnPart := parts[0]
			if strings.HasPrefix(cnPart, "CN=") {
				groupName := strings.TrimPrefix(cnPart, "CN=")
				groups = append(groups, groupName)
			}
		}
	}

	return groups, nil
}

func (s *ldapService) Close() error {
	if s.conn != nil {
		s.conn.Close()
		s.logger.Info("Closed LDAP connection")
	}
	return nil
}
