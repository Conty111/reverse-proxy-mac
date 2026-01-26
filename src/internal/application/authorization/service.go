package authorization

import (
	"context"

	"reverse-proxy-mac/src/config"
	"reverse-proxy-mac/src/internal/domain/entities"
	"reverse-proxy-mac/src/internal/domain/ports"
)

// Service handles authorization and MAC enforcement
type Service struct {
	config      *config.MACConfig
	ldapService ports.LDAPService
	logger      ports.Logger
}

// NewService creates a new authorization service
func NewService(config *config.MACConfig, ldapService ports.LDAPService, logger ports.Logger) *Service {
	return &Service{
		config:      config,
		ldapService: ldapService,
		logger:      logger,
	}
}

// AuthorizeUser checks if a user is authorized based on MAC policy
func (s *Service) AuthorizeUser(ctx context.Context, user *entities.User) (bool, error) {
	if !s.config.Enabled {
		s.logger.Debug("MAC enforcement disabled, allowing request")
		return true, nil
	}

	// Check if user has a MAC label
	if user.MACLabel == -1 {
		s.logger.Warn("User has no MAC label", "username", user.Username)
		
		user.MACLabel = s.config.DefaultLabel
		s.logger.Info("Assigned default MAC label", "username", user.Username, "label", s.config.DefaultLabel)
	}

	// Check if label is in allowed list
	// if len(s.config.AllowedLabels) > 0 {
	// 	allowed := false
	// 	for _, allowedLabel := range s.config.AllowedLabels {
	// 		if user.MACLabel == allowedLabel {
	// 			allowed = true
	// 			break
	// 		}
	// 	}
		
	// 	if !allowed {
	// 		s.logger.Warn("User MAC label not in allowed list", 
	// 			"username", user.Username, 
	// 			"label", user.MACLabel)
	// 		return false, fmt.Errorf("MAC label not allowed: %s", user.MACLabel)
	// 	}
	// }

	s.logger.Info("User authorized", "username", user.Username, "mac_label", user.MACLabel)
	return true, nil
}

// GetHostInfo retrieves host information for L4 traffic
func (s *Service) GetHostInfo(ctx context.Context, ipAddress string) (*entities.Host, error) {
	host, err := s.ldapService.GetHostByIP(ctx, ipAddress)
	if err != nil {
		s.logger.Error("Failed to get host info", "ip", ipAddress, "error", err)
		return nil, err
	}

	s.logger.Info("Retrieved host information", 
		"ip", ipAddress, 
		"hostname", host.Hostname, 
		"mac_label", host.MACLabel)

	return host, nil
}

// LogL4Traffic logs L4 traffic information
func (s *Service) LogL4Traffic(ctx context.Context, srcIP, dstIP string, srcPort, dstPort int) {
	s.logger.Info("L4 traffic detected",
		"src_ip", srcIP,
		"dst_ip", dstIP,
		"src_port", srcPort,
		"dst_port", dstPort)

	// Get source host info
	if srcHost, err := s.ldapService.GetHostByIP(ctx, srcIP); err == nil {
		s.logger.Info("Source host info",
			"ip", srcIP,
			"hostname", srcHost.Hostname,
			"mac_label", srcHost.MACLabel)
	}

	// Get destination host info
	if dstHost, err := s.ldapService.GetHostByIP(ctx, dstIP); err == nil {
		s.logger.Info("Destination host info",
			"ip", dstIP,
			"hostname", dstHost.Hostname,
			"mac_label", dstHost.MACLabel)
	}
}
