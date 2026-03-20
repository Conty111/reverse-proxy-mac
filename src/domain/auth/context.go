package auth

// SecurityContext defines the interface for security context objects
// used in Mandatory Access Control (MAC) decisions.
// It provides access to the four key security attributes:
// confidentiality level, integrity level, capabilities, and categories.
type SecurityContext interface {
	// GetConfidentiality returns the confidentiality level (0-255).
	GetConfidentiality() uint8
	// GetIntegrity returns the integrity level as a 32-bit value.
	GetIntegrity() uint32
	// GetCapabilities returns the capabilities bitmask.
	GetCapabilities() uint64
	// GetCategories returns the categories bitmask.
	GetCategories() uint64
}
