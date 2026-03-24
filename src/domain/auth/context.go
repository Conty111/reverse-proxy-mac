package auth

// SecurityContext defines the interface for security context objects
// used in Mandatory Access Control (MAC) decisions.
// It provides access to the key security attributes:
// confidentiality range (min/max), categories range (min/max), and integrity categories.
type SecurityContext interface {
	// GetConfidentialityMin returns the minimum confidentiality level (0-255).
	GetConfidentialityMin() uint8
	// GetCategoriesMin returns the minimum categories bitmask.
	GetCategoriesMin() uint64
	// GetConfidentialityMax returns the maximum confidentiality level (0-255).
	GetConfidentialityMax() uint8
	// GetCategoriesMax returns the maximum categories bitmask.
	GetCategoriesMax() uint64
	// GetIntegrityCategories returns the integrity categories bitmask.
	GetIntegrityCategories() uint32
}
