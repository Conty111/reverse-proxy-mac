package auth

type SecurityContext interface {
	GetLevel() uint8
	GetIntegrity() uint32
	GetCapabilities() uint64
	GetCategories() uint64
}
