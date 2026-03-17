package auth

type SecurityContext interface {
	GetConfidentiality() uint8
	GetIntegrity() uint32
	GetCapabilities() uint64
	GetCategories() uint64
}
