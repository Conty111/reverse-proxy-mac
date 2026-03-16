package auth

type URLSecurityContext struct {
	Path string
	Categories uint64
	Level uint8
	Capabilities uint64
	Integrity uint32
}

const (
	URLMacAttribute = "x-ald-url-mac"

	URLCapabilitiesAttribute = "x-ald-url-caps"
	URLIntegrityLevelAttribute = "x-ald-url-mic-level"
)

// AllMacURLAttributes contains all MAC-related attributes for URL resources
var AllMacURLAttributes []string = []string{
	URLMacAttribute,
	URLCapabilitiesAttribute,
	URLIntegrityLevelAttribute,
}