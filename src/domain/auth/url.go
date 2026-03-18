package auth

type URLSecurityContext struct {
	Path            string
	Categories      uint64
	Confidentiality uint8
	Capabilities    uint64
	Integrity       uint32
}

const (
	URLMacAttribute = "x-ald-url-mac"

	URLCapabilitiesAttribute   = "x-ald-url-caps"
	URLIntegrityLevelAttribute = "x-ald-url-mic-level"
)

// AllMacURLAttributes contains all MAC-related attributes for URL resources
var AllMacURLAttributes []string = []string{
	URLMacAttribute,
	URLCapabilitiesAttribute,
	URLIntegrityLevelAttribute,
}

func (urlsc *URLSecurityContext) GetConfidentiality() uint8 { return urlsc.Confidentiality }

func (urlsc *URLSecurityContext) GetCategories() uint64 { return urlsc.Categories }

func (urlsc *URLSecurityContext) GetCapabilities() uint64 { return urlsc.Capabilities }

func (urlsc *URLSecurityContext) GetIntegrity() uint32 { return urlsc.Integrity }
