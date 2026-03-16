package auth

const (
	HostMacAttribute = "x-ald-host-mac"
	HostCapabilitiesAttribute = "x-ald-host-caps"
	HostIntegrityLevelAttribute = "x-ald-host-mic-level"
)

var AllMacHostAttributes []string = []string{
	HostMacAttribute,
	HostCapabilitiesAttribute,
	HostIntegrityLevelAttribute,
}

type HostSecurityContext struct {
	Categories uint64
	Level uint8
	Capabilities uint64
	Integrity uint32
}

func (hsc *HostSecurityContext) GetLevel() uint8 { return hsc.Level }

func (hsc *HostSecurityContext) GetCategories() uint64 { return hsc.Categories }

func (hsc *HostSecurityContext) GetCapabilities() uint64 { return hsc.Capabilities }

func (hsc *HostSecurityContext) GetIntegrity() uint32 { return hsc.Integrity }