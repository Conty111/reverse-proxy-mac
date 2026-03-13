package auth

type HostSecurityContext struct {
	Categories uint64
	Level uint8
	Capabilities uint64
	Integrity uint32
}

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
