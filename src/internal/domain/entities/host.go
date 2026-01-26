package entities

// Host represents a network host with MAC label
type Host struct {
	Hostname  string
	IPAddress string
	MACLabel  string
	DN        string // Distinguished Name in LDAP
	Metadata  map[string]string
}

// IsValid checks if the host has required information
func (h *Host) IsValid() bool {
	return h.Hostname != "" || h.IPAddress != ""
}
