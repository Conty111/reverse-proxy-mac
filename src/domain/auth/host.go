package auth

const (
	HostMacAttribute                 = "x-ald-host-mac"
	HostIntegrityCategoriesAttribute = "x-ald-host-mic-level"
)

var AllMacHostAttributes []string = []string{
	HostMacAttribute,
	HostIntegrityCategoriesAttribute,
}

type HostSecurityContext struct {
	ConfidentialityMin  uint8
	CategoriesMin       uint64
	ConfidentialityMax  uint8
	CategoriesMax       uint64
	IntegrityCategories uint32
}

func (hsc *HostSecurityContext) GetConfidentialityMin() uint8 { return hsc.ConfidentialityMin }

func (hsc *HostSecurityContext) GetCategoriesMin() uint64 { return hsc.CategoriesMin }

func (hsc *HostSecurityContext) GetConfidentialityMax() uint8 { return hsc.ConfidentialityMax }

func (hsc *HostSecurityContext) GetCategoriesMax() uint64 { return hsc.CategoriesMax }

func (hsc *HostSecurityContext) GetIntegrityCategories() uint32 { return hsc.IntegrityCategories }
