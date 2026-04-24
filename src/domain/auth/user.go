package auth

const (
	UserMacAttribute            = "x-ald-user-mac"
	UserIntegrityLevelAttribute = "x-ald-user-mic-level"
)

// https://www.aldpro.ru/professional/ALD_Pro_Module_13/ALD_Pro_mac_mic.html#freeipa
var AllMacUserAttributes []string = []string{
	"uid",
	UserMacAttribute,
	UserIntegrityLevelAttribute,
}

type UserHTTPSecurityContext struct {
	RequestMethod       string
	ConfidentialityMin  uint8
	CategoriesMin       uint64
	ConfidentialityMax  uint8
	CategoriesMax       uint64
	IntegrityCategories uint32
}

func (usc *UserHTTPSecurityContext) GetConfidentialityMin() uint8 { return usc.ConfidentialityMin }

func (usc *UserHTTPSecurityContext) GetCategoriesMin() uint64 { return usc.CategoriesMin }

func (usc *UserHTTPSecurityContext) GetConfidentialityMax() uint8 { return usc.ConfidentialityMax }

func (usc *UserHTTPSecurityContext) GetCategoriesMax() uint64 { return usc.CategoriesMax }

func (usc *UserHTTPSecurityContext) GetIntegrityCategories() uint32 { return usc.IntegrityCategories }
