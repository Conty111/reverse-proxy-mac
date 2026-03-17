package auth

const (
	UserMacAttribute            = "x-ald-user-mac"
	UserCapabilitiesAttribute   = "x-ald-user-caps"
	UserIntegrityLevelAttribute = "x-ald-user-mic-level"
)

var DefaultUserAttributes []string = []string{
	"dn",
	"uid",
	"cn",
	"sn",
	"memberOf",
	"uidNumber",
	"gidNumber",
	"krbPrincipalName",
}

// https://www.aldpro.ru/professional/ALD_Pro_Module_13/ALD_Pro_mac_mic.html#freeipa
var AllMacUserAttributes []string = []string{
	UserMacAttribute,
	UserCapabilitiesAttribute,
	UserIntegrityLevelAttribute,
	"x-ald-aud-mask",
	"x-ald-aud-type",
	"x-ald-user-cap",
	"xaldusermacmax",
	"xaldusermacmin",
}

type UserHTTPSecurityContext struct {
	RequestMethod string
	Categories    uint64
	Level         uint8
	Capabilities  uint64
	Integrity     uint32
}

func (usc *UserHTTPSecurityContext) GetLevel() uint8 { return usc.Level }

func (usc *UserHTTPSecurityContext) GetCategories() uint64 { return usc.Categories }

func (usc *UserHTTPSecurityContext) GetCapabilities() uint64 { return usc.Capabilities }

func (usc *UserHTTPSecurityContext) GetIntegrity() uint32 { return usc.Integrity }
