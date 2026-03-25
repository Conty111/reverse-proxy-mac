package auth

type URIMatchType string

const (
	// URIMatchExact requires the request URI path to be identical to the rule's URIPath.
	URIMatchExact URIMatchType = "exact"
	// URIMatchPrefix requires the request URI path to start with the rule's URIPath.
	// The prefix itself must end with "/" or the next character in the request path must be "/".
	URIMatchPrefix URIMatchType = "prefix"
	// URIMatchRegex treats the rule's URIPath as a regular expression (RE2 syntax).
	URIMatchRegex URIMatchType = "regex"
)

type URISecurityContext struct {
	// Path is the URI path this context applies to.
	Path                string
	ConfidentialityMin  uint8
	CategoriesMin       uint64
	ConfidentialityMax  uint8
	CategoriesMax       uint64
	IntegrityCategories uint32
}

// URIMACRule represents a URI-based MAC rule stored in LDAP as an aldURIMACRule entry.
type URIMACRule struct {
	CN      string
	URIPath string
	// MatchType controls how URIPath is matched: exact, prefix, or regex.
	// Defaults to URIMatchExact when the LDAP attribute is absent.
	MatchType URIMatchType
	// MACLabel is the mandatory access control label for this URI resource.
	MACLabel URISecurityContext
	// HostFQDNs lists the FQDNs of hosts this rule is bound to.
	HostFQDNs []string
	// HostGroups lists the host-group CNs this rule is bound to.
	HostGroups  []string
	Description string
}

const (
	URIMacAttribute         = "x-ald-uri-mac"
	URIPathAttribute        = "x-ald-uri-path"
	URIMatchTypeAttribute   = "x-ald-uri-match-type"
	URIDescriptionAttribute = "x-ald-uri-description"
	URIHostAttribute        = "x-ald-uri-memberHost"
	URIHostGroupAttribute   = "x-ald-uri-memberHostGroup"
)

// AllMacURIAttributes contains all MAC-related attributes for URI resources (aldURIContext).
var AllURIAttributes []string = []string{
	"cn",
	URIMacAttribute,
	URIPathAttribute,
	URIMatchTypeAttribute,
	URIHostAttribute,
	URIHostGroupAttribute,
	URIDescriptionAttribute,
}

// AllURIMACRuleAttributes contains all attributes for URI MAC rule entries (aldURIMACRule).
var AllURIMACAttributes []string = []string{
	"cn",
	URIMacAttribute,
	URIPathAttribute,
	URIMatchTypeAttribute,
	URIHostAttribute,
	URIHostGroupAttribute,
}

func (usc *URISecurityContext) GetConfidentialityMin() uint8 { return usc.ConfidentialityMin }

func (usc *URISecurityContext) GetCategoriesMin() uint64 { return usc.CategoriesMin }

func (usc *URISecurityContext) GetConfidentialityMax() uint8 { return usc.ConfidentialityMax }

func (usc *URISecurityContext) GetCategoriesMax() uint64 { return usc.CategoriesMax }

func (usc *URISecurityContext) GetIntegrityCategories() uint32 { return usc.IntegrityCategories }
