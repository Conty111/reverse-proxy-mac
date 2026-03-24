package auth

// URIMatchType defines how the URI path in a MAC rule is matched against the request URI.
// Mirrors the semantics of FreeIPA URI-based HBAC.
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

// URISecurityContext holds the MAC label associated with a URI resource entry in LDAP.
// It is stored as an auxiliary objectClass (aldURIContext) attached to a host entry.
type URISecurityContext struct {
	// Path is the URI path this context applies to.
	Path            string
	Categories      uint64
	Confidentiality uint8
	Capabilities    uint64
	Integrity       uint32
}

// URIMACRule represents a URI-based MAC rule stored in LDAP as an aldURIMACRule entry.
// Unlike RBAC rules, a URI MAC rule carries a MAC label and is bound to hosts/host-groups,
// not to users or user-groups.
type URIMACRule struct {
	// CN is the unique common name of the rule entry.
	CN string
	// URIPath is the URI path pattern this rule applies to.
	// Its interpretation depends on MatchType.
	URIPath string
	// MatchType controls how URIPath is matched: exact, prefix, or regex.
	// Defaults to URIMatchExact when the LDAP attribute is absent.
	MatchType URIMatchType
	// MACLabel is the mandatory access control label for this URI resource.
	MACLabel URISecurityContext
	// HostFQDNs lists the FQDNs of hosts this rule is bound to.
	HostFQDNs []string
	// HostGroups lists the host-group CNs this rule is bound to.
	HostGroups []string
	// Description is an optional human-readable description.
	Description string
}

const (
	// URIMacAttribute is the composite MAC label: confidentiality:categories:capabilities:integrity
	URIMacAttribute = "x-ald-uri-mac"
	// URIMatchTypeAttribute stores the match type: "exact" (default), "prefix", or "regex".
	URIMatchTypeAttribute = "x-ald-uri-match-type"
	// URIDescriptionAttribute is an optional human-readable description of the URI resource.
	URIDescriptionAttribute = "x-ald-uri-description"
	// URIPathAttribute stores the URI path (exact string, prefix, or regex pattern).
	URIPathAttribute = "x-ald-uri-path"
	// URIHostAttribute lists the host FQDNs this MAC rule is bound to (multi-value).
	URIHostAttribute = "x-ald-uri-host"
	// URIHostGroupAttribute lists the host-group CNs this MAC rule is bound to (multi-value).
	URIHostGroupAttribute = "x-ald-uri-hostgroup"
)

// AllMacURIAttributes contains all MAC-related attributes for URI resources (aldURIContext).
var AllMacURIAttributes []string = []string{
	URIMacAttribute,
	URIMatchTypeAttribute,
	URIDescriptionAttribute,
}

// AllURIMACRuleAttributes contains all attributes for URI MAC rule entries (aldURIMACRule).
var AllURIMACRuleAttributes []string = []string{
	"cn",
	URIMacAttribute,
	URIPathAttribute,
	URIMatchTypeAttribute,
	URIHostAttribute,
	URIHostGroupAttribute,
	URIDescriptionAttribute,
}

func (usc *URISecurityContext) GetConfidentiality() uint8 { return usc.Confidentiality }

func (usc *URISecurityContext) GetCategories() uint64 { return usc.Categories }

func (usc *URISecurityContext) GetCapabilities() uint64 { return usc.Capabilities }

func (usc *URISecurityContext) GetIntegrity() uint32 { return usc.Integrity }
