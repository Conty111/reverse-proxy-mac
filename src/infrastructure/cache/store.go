package cache

import (
	"context"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/bits-and-blooms/bitset"

	"reverse-proxy-mac/src/domain/auth"
	"reverse-proxy-mac/src/domain/logger"
	ldapclient "reverse-proxy-mac/src/infrastructure/ldap"
)

// Store is the top-level in-memory cache for MAC policy objects.
// It holds an atomically-swapped *snapshot so that readers never block writers
// and writers never block readers. A background goroutine refreshes the
// snapshot every TTL seconds.
type Store struct {
	// snap is an *snapshot stored as unsafe.Pointer for atomic swap.
	snap unsafe.Pointer

	ldapClient *ldapclient.Client
	log        logger.Logger
	ttl        time.Duration
}

// NewStore creates a Store and performs the first synchronous load from LDAP.
// If the initial load fails the error is returned and the Store is not usable.
func NewStore(ctx context.Context, cl *ldapclient.Client, log logger.Logger, ttl time.Duration) (*Store, error) {
	s := &Store{
		ldapClient: cl,
		log:        log,
		ttl:        ttl,
	}

	snap, err := loadSnapshot(ctx, cl, log)
	if err != nil {
		return nil, err
	}
	atomic.StorePointer(&s.snap, unsafe.Pointer(snap))

	return s, nil
}

// Start launches the background refresh goroutine. It stops when ctx is
// cancelled. Call this after NewStore.
func (s *Store) Start(ctx context.Context) {
	go s.refreshLoop(ctx)
}

func (s *Store) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(s.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info(ctx, "cache: refresh loop stopped", nil)
			return
		case <-ticker.C:
			s.log.Info(ctx, "cache: refreshing from LDAP", map[string]interface{}{
				"ttl": s.ttl.String(),
			})
			snap, err := loadSnapshot(ctx, s.ldapClient, s.log)
			if err != nil {
				s.log.Error(ctx, "cache: refresh failed, keeping stale data", map[string]interface{}{
					"error": err.Error(),
				})
				continue
			}
			atomic.StorePointer(&s.snap, unsafe.Pointer(snap))
			s.log.Info(ctx, "cache: refresh complete", map[string]interface{}{
				"uri_rules": len(snap.allRules),
			})
		}
	}
}

// ForceRefresh triggers an immediate reload of the cache from LDAP.
// It blocks until the reload is complete and returns an error if the load fails.
// On failure the existing (stale) snapshot is preserved.
func (s *Store) ForceRefresh(ctx context.Context) error {
	s.log.Info(ctx, "cache: force refresh requested", nil)

	snap, err := loadSnapshot(ctx, s.ldapClient, s.log)
	if err != nil {
		s.log.Error(ctx, "cache: force refresh failed, keeping stale data", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	atomic.StorePointer(&s.snap, unsafe.Pointer(snap))
	s.log.Info(ctx, "cache: force refresh complete", map[string]interface{}{
		"uri_rules": len(snap.allRules),
		"users":     len(snap.users),
	})
	return nil
}

// current returns the current snapshot. Never nil after NewStore succeeds.
func (s *Store) current() *snapshot {
	return (*snapshot)(atomic.LoadPointer(&s.snap))
}

// LookupHost returns the CachedHost for the given FQDN, or nil if not found.
func (s *Store) LookupHost(fqdn string) *CachedHost {
	return s.current().hosts.Lookup(fqdn)
}

// LookupUser returns the CachedUser for the given uid (case-insensitive), or nil if not found.
func (s *Store) LookupUser(uid string) *CachedUser {
	return s.current().users[strings.ToLower(uid)]
}

// MatchingURIRules implements the algorithm from the spec:
//
//  1. Look up the host to get HostRuleSet (the set of rule IDs bound to it).
//  2. Walk the URI trie to collect PrefixRuleSet (prefix + exact matches).
//  3. Walk the regex list, testing only rules whose ID is in HostRuleSet.
//  4. MatchedUriRuleSet = PrefixRuleSet OR RegexRuleSet.
//  5. ActiveRuleSet = HostRuleSet AND MatchedUriRuleSet.
//  6. Return the URISecurityContext for each rule in ActiveRuleSet.
//
// The second return value is false only when the host is not found in the
// cache at all (caller may decide to fall back to LDAP or deny).
func (s *Store) MatchingURIRules(fqdn, requestPath string) ([]*auth.URISecurityContext, bool) {
	snap := s.current()

	host := snap.hosts.Lookup(fqdn)
	if host == nil {
		return nil, false
	}

	hostRuleSet := host.RuleIDs // *bitset.BitSet

	// Step 2: trie lookup (prefix + exact).
	trieResult := snap.uriTrie.Lookup(requestPath) // may be nil

	// Step 3: regex rules — only test those in HostRuleSet.
	var regexResult *bitset.BitSet
	for _, rule := range snap.regexRules {
		if !hostRuleSet.Test(rule.ID) {
			continue
		}
		if rule.CompiledRegex.MatchString(requestPath) {
			if regexResult == nil {
				regexResult = bitset.New(uint(len(snap.allRules)))
			}
			regexResult.Set(rule.ID)
		}
	}

	// Step 4: MatchedUriRuleSet = trieResult OR regexResult.
	var matchedURI *bitset.BitSet
	switch {
	case trieResult != nil && regexResult != nil:
		u := trieResult.Clone()
		u.InPlaceUnion(regexResult)
		matchedURI = u
	case trieResult != nil:
		matchedURI = trieResult
	case regexResult != nil:
		matchedURI = regexResult
	default:
		// No URI rules matched at all.
		return nil, true
	}

	// Step 5: ActiveRuleSet = HostRuleSet AND MatchedUriRuleSet.
	active := hostRuleSet.Clone()
	active.InPlaceIntersection(matchedURI)

	if !active.Any() {
		return nil, true
	}

	// Step 6: collect security contexts using AsSlice for iteration.
	ids := active.AsSlice(nil)
	result := make([]*auth.URISecurityContext, 0, len(ids))
	for _, id := range ids {
		if int(id) < len(snap.allRules) {
			ctx := snap.allRules[id].MACLabel
			result = append(result, &ctx)
		}
	}

	return result, true
}
