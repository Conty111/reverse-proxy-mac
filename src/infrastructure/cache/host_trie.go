package cache

import (
	"strings"

	"github.com/bits-and-blooms/bitset"
	"reverse-proxy-mac/src/domain/auth"
)

// CachedHost holds the security context of a host and the set of URI rule IDs
// that are bound to it (via x-ald-uri-service-ref in LDAP).
type CachedHost struct {
	SecurityContext auth.HostSecurityContext
	// RuleIDs is the set of URIMACRule IDs associated with this host.
	RuleIDs *bitset.BitSet
}

// hostTrieNode is a node in the FQDN trie.
// FQDNs are stored label-by-label in reverse order so that the trie root
// corresponds to the TLD and lookups naturally share common suffixes.
// E.g. "api.example.com" is stored as ["com", "example", "api"].
type hostTrieNode struct {
	host     *CachedHost
	children map[string]*hostTrieNode
}

func newHostTrieNode() *hostTrieNode {
	return &hostTrieNode{children: make(map[string]*hostTrieNode)}
}

// HostTrie is a trie over reversed FQDN labels for O(labels) host lookup.
// It is built once during cache load and then read-only during request handling.
type HostTrie struct {
	root *hostTrieNode
}

// NewHostTrie returns an empty HostTrie.
func NewHostTrie() *HostTrie {
	return &HostTrie{root: newHostTrieNode()}
}

// reversedLabels splits an FQDN into labels and reverses them.
// "api.example.com" -> ["com", "example", "api"]
func reversedLabels(fqdn string) []string {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	parts := strings.Split(fqdn, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

// Add inserts or replaces the CachedHost entry for the given FQDN.
func (t *HostTrie) Add(fqdn string, host *CachedHost) {
	labels := reversedLabels(fqdn)
	node := t.root
	for _, label := range labels {
		child, ok := node.children[label]
		if !ok {
			child = newHostTrieNode()
			node.children[label] = child
		}
		node = child
	}
	node.host = host
}

// Lookup returns the CachedHost for the given FQDN, or nil if not found.
func (t *HostTrie) Lookup(fqdn string) *CachedHost {
	labels := reversedLabels(fqdn)
	node := t.root
	for _, label := range labels {
		child, ok := node.children[label]
		if !ok {
			return nil
		}
		node = child
	}
	return node.host
}
