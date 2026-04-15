package cache

import (
	"strings"

	"github.com/bits-and-blooms/bitset"
)

// uriTrieNode is a node in the URI path prefix trie.
// The trie is keyed by individual path segments (split on '/').
// Each node accumulates the union of all prefix-rule IDs that pass through it,
// and optionally holds an exact-rule set for rules whose path ends exactly here.
type uriTrieNode struct {
	// prefixRules holds IDs of URIMatchPrefix rules whose path ends at this node.
	// When descending the trie we OR all prefixRules along the path.
	prefixRules *bitset.BitSet

	// exactRules holds IDs of URIMatchExact rules whose path ends at this node.
	// Only checked when the request path is fully consumed.
	exactRules *bitset.BitSet

	children map[string]*uriTrieNode
}

func newURITrieNode() *uriTrieNode {
	return &uriTrieNode{children: make(map[string]*uriTrieNode)}
}

// URITrie is a trie over URI path segments for exact and prefix URI rules.
// It is built once during cache load and then read-only during request handling.
type URITrie struct {
	root *uriTrieNode
}

// NewURITrie returns an empty URITrie.
func NewURITrie() *URITrie {
	return &URITrie{root: newURITrieNode()}
}

// splitPath splits a URI path into non-empty segments, preserving a leading
// empty string for the root "/" so that "/foo" → ["", "foo"].
func splitPath(path string) []string {
	// strings.Split("/foo/bar", "/") → ["", "foo", "bar"]
	// strings.Split("/", "/")       → ["", ""]
	// We keep the leading "" to represent the root segment.
	parts := strings.Split(path, "/")
	return parts
}

// AddPrefix inserts a URIMatchPrefix rule into the trie.
// The rule's BitSet bit is set on the node where the path ends, so that any
// request path that passes through (or ends at) that node will pick it up.
func (t *URITrie) AddPrefix(path string, id RuleID) {
	node := t.walk(path, true)
	if node.prefixRules == nil {
		node.prefixRules = bitset.New(id + 1)
	}
	node.prefixRules.Set(id)
}

// AddExact inserts a URIMatchExact rule into the trie.
func (t *URITrie) AddExact(path string, id RuleID) {
	node := t.walk(path, true)
	if node.exactRules == nil {
		node.exactRules = bitset.New(id + 1)
	}
	node.exactRules.Set(id)
}

// Lookup returns the union of all prefix rules whose path is a prefix of
// requestPath, ORed with the exact rules whose path equals requestPath.
//
// The returned BitSet may be nil if no rules matched.
func (t *URITrie) Lookup(requestPath string) *bitset.BitSet {
	segments := splitPath(requestPath)
	node := t.root
	var result *bitset.BitSet

	merge := func(bs *bitset.BitSet) {
		if bs == nil {
			return
		}
		if result == nil {
			result = bs.Clone()
		} else {
			result.InPlaceUnion(bs)
		}
	}

	for i, seg := range segments {
		// Collect prefix rules at this node (they match any request that
		// passes through here, i.e. the rule path is a prefix of requestPath).
		merge(node.prefixRules)

		// If we have consumed all segments, also collect exact rules.
		if i == len(segments)-1 {
			merge(node.exactRules)
		}

		child, ok := node.children[seg]
		if !ok {
			break
		}
		node = child
	}

	return result
}

// walk descends (and optionally creates) nodes for each segment of path.
func (t *URITrie) walk(path string, create bool) *uriTrieNode {
	segments := splitPath(path)
	node := t.root
	for _, seg := range segments {
		child, ok := node.children[seg]
		if !ok {
			if !create {
				return nil
			}
			child = newURITrieNode()
			node.children[seg] = child
		}
		node = child
	}
	return node
}
