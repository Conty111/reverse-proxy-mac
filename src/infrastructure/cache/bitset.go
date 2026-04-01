// Package cache provides in-memory caching structures for MAC policy objects
// loaded from LDAP: hosts (keyed by FQDN) and URI rules (keyed by path).
package cache

import "github.com/bits-and-blooms/bitset"

// RuleID is a compact numeric identifier assigned to each URIMACRule during
// cache population. IDs start at 0 and are assigned in load order.
type RuleID = uint

// RuleSet is a bitset of RuleIDs backed by github.com/bits-and-blooms/bitset.
// The zero value is an empty set ready for use.
type RuleSet = bitset.BitSet
