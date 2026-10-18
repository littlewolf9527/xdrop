package api

import (
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

// Key/value fake supports actual trie enumeration for both copies.
type fakeTrie = cut55Trie

func newFakeTrie() *fakeTrie { return &fakeTrie{rows: map[string]uint32{}} }

// newCIDRTestHandlers builds a Handlers with only the fields that
// addCIDRRuleFromSync needs before CIDR allocation: the cidrMgr and the two
// in-memory maps. BPF map fields stay nil because the rejection test
// returns BEFORE any BPF access.
func newCIDRTestHandlers() (*Handlers, *cidr.Manager) {
	srcV4, dstV4 := newFakeTrie(), newFakeTrie()
	srcV6, dstV6 := newFakeTrie(), newFakeTrie()
	mgr := cidr.NewManager(srcV4, dstV4, srcV6, dstV6, newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie())
	return &Handlers{
		cidrMgr:          mgr,
		cidrRules:        make(map[string]StoredCIDRRule),
		cidrRuleKeyIndex: make(map[CIDRRuleKey]ruleIDSet),
	}, mgr
}
