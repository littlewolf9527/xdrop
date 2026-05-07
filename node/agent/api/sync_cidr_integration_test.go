//go:build linux && integration

// sync_cidr_integration_test.go — BL CIDR double-buffer flip integration tests.
//
// Requires CAP_BPF. Run via:
//
//	go test -tags=integration -race ./node/agent/api/... -run TestBL_CIDR -v
//
// Coverage:
//
//	T-BL-CIDR-1 — DoAtomicSync with CIDR rules flips cidrBlacklist/cidrBlacklistB
//	              and sets ConfigCIDRBitmap + ConfigCIDRRuleCount correctly.
//	T-BL-CIDR-2 — Consecutive syncs double-flip selector back to slot 0.
//	T-BL-CIDR-3 — Mixed exact + CIDR rules: both map pairs flip atomically in one sync.
package api

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

// newBLHashMap creates a BPF hash map for blacklist / blacklistB.
// KeySize=40 (RuleKey), ValueSize=32 (RuleValue).
func newBLHashMap(t *testing.T, name string) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    40, // sizeof(RuleKey)
		ValueSize:  32, // sizeof(RuleValue)
		MaxEntries: 256,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap %s (need CAP_BPF): %v", name, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// newCIDRHashMap creates a BPF hash map for cidrBlacklist / cidrBlacklistB.
// KeySize=16 (CIDRRuleKey), ValueSize=32 (RuleValue).
func newCIDRHashMap(t *testing.T, name string) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    16, // sizeof(CIDRRuleKey)
		ValueSize:  32, // sizeof(RuleValue)
		MaxEntries: 256,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap %s (need CAP_BPF): %v", name, err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// newBLCIDRTestHandlers builds a Handlers with real BPF maps for BL + CIDR
// double-buffer tests. The cidrMgr uses fake trie writers so no real LPM trie
// BPF maps are needed — ID allocation and trie writes are captured in-memory.
func newBLCIDRTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	bl    := newBLHashMap(t, "blcdr_bl")
	blB   := newBLHashMap(t, "blcdr_blb")
	cbl   := newCIDRHashMap(t, "blcdr_cbl")
	cblB  := newCIDRHashMap(t, "blcdr_cblb")
	cfgA  := newCfgArray(t, "blcdr_cfga")
	cfgB  := newCfgArray(t, "blcdr_cfgb")
	actCfg := newActiveCfg(t)

	srcV4, dstV4 := newFakeTrie(), newFakeTrie()
	srcV6, dstV6 := newFakeTrie(), newFakeTrie()

	h := &Handlers{
		blacklist:        bl,
		blacklistB:       blB,
		cidrBlacklist:    cbl,
		cidrBlacklistB:   cblB,
		configA:          cfgA,
		configB:          cfgB,
		activeConfig:     actCfg,
		cidrMgr:          cidr.NewManager(srcV4, dstV4, srcV6, dstV6),
		rules:            make(map[string]StoredRule),
		ruleKeyIndex:     make(map[RuleKey]string),
		cidrRules:        make(map[string]StoredCIDRRule),
		cidrRuleKeyIndex: make(map[CIDRRuleKey]string),
		activeSlot:       0,
		activeRuleSlot:   0,
	}

	if err := h.initDynamicConfig(cfgA); err != nil {
		t.Fatalf("initDynamicConfig cfgA: %v", err)
	}
	if err := h.initDynamicConfig(cfgB); err != nil {
		t.Fatalf("initDynamicConfig cfgB: %v", err)
	}
	return h
}

// T-BL-CIDR-1: DoAtomicSync with CIDR-only rules writes entries to the shadow
// cidrBlacklist map, flips the selector, and the new active map holds the rules
// while the new shadow is empty. Config slots reflect the installed state.
func TestBL_CIDR_T1_AtomicSyncFlipsMapPair(t *testing.T) {
	h := newBLCIDRTestHandlers(t)

	rules := []Rule{
		{ID: "cidr1", SrcCIDR: "192.0.2.0/24",   Action: "drop"},
		{ID: "cidr2", DstCIDR: "198.51.100.0/24", Action: "drop"},
	}

	res, err := h.DoAtomicSync(rules)
	if err != nil {
		t.Fatalf("DoAtomicSync: %v", err)
	}
	if res.Failed != 0 {
		t.Fatalf("expected 0 failed, got %d", res.Failed)
	}

	// activeRuleSlot must have flipped from 0 → 1.
	if h.activeRuleSlot != 1 {
		t.Errorf("activeRuleSlot = %d, want 1", h.activeRuleSlot)
	}

	// Active CIDR map (cidrBlacklistB, slot 1) must hold 2 entries.
	if n := countMapEntries(t, h.activeCidrBlacklist()); n != 2 {
		t.Errorf("active cidrBlacklist entries = %d, want 2", n)
	}

	// Shadow CIDR map (cidrBlacklist, slot 0) must be empty after cleanup.
	if n := countMapEntries(t, h.shadowCidrBlacklist()); n != 0 {
		t.Errorf("shadow cidrBlacklist entries = %d, want 0 (should be cleared)", n)
	}

	// ConfigCIDRBitmap must be non-zero.
	if got := readSlot(t, h.activeMap(), ConfigCIDRBitmap); got == 0 {
		t.Error("ConfigCIDRBitmap = 0 after sync with CIDR rules")
	}

	// ConfigCIDRRuleCount must equal 2.
	if got := readSlot(t, h.activeMap(), ConfigCIDRRuleCount); got != 2 {
		t.Errorf("ConfigCIDRRuleCount = %d, want 2", got)
	}

	// ConfigRuleMapSelector must equal 1.
	if got := readSlot(t, h.activeMap(), ConfigRuleMapSelector); got != 1 {
		t.Errorf("ConfigRuleMapSelector = %d, want 1", got)
	}
}

// T-BL-CIDR-2: Two consecutive DoAtomicSync calls double-flip the selector
// back to slot 0. The second sync's rules end up in the originally-active maps.
func TestBL_CIDR_T2_ConsecutiveSyncsDoubleFlip(t *testing.T) {
	h := newBLCIDRTestHandlers(t)

	// First sync: 1 CIDR rule → slot flips 0→1.
	if _, err := h.DoAtomicSync([]Rule{
		{ID: "c1", SrcCIDR: "192.0.2.0/24", Action: "drop"},
	}); err != nil {
		t.Fatalf("first DoAtomicSync: %v", err)
	}
	if h.activeRuleSlot != 1 {
		t.Fatalf("after first sync: activeRuleSlot = %d, want 1", h.activeRuleSlot)
	}

	// Second sync: different CIDR rule → slot flips 1→0.
	if _, err := h.DoAtomicSync([]Rule{
		{ID: "c2", DstCIDR: "198.51.100.0/24", Action: "drop"},
	}); err != nil {
		t.Fatalf("second DoAtomicSync: %v", err)
	}
	if h.activeRuleSlot != 0 {
		t.Errorf("after second sync: activeRuleSlot = %d, want 0", h.activeRuleSlot)
	}

	// Active CIDR map (cidrBlacklist, slot 0) must hold second sync's 1 entry.
	if n := countMapEntries(t, h.activeCidrBlacklist()); n != 1 {
		t.Errorf("active cidrBlacklist entries after double-flip = %d, want 1", n)
	}

	// Shadow (cidrBlacklistB, slot 1) must be empty.
	if n := countMapEntries(t, h.shadowCidrBlacklist()); n != 0 {
		t.Errorf("shadow cidrBlacklist entries after double-flip = %d, want 0", n)
	}

	// ConfigCIDRRuleCount must reflect second sync (1 rule).
	if got := readSlot(t, h.activeMap(), ConfigCIDRRuleCount); got != 1 {
		t.Errorf("ConfigCIDRRuleCount after double-flip = %d, want 1", got)
	}

	// ConfigRuleMapSelector must be back to 0.
	if got := readSlot(t, h.activeMap(), ConfigRuleMapSelector); got != 0 {
		t.Errorf("ConfigRuleMapSelector after double-flip = %d, want 0", got)
	}
}

// T-BL-CIDR-3: DoAtomicSync with mixed exact-IP + CIDR rules flips both the
// blacklist and cidrBlacklist map pairs atomically in a single sync call.
func TestBL_CIDR_T3_MixedExactAndCIDRRulesFlipBothMaps(t *testing.T) {
	h := newBLCIDRTestHandlers(t)

	rules := []Rule{
		{ID: "exact1", SrcIP: "198.51.100.1",    Action: "drop"},
		{ID: "exact2", DstIP: "203.0.113.5",      Action: "drop"},
		{ID: "cidr1",  SrcCIDR: "192.0.2.0/24",   Action: "drop"},
	}

	res, err := h.DoAtomicSync(rules)
	if err != nil {
		t.Fatalf("DoAtomicSync: %v", err)
	}
	if res.Failed != 0 {
		t.Fatalf("expected 0 failed, got %d", res.Failed)
	}

	// Active exact-match map must hold 2 entries.
	if n := countMapEntries(t, h.activeBlacklist()); n != 2 {
		t.Errorf("active blacklist entries = %d, want 2", n)
	}

	// Active CIDR map must hold 1 entry.
	if n := countMapEntries(t, h.activeCidrBlacklist()); n != 1 {
		t.Errorf("active cidrBlacklist entries = %d, want 1", n)
	}

	// Both shadow maps must be empty.
	if n := countMapEntries(t, h.shadowBlacklist()); n != 0 {
		t.Errorf("shadow blacklist entries = %d, want 0", n)
	}
	if n := countMapEntries(t, h.shadowCidrBlacklist()); n != 0 {
		t.Errorf("shadow cidrBlacklist entries = %d, want 0", n)
	}

	// Config must reflect both counts.
	if got := readSlot(t, h.activeMap(), ConfigBlacklistCount); got != 2 {
		t.Errorf("ConfigBlacklistCount = %d, want 2", got)
	}
	if got := readSlot(t, h.activeMap(), ConfigCIDRRuleCount); got != 1 {
		t.Errorf("ConfigCIDRRuleCount = %d, want 1", got)
	}
	if got := readSlot(t, h.activeMap(), ConfigRuleMapSelector); got != 1 {
		t.Errorf("ConfigRuleMapSelector = %d, want 1", got)
	}
}
