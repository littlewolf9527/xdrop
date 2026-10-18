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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
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
	bl := newBLHashMap(t, "blcdr_bl")
	blB := newBLHashMap(t, "blcdr_blb")
	cbl := newCIDRHashMap(t, "blcdr_cbl")
	cblB := newCIDRHashMap(t, "blcdr_cblb")
	cfgA := newCfgArray(t, "blcdr_cfga")
	cfgB := newCfgArray(t, "blcdr_cfgb")
	actCfg := newActiveCfg(t)

	srcV4, dstV4 := newFakeTrie(), newFakeTrie()
	srcV6, dstV6 := newFakeTrie(), newFakeTrie()

	h := &Handlers{
		condA: b7Map(t, ebpf.Hash, 40, 844), condB: b7Map(t, ebpf.Hash, 40, 844),
		cidrCondA: b7Map(t, ebpf.Hash, 16, 844), cidrCondB: b7Map(t, ebpf.Hash, 16, 844),
		idRLStates: b7Map(t, ebpf.PerCPUHash, 4, 16), idCounts: b7Map(t, ebpf.PerCPUHash, 4, 40),
		quiescer:         cut5ReceiptFunc(func() error { return nil }),
		blacklist:        bl,
		blacklistB:       blB,
		cidrBlacklist:    cbl,
		cidrBlacklistB:   cblB,
		configA:          cfgA,
		configB:          cfgB,
		activeConfig:     actCfg,
		cidrMgr:          cidr.NewManager(srcV4, dstV4, srcV6, dstV6, newFakeTrie(), newFakeTrie(), newFakeTrie(), newFakeTrie()),
		rules:            make(map[string]StoredRule),
		ruleKeyIndex:     make(map[RuleKey]ruleIDSet),
		cidrRules:        make(map[string]StoredCIDRRule),
		cidrRuleKeyIndex: make(map[CIDRRuleKey]ruleIDSet),
		activeSlot:       0,
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
		{LogicalID: 543001, ID: "cidr1", SrcCIDR: "192.0.2.0/24", Action: "drop"},
		{LogicalID: 543002, ID: "cidr2", DstCIDR: "198.51.100.0/24", Action: "drop"},
	}

	res, err := h.DoAtomicSync(rules)
	if err != nil {
		t.Fatalf("DoAtomicSync: %v", err)
	}
	if res.Failed != 0 {
		t.Fatalf("expected 0 failed, got %d", res.Failed)
	}

	// activeRuleSlot must have flipped from 0 → 1.
	if int(h.activeRuleSlot.Load()) != 1 {
		t.Errorf("activeRuleSlot = %d, want 1", int(h.activeRuleSlot.Load()))
	}

	// Active CIDR map (cidrBlacklistB, slot 1) must hold 2 entries.
	if n := countMapEntries(t, p7ActiveCIDR(h)); n != 2 {
		t.Errorf("active cidrBlacklist entries = %d, want 2", n)
	}

	// Protocol 5 I16: the old side is an exact byte mirror of the new side.
	if !reflect.DeepEqual(b7Snapshot(t, h.shadowCidrBlacklist()), b7Snapshot(t, p7ActiveCIDR(h))) {
		t.Error("shadow CIDR bytes differ from active after sync")
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
		{LogicalID: 543003, ID: "c1", SrcCIDR: "192.0.2.0/24", Action: "drop"},
	}); err != nil {
		t.Fatalf("first DoAtomicSync: %v", err)
	}
	if int(h.activeRuleSlot.Load()) != 1 {
		t.Fatalf("after first sync: activeRuleSlot = %d, want 1", int(h.activeRuleSlot.Load()))
	}

	// Second sync: different CIDR rule → slot flips 1→0.
	if _, err := h.DoAtomicSync([]Rule{
		{LogicalID: 543004, ID: "c2", DstCIDR: "198.51.100.0/24", Action: "drop"},
	}); err != nil {
		t.Fatalf("second DoAtomicSync: %v", err)
	}
	if int(h.activeRuleSlot.Load()) != 0 {
		t.Errorf("after second sync: activeRuleSlot = %d, want 0", int(h.activeRuleSlot.Load()))
	}

	// Active CIDR map (cidrBlacklist, slot 0) must hold second sync's 1 entry.
	if n := countMapEntries(t, p7ActiveCIDR(h)); n != 1 {
		t.Errorf("active cidrBlacklist entries after double-flip = %d, want 1", n)
	}

	// Protocol 5 I16: both generations retain the complete mirror.
	if !reflect.DeepEqual(b7Snapshot(t, h.shadowCidrBlacklist()), b7Snapshot(t, p7ActiveCIDR(h))) {
		t.Error("shadow CIDR bytes differ from active after double flip")
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
		{LogicalID: 543005, ID: "exact1", SrcIP: "198.51.100.1", Action: "drop"},
		{LogicalID: 543006, ID: "exact2", DstIP: "203.0.113.5", Action: "drop"},
		{LogicalID: 543007, ID: "cidr1", SrcCIDR: "192.0.2.0/24", Action: "drop"},
	}

	res, err := h.DoAtomicSync(rules)
	if err != nil {
		t.Fatalf("DoAtomicSync: %v", err)
	}
	if res.Failed != 0 {
		t.Fatalf("expected 0 failed, got %d", res.Failed)
	}

	// Active exact-match map must hold 2 entries.
	if n := countMapEntries(t, p7ActiveBlacklist(h)); n != 2 {
		t.Errorf("active blacklist entries = %d, want 2", n)
	}

	// Active CIDR map must hold 1 entry.
	if n := countMapEntries(t, p7ActiveCIDR(h)); n != 1 {
		t.Errorf("active cidrBlacklist entries = %d, want 1", n)
	}

	// Protocol 5 I16: retain both independent byte-equality assertions.
	if !reflect.DeepEqual(b7Snapshot(t, h.shadowBlacklist()), b7Snapshot(t, p7ActiveBlacklist(h))) {
		t.Error("shadow exact bytes differ from active")
	}
	if !reflect.DeepEqual(b7Snapshot(t, h.shadowCidrBlacklist()), b7Snapshot(t, p7ActiveCIDR(h))) {
		t.Error("shadow CIDR bytes differ from active")
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

// Jia golden fixtures are emitted only by real handlers backed by private BPF
// maps in the authorized lab. Verification always compares the raw body bytes.
type jiaGolden struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func jiaHandler(t *testing.T) (*Handlers, *gin.Engine) {
	t.Helper()
	// Fail (never skip) if this lab cannot create the private maps we require.
	probe, err := ebpf.NewMap(&ebpf.MapSpec{Name: "jia_cap", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
	h := newBLCIDRTestHandlers(t)
	h.whitelist = newWLHashMap(t, "jia_wl")
	h.whitelistB = newWLHashMap(t, "jia_wlb")
	h.wlEntries = make(map[string]RuleKey)
	h.wlKeyIndex = make(map[RuleKey]string)
	h.lastRuleDropCount = make(map[string]uint64)
	h.lastRuleStatsTime = make(map[string]int64)
	h.sysStatsCache = &SystemStatsCache{}
	h.stats, err = ebpf.NewMap(&ebpf.MapSpec{Name: "jia_stats", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 5})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.stats.Close() })
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/sync/atomic", h.AtomicSync)
	r.POST("/api/v1/sync/whitelist", h.SyncWhitelistHandler)
	r.GET("/api/v1/rules", h.ListRules)
	r.GET("/api/v1/stats", h.GetStats)
	r.GET("/api/v1/whitelist", h.ListWhitelist)
	return h, r
}
func jiaCall(t *testing.T, r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	q := httptest.NewRequest(method, path, strings.NewReader(body))
	q.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, q)
	return w
}
func jiaAssertGolden(t *testing.T, name string, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("%s status=%d want=%d body=%s", name, w.Code, status, w.Body.String())
	}
	if code != "" {
		var m map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if m["code"] != code {
			t.Fatalf("%s code=%v want=%s", name, m["code"], code)
		}
	}
	file := filepath.Join("..", "testdata", "sync-jia", name+".json")
	actual := jiaGolden{Status: w.Code, Body: w.Body.String()}
	if strings.HasSuffix(name, "_p3") || strings.HasSuffix(name, "_p4") || strings.HasSuffix(name, "_p8") || strings.HasSuffix(name, "_p9") || strings.HasSuffix(name, "_p10") || strings.HasSuffix(name, "_p11") {
		if !dingWritableGolden[name] && !prefixABWritableGolden[name] {
			t.Fatalf("unregistered protocol-3 golden: %s", name)
		}
		cut53P3Golden(t, name, t.Name(), w)
		return
	}
	// All historical single-response fixtures are read-only.
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var expected jiaGolden
	if err = json.Unmarshal(b, &expected); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("%s golden mismatch\nactual=%+v\nexpected=%+v", name, actual, expected)
	}
}
func jiaRule(id string, rate int) string {
	logicalID := uint32(17)
	if id == "other" {
		logicalID = 19
	}
	return fmt.Sprintf(`{"id":%q,"logical_id":%d,"src_ip":"10.0.0.1","protocol":"tcp","action":"rate_limit","rate_limit":%d}`, id, logicalID, rate)
}
func TestJiaHandlerGolden(t *testing.T) {
	t.Run("YiFailures", yiGoldenFailures)
	t.Run("RouteMissing", func(t *testing.T) {
		_, r := jiaHandler(t)
		jiaAssertGolden(t, "route_missing", jiaCall(t, r, "DELETE", "/unregistered", ""), 404, "")
	})
	t.Run("SnapshotsAndWhitelist", func(t *testing.T) {
		_, r := jiaHandler(t)
		for n := 0; n <= 2; n++ {
			rules := []json.RawMessage{}
			if n > 0 {
				rules = append(rules, json.RawMessage(jiaRule("r", 100)))
			}
			if n > 1 {
				rules = append(rules, json.RawMessage(`{"id":"r2","logical_id":18,"src_ip":"10.0.0.2","action":"drop"}`))
			}
			b, _ := json.Marshal(map[string]interface{}{"rules": rules})
			jiaAssertGolden(t, fmt.Sprintf("atomic_%d_p8", n), jiaCall(t, r, "POST", "/api/v1/sync/atomic", string(b)), 200, "")
			jiaAssertGolden(t, fmt.Sprintf("stats_%d_p11", n), jiaCall(t, r, "GET", "/api/v1/stats", ""), 200, "")
			rulesGolden := fmt.Sprintf("rules_%d", n)
			if n > 0 {
				rulesGolden += "_p11"
			}
			jiaAssertGolden(t, rulesGolden, jiaCall(t, r, "GET", "/api/v1/rules?page=1&limit=1000", ""), 200, "")
		}
		jiaAssertGolden(t, "whitelist_empty", jiaCall(t, r, "POST", "/api/v1/sync/whitelist", `{"entries":[]}`), 200, "")
		jiaAssertGolden(t, "whitelist_list_empty", jiaCall(t, r, "GET", "/api/v1/whitelist", ""), 200, "")
		jiaAssertGolden(t, "atomic_invalid_p8", jiaCall(t, r, "POST", "/api/v1/sync/atomic", `{"rules":[{"id":"bad","src_ip":"bad","action":"drop"}]}`), 200, "")
	})
}

func yiAtomicCall(t *testing.T, r *gin.Engine, rules []Rule) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"rules": rules})
	if err != nil {
		t.Fatal(err)
	}
	return jiaCall(t, r, "POST", "/api/v1/sync/atomic", string(b))
}
func yiGoldenFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		freeze func(*Handlers) *ebpf.Map
	}{{"atomic_kernel_error_p8", (*Handlers).shadowBlacklist}, {"atomic_config_error_p8", (*Handlers).shadowMap}, {"atomic_flip_error_p8", func(h *Handlers) *ebpf.Map { return h.activeConfig }}} {
		t.Run(tc.name, func(t *testing.T) {
			h, r := jiaHandler(t)
			if err := tc.freeze(h).Freeze(); err != nil {
				t.Fatal(err)
			}
			jiaAssertGolden(t, tc.name, yiAtomicCall(t, r, []Rule{{LogicalID: 17, ID: "r", SrcIP: "10.0.0.1", Action: "drop"}}), 500, "")
		})
	}
	t.Run("DuplicateKey", func(t *testing.T) {
		_, router := jiaHandler(t)
		jiaAssertGolden(t, "atomic_duplicate_key_p8", yiAtomicCall(t, router, []Rule{{ID: "r", SrcIP: "10.0.0.1", Protocol: "tcp", Action: "rate_limit", RateLimit: 100}, {ID: "r2", SrcIP: "10.0.0.1", Protocol: "tcp", Action: "drop"}}), 409, "condition_group_invalid")
	})
	t.Run("Partial", func(t *testing.T) {
		_, r := jiaHandler(t)
		jiaAssertGolden(t, "atomic_partial_p8", yiAtomicCall(t, r, []Rule{{LogicalID: 17, ID: "r", SrcIP: "10.0.0.1", Protocol: "tcp", Action: "rate_limit", RateLimit: 100}, {LogicalID: 543010, ID: "r2", SrcIP: "invalid", Action: "drop"}}), 200, "")
		jiaAssertGolden(t, "atomic_bad_json_p8", jiaCall(t, r, "POST", "/api/v1/sync/atomic", "{"), 400, "")
	})
}

// Real handlers backed by private maps loaded from the real ELF; no attach/pin.
func TestYiPartialRejection(t *testing.T) {
	cases := []struct {
		name   string
		bad    Rule
		reason string
	}{
		{"mixed", Rule{SrcIP: "10.1.0.1", SrcCIDR: "10.1.0.0/24", Action: "drop"}, "exact IP and CIDR"},
		{"action", Rule{SrcIP: "10.1.0.1", Action: "invalid"}, "invalid action"},
		{"rate", Rule{SrcIP: "10.1.0.1", Action: "rate_limit"}, "rate_limit must be > 0"},
		{"src_cidr", Rule{SrcCIDR: "10.1.0.0/99", Action: "drop"}, "invalid src_cidr"},
		{"dst_cidr", Rule{DstCIDR: "10.2.0.0/99", Action: "drop"}, "invalid dst_cidr"},
		{"cidr_flags", Rule{SrcCIDR: "10.1.0.0/24", Protocol: "tcp", TcpFlags: "BAD", Action: "drop"}, "unknown TCP flag"},
		{"cidr_flags_protocol", Rule{SrcCIDR: "10.1.0.0/24", Protocol: "udp", TcpFlags: "SYN", Action: "drop"}, "tcp_flags requires protocol=tcp"},
		{"cidr_anomaly", Rule{SrcCIDR: "10.1.0.0/24", MatchAnomaly: 8, Action: "drop"}, "missing/duplicate logical_id"},
		{"cidr_port", Rule{SrcCIDR: "10.1.0.0/24", Protocol: "gre", SrcPort: 50, Action: "drop"}, "port"},
		{"cidr_protocol", Rule{SrcCIDR: "10.1.0.0/24", Protocol: "typo", Action: "drop"}, "unknown protocol"},
		{"exact_length", Rule{SrcIP: "10.1.0.1", PktLenMin: 100, PktLenMax: 50, Action: "drop"}, "invalid length range"},
		{"exact_src_ip", Rule{SrcIP: "invalid", Action: "drop"}, "invalid src_ip"},
		{"exact_dst_ip", Rule{DstIP: "invalid", Action: "drop"}, "invalid dst_ip"},
		{"exact_anomaly", Rule{SrcIP: "10.1.0.1", MatchAnomaly: 8, Action: "drop"}, "missing/duplicate logical_id"},
		{"exact_combo", Rule{Action: "drop"}, "combination is not recognized"},
		{"exact_flags", Rule{SrcIP: "10.1.0.1", Protocol: "tcp", TcpFlags: "BAD", Action: "drop"}, "unknown TCP flag"},
		{"exact_flags_protocol", Rule{SrcIP: "10.1.0.1", Protocol: "udp", TcpFlags: "SYN", Action: "drop"}, "tcp_flags requires protocol=tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, r, p := b7ELF(t)
			bad := tc.bad
			bad.ID = "unchanged-request-ID"
			oldSlot := h.activeSlot
			before := cut53BusinessSnapshot(t, h)
			w := yiAtomicCall(t, r, []Rule{{LogicalID: 543011, ID: "good", SrcIP: "10.0.0.1", Action: "drop"}, bad, {LogicalID: 543012, ID: "cidr", SrcCIDR: "10.20.0.0/24", Action: "drop"}})
			if bad.TcpFlags != "" || bad.MatchAnomaly != 0 || bad.PktLenMin > 0 {
				var got struct {
					Code          string
					Conflicts     []atomicConditionConflict
					Added, Failed int
				}
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if w.Code != 409 || got.Code != "condition_group_invalid" || got.Added != 0 || got.Failed != 1 || len(got.Conflicts) != 1 || got.Conflicts[0].ID != bad.ID || !strings.Contains(got.Conflicts[0].Reason, tc.reason) {
					t.Fatalf("I6 invalid group: %d %s", w.Code, w.Body.String())
				}
				if h.activeSlot != oldSlot || !reflect.DeepEqual(before, cut53BusinessSnapshot(t, h)) {
					t.Fatal("I6 partial-rejection input wrote state")
				}
				b7Verdict(t, p, 2)
				return
			}

			var got struct {
				Added, Failed int
				Rejected      []AtomicSyncRejection
				Exact         int `json:"rules"`
				CIDR          int `json:"cidr_rules"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || got.Added != 2 || got.Failed != 1 || got.Exact != 1 || got.CIDR != 1 {
				t.Fatalf("partial counts/status: %d %s", w.Code, w.Body.String())
			}
			if len(got.Rejected) != 1 || got.Rejected[0].ID != bad.ID || got.Rejected[0].Index != nil || !strings.Contains(got.Rejected[0].Reason, tc.reason) {
				t.Fatalf("rejection identity/reason: %s", w.Body.String())
			}
			if h.activeSlot == oldSlot || len(h.rules) != 1 || len(h.cidrRules) != 1 {
				t.Fatal("accepted remainder did not flip")
			}
			b7Verdict(t, p, 1)
		})
	}
	t.Run("empty_id", func(t *testing.T) {
		_, r, _ := b7ELF(t)
		w := yiAtomicCall(t, r, []Rule{{LogicalID: 543013, ID: "ok", SrcIP: "10.0.0.1", Action: "drop"}, {SrcIP: "invalid", Action: "drop"}})
		var got struct{ Rejected []AtomicSyncRejection }
		json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != 200 || len(got.Rejected) != 1 || got.Rejected[0].ID != "" || got.Rejected[0].Index == nil || *got.Rejected[0].Index != 1 {
			t.Fatalf("original empty ID/index lost: %s", w.Body.String())
		}
	})
}

// Inspect the manager's counters, not merely prefix membership: a leaked extra
// reference to an old prefix would leave membership unchanged.
func yiCIDRRefs(h *Handlers) map[string]int64 {
	out := map[string]int64{}
	manager := reflect.ValueOf(h.cidrMgr).Elem()
	for _, field := range []string{"srcV4Refs", "dstV4Refs", "srcV6Refs", "dstV6Refs"} {
		it := manager.FieldByName(field).MapRange()
		for it.Next() {
			out[field+":"+it.Key().String()] = it.Value().Int()
		}
	}
	return out
}

func TestYiDuplicateKey(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		for _, emptyID := range []bool{false, true} {
			t.Run(fmt.Sprintf("cidr=%v/emptyID=%v", isCIDR, emptyID), func(t *testing.T) {
				h, router, program := b7ELF(t)
				old := b7Rule(isCIDR)
				old.ID = "old"
				if w := yiAtomicCall(t, router, []Rule{old}); w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				b7Verdict(t, program, 1)
				first := old
				first.ID = "first"
				// J5 witness：组成员逻辑 ID 0 ⇒ 整组无效。
				first.LogicalID = 0
				first.PktLenMax = 40
				second := old
				second.ID = "second"
				second.LogicalID = 0
				if emptyID {
					first.ID = ""
					second.ID = ""
				}
				// Include a newly allocated src+dst prefix before either duplicate.
				batch := []Rule{{LogicalID: 543014, ID: "new-prefix", SrcCIDR: "10.20.0.0/24", DstCIDR: "10.21.0.0/24", Action: "drop"}, first, second}
				slot, ruleSlot := h.activeSlot, int(h.activeRuleSlot.Load())
				refs := yiCIDRRefs(h)
				bl, cbl, conf := b7Snapshot(t, p7ActiveBlacklist(h)), b7Snapshot(t, p7ActiveCIDR(h)), b7Snapshot(t, h.activeMap())
				w := yiAtomicCall(t, router, batch)
				var got struct {
					Code, Error string
					Conflicts   []atomicRuleIdentity
					Rejected    []AtomicSyncRejection
				}
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if w.Code != 409 || got.Code != "condition_group_invalid" || len(got.Conflicts) != 2 || len(got.Rejected) != 0 {
					t.Fatalf("duplicate must abort: %d %s", w.Code, w.Body.String())
				}
				t.Logf("CUT54_YI_DUPLICATE_BRANCH cidr=%v emptyID=%v code=%s conflicts=%d target=duplicate_must_abort logical_ids=%d/%d", isCIDR, emptyID, got.Code, len(got.Conflicts), first.LogicalID, second.LogicalID)
				for i, id := range []string{first.ID, second.ID} {
					if got.Conflicts[i].ID != id {
						t.Fatalf("conflicting original ID lost: %s", w.Body.String())
					}
					if emptyID {
						if got.Conflicts[i].Index == nil || *got.Conflicts[i].Index != i+1 {
							t.Fatalf("empty ID index lost: %s", w.Body.String())
						}
					} else if got.Conflicts[i].Index != nil {
						t.Fatalf("conflict reason/identity: %s", w.Body.String())
					}
				}
				if slot != h.activeSlot || ruleSlot != int(h.activeRuleSlot.Load()) || readSlot(t, h.activeConfig, 0) != uint64(slot) {
					t.Fatal("duplicate flipped generation")
				}
				if !reflect.DeepEqual(bl, b7Snapshot(t, p7ActiveBlacklist(h))) || !reflect.DeepEqual(cbl, b7Snapshot(t, p7ActiveCIDR(h))) || !reflect.DeepEqual(conf, b7Snapshot(t, h.activeMap())) {
					t.Fatal("duplicate changed old maps/config")
				}
				if !reflect.DeepEqual(refs, yiCIDRRefs(h)) {
					t.Fatalf("CIDR refs before=%v after=%v", refs, yiCIDRRefs(h))
				}
				if len(h.rules)+len(h.cidrRules) != 1 {
					t.Fatal("duplicate committed new memory")
				}
				b7Verdict(t, program, 1)
				t.Logf("status=409 no_flip=true old_drop=1 refs_before=%v refs_after=%v", refs, yiCIDRRefs(h))
				if w = yiAtomicCall(t, router, nil); w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				if len(yiCIDRRefs(h)) != 0 {
					t.Fatal("references survived old-generation retirement")
				}
			})
		}
	}
	t.Run("old_broad_new_narrow", func(t *testing.T) {
		h, router, program := b7ELF(t)
		broad := Rule{LogicalID: 543015, ID: "old-broad", SrcCIDR: "10.0.0.0/8", Action: "drop"}
		if w := yiAtomicCall(t, router, []Rule{broad}); w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		packet := make([]byte, 512)
		copy(packet, b7Packet())
		packet[23] = 17
		binary.BigEndian.PutUint16(packet[16:18], uint16(len(packet)-14))
		copy(packet[26:30], []byte{10, 20, 1, 2})
		copy(packet[30:34], []byte{172, 16, 1, 1})
		binary.BigEndian.PutUint16(packet[38:40], uint16(len(packet)-34))
		verdict := func() {
			t.Helper()
			got, _, err := program.Test(packet)
			if err != nil || got != 1 {
				t.Fatalf("512-byte /8 protection verdict=%d err=%v", got, err)
			}
		}
		verdict()
		slot := h.activeSlot
		refs := yiCIDRRefs(h)
		narrow := broad
		narrow.ID = "new-narrow"
		// J5 witness：组成员逻辑 ID 0 ⇒ 整组无效；已安装的 broad 保持非 0。
		narrow.LogicalID = 0
		narrow.PktLenMax = 100
		w := yiAtomicCall(t, router, []Rule{narrow, broad})
		b7Code(t, w, 409, "condition_group_invalid")
		t.Logf("CUT54_YI_DUPLICATE_BRANCH old_broad_new_narrow code=condition_group_invalid target=want_409_condition_group_invalid logical_ids=%d/%d", narrow.LogicalID, broad.LogicalID)
		if h.activeSlot != slot || !reflect.DeepEqual(refs, yiCIDRRefs(h)) || h.cidrRules["old-broad"].PktLenMax != 0 || len(h.cidrRules) != 1 {
			t.Fatal("old broad generation lost")
		}
		verdict()
		t.Log("packet=10.20.1.2->172.16.1.1 length=512 before=DROP after=DROP status=409")
	})
}

// Open only the private trie maps already referenced by this loaded program.
func yiELFTries(t *testing.T, program *ebpf.Program) []*ebpf.Map {
	t.Helper()
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	ids, ok := info.MapIDs()
	if !ok {
		t.Fatal("ELF map IDs unavailable")
	}
	names := []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b"}
	tries := make([]*ebpf.Map, 8)
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		mi, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		for i, name := range names {
			if mi.Name == name {
				tries[i] = m
			}
		}
	}
	for i, m := range tries {
		if m == nil {
			t.Fatalf("ELF missing trie %s", names[i])
		}
	}
	return tries
}

// A missing static slot makes only the copy fail. Step 3b can still succeed,
// so deleting the copy guard cannot be masked by a later dynamic-write error.
func yiConfigHole(t *testing.T, source *ebpf.Map) *ebpf.Map {
	t.Helper()
	m := b7Map(t, ebpf.Hash, 4, 8)
	for i := uint32(0); i < ConfigMapEntries; i++ {
		if i == ConfigFilterIfindex {
			continue
		}
		var value [8]byte
		if err := source.Lookup(i, &value); err != nil {
			t.Fatal(err)
		}
		if err := m.Update(i, value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	return m
}
func TestYiKernelAbort(t *testing.T) {
	for _, failure := range []string{"exact_write", "cidr_write", "src_publish", "dst_publish", "copy_lookup", "copy_update", "flip"} {
		t.Run(failure, func(t *testing.T) {
			h, r, program := b7ELF(t)
			tries := yiELFTries(t, program)
			if failure == "src_publish" {
				if err := tries[0].Freeze(); err != nil {
					t.Fatal(err)
				}
			}
			old := []Rule{{LogicalID: 543016, ID: "old", SrcIP: "10.9.0.1", Action: "drop"}, {LogicalID: 543017, ID: "oldcidr", SrcCIDR: "10.9.1.0/24", Action: "drop"}}
			if w := yiAtomicCall(t, r, old); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			writeSlot(t, h.activeMap(), ConfigFilterIfindex, 17)
			activeBL, activeCIDR, activeConfig := p7ActiveBlacklist(h), p7ActiveCIDR(h), h.activeMap()
			beforeBL, beforeCIDR, beforeConfig := b7Snapshot(t, activeBL), b7Snapshot(t, activeCIDR), b7Snapshot(t, activeConfig)
			slot, ruleSlot := h.activeSlot, int(h.activeRuleSlot.Load())
			wanted := ""
			switch failure {
			case "exact_write":
				wanted = "write shadow exact rule"
				// Auth3 section 2: retain the Step 2 failure witness after strict Step 1.
				if err := StrictClearAndRecount(h.shadowBlacklist()); err != nil {
					t.Fatal(err)
				}
				if err := h.shadowBlacklist().Freeze(); err != nil {
					t.Fatal(err)
				}
			case "cidr_write":
				wanted = "write shadow CIDR rule"
				// Auth3 section 2: retain the Step 2 failure witness after strict Step 1.
				if err := StrictClearAndRecount(h.shadowCidrBlacklist()); err != nil {
					t.Fatal(err)
				}
				if err := h.shadowCidrBlacklist().Freeze(); err != nil {
					t.Fatal(err)
				}
			case "src_publish":
				wanted = "update: operation not permitted"
			case "dst_publish":
				wanted = "update: operation not permitted"
				if err := tries[1].Freeze(); err != nil {
					t.Fatal(err)
				}
			case "copy_lookup":
				wanted = "read active config index 5"
				if slot == 0 {
					h.configA = yiConfigHole(t, activeConfig)
				} else {
					h.configB = yiConfigHole(t, activeConfig)
				}
			case "copy_update":
				wanted = "copy shadow config index 5"
				if slot == 0 {
					h.configB = yiConfigHole(t, h.shadowMap())
				} else {
					h.configA = yiConfigHole(t, h.shadowMap())
				}
			case "flip":
				wanted = "failed to flip config selector"
				if err := h.activeConfig.Freeze(); err != nil {
					t.Fatal(err)
				}
			}
			batch := []Rule{{LogicalID: 543018, ID: "newcidr", SrcCIDR: "10.20.0.0/24", DstCIDR: "10.21.0.0/24", Action: "drop"}, {LogicalID: 543019, ID: "newexact", SrcIP: "10.30.0.1", Action: "drop"}, {LogicalID: 543020, ID: "bad", SrcIP: "invalid", Action: "drop"}}
			w := yiAtomicCall(t, r, batch)
			if w.Code != 500 || !strings.Contains(w.Body.String(), wanted) {
				t.Fatalf("kernel error must abort (%s): %d %s", wanted, w.Code, w.Body.String())
			}
			if h.activeSlot != slot || int(h.activeRuleSlot.Load()) != ruleSlot || readSlot(t, h.activeConfig, 0) != uint64(slot) {
				t.Fatal("kernel error flipped selectors")
			}
			if !reflect.DeepEqual(beforeBL, b7Snapshot(t, activeBL)) || !reflect.DeepEqual(beforeCIDR, b7Snapshot(t, activeCIDR)) || !reflect.DeepEqual(beforeConfig, b7Snapshot(t, activeConfig)) {
				t.Fatal("kernel error changed active tables/config")
			}
			if len(h.rules) != 1 || len(h.cidrRules) != 1 {
				t.Fatal("kernel error committed memory")
			}
			if len(h.cidrMgr.ListSrcCIDRs()) != 1 || len(h.cidrMgr.ListDstCIDRs()) != 0 {
				t.Fatalf("abort leaked CIDR IDs: src=%v dst=%v", h.cidrMgr.ListSrcCIDRs(), h.cidrMgr.ListDstCIDRs())
			}
			if len(b7Snapshot(t, tries[ruleSlot*4])) != 1 || len(b7Snapshot(t, tries[ruleSlot*4+1])) != 0 {
				t.Fatal("abort changed active trie entries")
			}
			if failure == "src_publish" && len(b7Snapshot(t, tries[0])) != 0 {
				t.Fatal("failed first shadow write unexpectedly created prefix")
			}
			if failure == "dst_publish" && (len(b7Snapshot(t, tries[0])) != 1 || len(b7Snapshot(t, tries[1])) != 0) {
				t.Fatal("shadow residue differs from completed write before failure")
			}
			if failure == "flip" && (len(b7Snapshot(t, tries[0])) != 1 || len(b7Snapshot(t, tries[1])) != 1) {
				t.Fatal("flip failure must retain the unknown shadow copy")
			}
		})
	}
}

var dingWritableGolden = map[string]bool{
	"welcome_p11": true, "stats_0_p11": true, "stats_1_p11": true, "stats_2_p11": true,
	"stats_slot5_p11": true, "rules_1_p11": true, "rules_2_p11": true,
	"stats_0_p10": true, "stats_1_p10": true, "stats_2_p10": true,
	"stats_0_p9": true, "stats_1_p9": true, "stats_2_p9": true,
	"commit_committed_p8": true, "commit_unchanged_p8": true,
	"commit_deferred_p8": true, "commit_validation_p8": true, "commit_failed_p8": true,
	"stats_0_p4": true, "stats_1_p4": true, "stats_2_p4": true,
	"rules_1_p4": true, "rules_2_p4": true,
	"occupied_p3":               true,
	"cidr_add_p3":               true,
	"cidr_occupied_p3":          true,
	"different_p3":              true,
	"cidr_batch_different_p3":   true,
	"batch_conflict_invalid_p3": true,
	"batch_occupied_pair_p3":    true,
	"cidr_batch_conflict_p3":    true,
	"atomic_duplicate_key_p8":   true,
	"put_updated_p3":            true,
	"put_unchanged_p3":          true,
	"put_key_different_p3":      true,
	"cidr_put_updated_p3":       true,
	"cidr_put_unchanged_p3":     true,
	"cidr_put_key_different_p3": true,
	"put_state_unconfirmed_p3":  true,
	"put_internal_p3":           true,

	"add":                      true,
	"atomic_0_p8":              true,
	"atomic_1_p8":              true,
	"atomic_2_p8":              true,
	"atomic_bad_json_p8":       true,
	"atomic_config_error_p8":   true,
	"atomic_duplicate_key":     true,
	"atomic_flip_error_p8":     true,
	"atomic_invalid_p8":        true,
	"atomic_kernel_error_p8":   true,
	"atomic_partial_p8":        true,
	"batch_add":                true,
	"batch_conflict_invalid":   true,
	"batch_delete":             true,
	"batch_different":          true,
	"batch_different_internal": true,
	"batch_exists":             true,
	"batch_internal":           true,
	"batch_internal_pair":      true,
	"batch_invalid_pair":       true,
	"batch_missing":            true,
	"batch_occupied_pair":      true,
	"batch_rollback_duplicate": true,
	"cidr_add":                 true,
	"cidr_batch_add":           true,
	"cidr_batch_conflict":      true,
	"cidr_batch_different":     true,
	"cidr_batch_exists":        true,
	"cidr_different":           true,
	"cidr_exists":              true,
	"cidr_occupied":            true,
	"cidr_prefix_different":    true,
	"cidr_put_key_different":   true,
	"cidr_put_missing":         true,
	"cidr_put_unchanged":       true,
	"cidr_put_updated":         true,
	"delete":                   true,
	"different":                true,
	"exists":                   true,
	"missing":                  true,
	"occupied":                 true,
	"put_internal":             true,
	"put_key_different":        true,
	"put_missing":              true,
	"put_state_unconfirmed":    true,
	"put_unchanged":            true,
	"put_updated":              true,
}
