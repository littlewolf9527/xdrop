//go:build linux && integration

package api

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

func capacityRig(t *testing.T, small bool) (*Handlers, *gin.Engine, *ebpf.Collection) {
	t.Helper()
	var whitelist *ebpf.MapSpec
	h, router, _, coll := prefixABCollection(t, func(spec *ebpf.CollectionSpec) {
		for i, pair := range [][2]string{{"blacklist", "blacklist_b"}, {"cidr_blacklist", "cidr_blist_b"}, {"cond_a", "cond_b"}, {"cidr_cond_a", "cidr_cond_b"}, {"whitelist", "whitelist"}, {"sv4_cidr_trie", "sv4_cidr_trie_b"}, {"dv4_cidr_trie", "dv4_cidr_trie_b"}, {"sv6_cidr_trie", "sv6_cidr_trie_b"}, {"dv6_cidr_trie", "dv6_cidr_trie_b"}, {"id_counts", "id_rl_states"}} {
			if small {
				for _, name := range pair {
					spec.Maps[name].MaxEntries = uint32(32 + i)
				}
			}
		}
		whitelist = spec.Maps["whitelist"].Copy()
	})
	h.whitelist = coll.Maps["whitelist"]
	var err error
	h.whitelistB, err = ebpf.NewMap(whitelist)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.whitelistB.Close() })
	return h, router, coll
}

func capacityRules() []Rule {
	var rules []Rule
	for n := 1; n <= 4; n++ {
		r := cut55Rule(fmt.Sprint("r", n), uint32(n), "192.0.2.1")
		r.TTL = cut4BString(fmt.Sprint(60 + n))
		rules = append(rules, r)
	}
	r := cut55Rule("r5", 5, "192.0.2.2")
	r.TTL = cut4BString("70")
	rules = append(rules, r)
	for n := 6; n <= 7; n++ {
		rules = append(rules, Rule{ID: fmt.Sprint("r", n), LogicalID: uint32(n), SrcCIDR: "198.51.100.0/24", DstCIDR: "203.0.113.0/24", DstPort: uint16(n), Protocol: "tcp", Action: "drop", TTL: cut4BString("64")})
	}
	return append(rules, Rule{ID: "r8", LogicalID: 8, SrcCIDR: "2001:db8:1::/64", DstCIDR: "2001:db8:2::/64", Action: "drop", DSCP: cut4BString("3")})
}

func capacityAtomic(t *testing.T, h *Handlers, rules []Rule) {
	t.Helper()
	result, err := h.DoAtomicSync(rules)
	if err != nil || result.Failed != 0 || result.Added != len(rules) {
		t.Fatalf("atomic result=%+v error=%v", result, err)
	}
}

func capacityRead(t *testing.T, router *gin.Engine) CapacityReport {
	t.Helper()
	done := make(chan *CapacityReport, 1)
	go func() {
		w := jiaCall(t, router, "GET", "/api/v1/stats", "")
		var stats Stats
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &stats) != nil {
			done <- nil
			return
		}
		done <- stats.Capacity
	}()
	select {
	case report := <-done:
		if report == nil {
			t.Fatal("capacity missing")
		}
		return *report
	case <-time.After(200 * time.Millisecond):
		t.Fatal("capacity stats blocked beyond 200 ms")
		return CapacityReport{}
	}
}

func capacityKernel(t *testing.T, h *Handlers, router *gin.Engine, coll *ebpf.Collection, distinctTries ...[4]int) CapacityReport {
	t.Helper()
	var active, ruleSlot, wlSlot uint64
	if err := coll.Maps["active_config"].Lookup(uint32(0), &active); err != nil || active > 1 {
		t.Fatal("kernel active selector", active, err)
	}
	config := coll.Maps[[]string{"config_a", "config_b"}[active]]
	if err := config.Lookup(uint32(ConfigRuleMapSelector), &ruleSlot); err != nil || ruleSlot > 1 {
		t.Fatal("kernel rule selector", ruleSlot, err)
	}
	if err := config.Lookup(uint32(ConfigWLMapSelector), &wlSlot); err != nil || wlSlot > 1 {
		t.Fatal("kernel whitelist selector", wlSlot, err)
	}
	report := capacityRead(t, router)
	entries := report.entries()
	var trieUsed [4]int
	for i, pair := range [][2]string{{"blacklist", "blacklist_b"}, {"cidr_blacklist", "cidr_blist_b"}, {"cond_a", "cond_b"}, {"cidr_cond_a", "cidr_cond_b"}, {"", ""}, {"sv4_cidr_trie", "sv4_cidr_trie_b"}, {"dv4_cidr_trie", "dv4_cidr_trie_b"}, {"sv6_cidr_trie", "sv6_cidr_trie_b"}, {"dv6_cidr_trie", "dv6_cidr_trie_b"}} {
		table := coll.Maps[pair[ruleSlot]]
		if i == 4 {
			table = []*ebpf.Map{h.whitelist, h.whitelistB}[wlSlot]
		}
		used := len(cut53KernelMapBytes(t, table)) // NextKey and Lookup failures are fatal.
		if i >= 5 {
			trieUsed[i-5] = used
		}
		if *entries[i] != (CapacityEntry{int(table.MaxEntries()), used}) {
			t.Fatalf("%s report=%+v kernel_limit=%d kernel_used=%d", capacityKeys[i], entries[i], table.MaxEntries(), used)
		}
	}
	if report.LogicalState.Limit != h.logicalCapacity() {
		t.Fatal("logical limit", report.LogicalState)
	}
	if len(distinctTries) != 0 {
		if trieUsed != distinctTries[0] {
			t.Fatal("asymmetric kernel trie counts", trieUsed, distinctTries[0])
		}
		for i, used := range trieUsed {
			for j := 0; j < i; j++ {
				if used == trieUsed[j] {
					t.Fatal("kernel trie counts must be pairwise distinct", trieUsed)
				}
			}
		}
		t.Logf("CAP_ASYMMETRIC_TRIES sv4=%d dv4=%d sv6=%d dv6=%d", trieUsed[0], trieUsed[1], trieUsed[2], trieUsed[3])
	}
	return report
}

func capacityR5cAttempts(t *testing.T) int {
	t.Helper()
	source, err := os.ReadFile("quiescence.go")
	if err != nil {
		t.Fatal(err)
	}
	loop := regexp.MustCompile(`(?s)func \(h \*Handlers\) awaitQuiescence\(\) error \{.*?for attempt := 0; attempt < ([0-9]+); attempt\+\+`).FindSubmatch(source)
	if len(loop) != 2 {
		t.Fatal("awaitQuiescence retry loop not found")
	}
	attempts, err := strconv.Atoi(string(loop[1]))
	if err != nil || attempts < 1 {
		t.Fatal("invalid awaitQuiescence retry count", attempts, err)
	}
	t.Logf("CAP_R5C_ATTEMPTS source=awaitQuiescence attempts=%d", attempts)
	return attempts
}

func capacityPending(t *testing.T) (*Handlers, *gin.Engine, *ebpf.Collection) {
	t.Helper()
	h, router, coll := capacityRig(t, false)
	a, b, c := cut55Rule("a", 1, "192.0.2.1"), cut55Rule("b", 2, "192.0.2.2"), cut55Rule("c", 3, "192.0.2.3")
	capacityAtomic(t, h, []Rule{a, b})
	hits := 0
	restore := flipBReceipt(t, h, func() error { hits++; return fmt.Errorf("capacity R5c injection") })
	capacityAtomic(t, h, []Rule{b, c})
	restore()
	if hits != capacityR5cAttempts(t) || len(h.logicalOwners) != 2 || len(h.pendingLogicalIDs) != 1 || !h.pendingLogicalIDs[1] || h.logicalRetireThreshold != 0 {
		t.Fatal("pending witness", hits, h.logicalOwners, h.pendingLogicalIDs)
	}
	return h, router, coll
}

func TestCapacityELF(t *testing.T) {
	t.Run("CR-atomic", func(t *testing.T) {
		h, router, coll := capacityRig(t, false)
		capacityAtomic(t, h, capacityRules())
		r := capacityKernel(t, h, router, coll)
		if r.Blacklist.Used != 2 || r.Cond.Used != 2 || r.CIDRBlacklist.Used != 3 || r.CIDRCond.Used != 3 || r.LogicalState.Used != 8 {
			t.Fatal("row/member witness", r)
		}
		for i, entry := range r.entries() {
			if i >= 5 && i < 9 && entry.Used != 1 {
				t.Fatal("distinct shared-prefix witness", r)
			}
		}
		rules := append(capacityRules(), Rule{ID: "asym-v4", LogicalID: 9, SrcCIDR: "198.51.100.0/24", DstCIDR: "192.0.2.0/24", Action: "drop"})
		for n := 1; n <= 3; n++ {
			rules = append(rules, Rule{
				ID: fmt.Sprint("asym-v6-", n), LogicalID: uint32(9 + n),
				SrcCIDR: fmt.Sprintf("2001:db8:%x::/64", 3+n%2),
				DstCIDR: fmt.Sprintf("2001:db8:%x::/64", 4+n), Action: "drop",
			})
		}
		capacityAtomic(t, h, rules)
		capacityKernel(t, h, router, coll, [4]int{1, 2, 3, 4})
	})
	t.Run("CR-commit", func(t *testing.T) {
		h, router, coll := capacityRig(t, false)
		rules := capacityRules()
		capacityAtomic(t, h, rules)
		old := capacityKernel(t, h, router, coll)
		changed := rules[0]
		changed.TTL = cut4BString("80")
		a, b := cut55Rule("a", 9, "192.0.2.9"), cut55Rule("b", 10, "192.0.2.10")
		cut55Commit(t, h, cut55Group(t, h, rules[4]), cut55Group(t, h, changed, changed), cut55Group(t, h, a, a), cut55Group(t, h, b, b))
		got := capacityKernel(t, h, router, coll)
		if old.Blacklist.Used == got.Blacklist.Used || got.Blacklist.Used != 3 || got.Cond.Used != 1 {
			t.Fatal("commit add/delete/change row witness", old, got)
		}
	})
	t.Run("CR-wl", func(t *testing.T) {
		h, router, coll := capacityRig(t, false)
		capacityAtomic(t, h, capacityRules())
		old := capacityKernel(t, h, router, coll)
		if err := h.DoWhitelistAtomicSync([]SyncWhitelistEntry{{ID: "w1", SrcIP: "192.0.2.11"}, {ID: "w2", SrcIP: "192.0.2.12"}}); err != nil {
			t.Fatal(err)
		}
		got := capacityKernel(t, h, router, coll)
		if got.Whitelist.Used != 2 {
			t.Fatal("nonempty whitelist witness", got)
		}
		got.Whitelist = old.Whitelist
		if got != old {
			t.Fatal("whitelist changed rule capacity")
		}
	})
	t.Run("CR-logical", func(t *testing.T) {
		h, router, _ := capacityRig(t, false)
		a, b := cut55Rule("a", 1, "192.0.2.1"), cut55Rule("b", 2, "192.0.2.2")
		capacityAtomic(t, h, []Rule{a, b})
		if got := capacityRead(t, router).LogicalState.Used; got != 2 {
			t.Fatal("atomic logical usage", got)
		}
		c, d := cut55Rule("c", 3, "192.0.2.3"), cut55Rule("d", 4, "192.0.2.4")
		cut55Commit(t, h, cut55Group(t, h, c, c), cut55Group(t, h, d, d))
		if got := capacityRead(t, router).LogicalState.Used; got != 4 || len(h.pendingLogicalIDs) != 0 {
			t.Fatal("commit logical usage", got, h.pendingLogicalIDs)
		}
		h.logicalStateCapacity = capacityRead(t, router).LogicalState.Used
		e := cut55Rule("e", 5, "192.0.2.5")
		w := cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, e, e)})
		var body struct {
			Code   string
			Groups []struct {
				Table  string
				Excess int
			}
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 409 || body.Code != "table_full" || len(body.Groups) != 1 || body.Groups[0].Table != "logical_state" || body.Groups[0].Excess != 1 {
			t.Fatal("logical admission disagreement", w.Code, w.Body.String(), err)
		}
	})
	t.Run("CR-logical-pending", func(t *testing.T) {
		h, router, _ := capacityPending(t)
		if got := capacityRead(t, router).LogicalState.Used; got != 3 || got == len(h.logicalOwners) {
			t.Fatal("pending omitted", got)
		}
	})
	t.Run("CR-logical-paid", func(t *testing.T) {
		h, router, _ := capacityPending(t)
		before, payments := len(h.logicalOwners)+len(h.pendingLogicalIDs)+1, h.logicalPayments
		h.logicalStateCapacity = 3
		d := cut55Rule("d", 4, "192.0.2.4")
		cut55Commit(t, h, cut55Group(t, h, d, d))
		after := capacityRead(t, router).LogicalState.Used
		if before != 4 || after != 3 || before == after || len(h.pendingLogicalIDs) != 0 || h.logicalPayments != payments+1 {
			t.Fatal("admission payment witness", before, after, payments, h.logicalPayments, h.pendingLogicalIDs)
		}
	})
	t.Run("CR-limit", func(t *testing.T) {
		h, router, coll := capacityRig(t, true)
		capacityAtomic(t, h, capacityRules())
		r := capacityKernel(t, h, router, coll)
		for i, entry := range r.entries() {
			if entry.Limit != 32+i {
				t.Fatalf("real map limit %s=%d want=%d", capacityKeys[i], entry.Limit, 32+i)
			}
		}
	})
	t.Run("CR-r5c", func(t *testing.T) {
		h, router, coll := capacityRig(t, false)
		hits := 0
		restore := flipBReceipt(t, h, func() error { hits++; return fmt.Errorf("capacity R5c injection") })
		capacityAtomic(t, h, capacityRules())
		restore()
		r := capacityKernel(t, h, router, coll)
		if hits != capacityR5cAttempts(t) || h.ruleRowCountsKnown || h.ruleRowCounts[2] != 0 || h.ruleRowCounts[3] != 0 || r.Cond.Used == 0 || r.CIDRCond.Used == 0 {
			t.Fatal("R5c condition witness", hits, h.ruleRowCountsKnown, h.ruleRowCounts, r)
		}
	})
	t.Run("CR-midwrite", capacityMidwrite)
	t.Run("CR-golden", capacityGolden)
}

func capacityPrefixes(start, count int) []Rule {
	var rules []Rule
	for n := start; n < start+count; n++ {
		for family := 0; family < 2; family++ {
			src, dst := fmt.Sprintf("10.20.%d.0/24", n), fmt.Sprintf("10.21.%d.0/24", n)
			if family == 1 {
				src, dst = fmt.Sprintf("2001:db8:20:%x::/64", n), fmt.Sprintf("2001:db8:21:%x::/64", n)
			}
			id := uint32(2*n + family)
			rules = append(rules, Rule{ID: fmt.Sprint(id), LogicalID: id, SrcCIDR: src, DstCIDR: dst, Action: "drop"})
		}
	}
	return rules
}

func capacityMidwrite(t *testing.T) {
	h, router, _ := capacityRig(t, false)
	capacityAtomic(t, h, capacityPrefixes(1, 1))
	stages, release := make(chan string, 2), make(chan struct{})
	t.Cleanup(func() { close(release); cidrBeforeAtomicPublishTestHook = nil; atomicStageTestHook = nil })
	pause := func(stage string) { stages <- stage; <-release }
	cidrBeforeAtomicPublishTestHook = func(owner *Handlers) {
		if owner == h {
			pause("reserved")
		}
	}
	atomicStageTestHook = func(stage string, owner *Handlers) {
		if owner == h && stage == "flip" {
			pause("published")
		}
	}
	done := make(chan error, 1)
	go func() {
		result, err := h.DoAtomicSync(capacityPrefixes(2, 2))
		if err == nil && result.Failed != 0 {
			err = fmt.Errorf("unexpected rejected rules: %d", result.Failed)
		}
		done <- err
	}()
	for _, stage := range []string{"reserved", "published"} {
		select {
		case got := <-stages:
			if got != stage {
				t.Fatal("pause order", got, stage)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("writer did not reach", stage)
		}
		union := h.cidrMgr.CountsAfter([2]map[string]int{})
		r := capacityRead(t, router)
		want := 1
		if stage == "published" {
			want = 2
		}
		entries := r.entries()
		for i, e := range entries[5:9] {
			if union[i] != 3 || e.Used != want || e.Used == union[i] {
				t.Fatal("published prefix count versus reserved union", stage, i, e, union)
			}
		}
		release <- struct{}{}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func capacityGolden(t *testing.T) {
	// Response bytes have one owner each: welcome, Jia snapshots, and AFE12.
	// This leaf checks case registration only; it must not invent a second scene.
	for _, name := range []string{"welcome_p10", "stats_0_p10", "stats_1_p10", "stats_2_p10", "stats_slot5_p9", "welcome_p11", "stats_0_p11", "stats_1_p11", "stats_2_p11", "stats_slot5_p11", "rules_1_p11", "rules_2_p11"} {
		key := "TestJiaHandlerGolden/SnapshotsAndWhitelist"
		if name == "welcome_p10" || name == "welcome_p11" {
			key = "TestBingWelcomeGolden"
		} else if name == "stats_slot5_p9" || name == "stats_slot5_p11" {
			key = "TestAFE12"
		} else if !prefixABWritableGolden[name] || !dingWritableGolden[name] {
			t.Fatal("unregistered p10 snapshot", name)
		}
		raw, err := os.ReadFile("../testdata/sync-jia/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var cases map[string]cut53GoldenResponse
		if err := json.Unmarshal(raw, &cases); err != nil {
			t.Fatal(err)
		}
		if _, ok := cases[key]; !ok || len(cases) != 1 {
			t.Fatalf("%s must have exactly the owner case %s", name, key)
		}
		t.Logf("CAP_GOLDEN_OWNER file=%s case=%s", name, key)
	}
}
