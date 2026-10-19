//go:build linux && integration

package api

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestB1Cut5AProductionQuiescer(t *testing.T) {
	created, updates, returned, matches, frozenErrors, unpinned := 0, 0, 0, 0, 0, 0
	q, err := newKernelQuiescer()
	if err != nil {
		t.Fatal(err)
	}
	created++
	defer q.Close()
	for _, m := range []*ebpf.Map{q.outer, q.inner} {
		info, e := m.Info()
		if e != nil {
			t.Fatal(e)
		}
		if info.MaxEntries != 1 {
			t.Fatal("receipt is not single-slot")
		}
		if m.IsPinned() {
			t.Fatal("receipt map is pinned")
		}
		unpinned++
	}
	if q.outer.Type() != ebpf.ArrayOfMaps {
		t.Fatal("receipt outer is not ARRAY_OF_MAPS")
	}
	innerInfo, err := q.inner.Info()
	if err != nil {
		t.Fatal(err)
	}
	innerID, ok := innerInfo.ID()
	if !ok || innerID == 0 {
		t.Fatal("receipt inner map ID unavailable")
	}
	for i := 0; i < 3; i++ {
		err := q.Quiesce()
		returned++
		if err != nil {
			t.Fatalf("production receipt Update %d: %v", i, err)
		}
		var got uint32
		if err := q.outer.Lookup(uint32(0), &got); err != nil || got != uint32(innerID) {
			t.Fatalf("receipt slot 0 does not contain inner map ID: call=%d got=%d want=%d error=%v", i+1, got, innerID, err)
		}
		updates++
		matches++
	}
	// A cached nil after the first successful Update must not mask later errors.
	if err := q.outer.Freeze(); err != nil {
		t.Fatal(err)
	}
	err = q.Quiesce()
	returned++
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("receipt did not attempt Update on frozen outer map: error=%v", err)
	}
	frozenErrors++
	t.Logf("B1_CUT5A_RECEIPT create=%d update=%d returned=%d slot_id_matches=%d frozen_update_errors=%d unpinned_maps=%d", created, updates, returned, matches, frozenErrors, unpinned)
}

func TestB1Cut5AStartupFailClosed(t *testing.T) {
	if os.Getenv("XDROP_CUT5A_STARTUP_CHILD") == "1" {
		newQuiescer = func() (quiescer, error) { return nil, errors.New("cut5a injected private receipt creation failure") }
		// This is the same production constructor called by main, before its
		// config setup and before startup synchronization. Nil maps prove that
		// the fatal result came from receipt creation, not later setup.
		NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		t.Fatal("startup continued after receipt creation failure")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestB1Cut5AStartupFailClosed$")
	cmd.Env = append(os.Environ(), "XDROP_CUT5A_STARTUP_CHILD=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("[NewHandlers] Failed to create quiescence receipt: cut5a injected")) || bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("production startup fail-closed: err=%v output=%s", err, out)
	}
	t.Log("B1_CUT5A_STARTUP creation_failure=1 refused=1")
}

func cut5Keys(t *testing.T, m *ebpf.Map) map[uint32]bool {
	t.Helper()
	out := map[uint32]bool{}
	var cursor interface{}
	for {
		var k uint32
		err := m.NextKey(cursor, &k)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		out[k] = true
		cursor = k
	}
	return out
}
func cut5SeedLogical(t *testing.T, h *Handlers, ids ...uint32) {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*ebpf.Map{h.idCounts, h.idRLStates} {
		for _, id := range ids {
			width := int(m.ValueSize())
			values := atomicBatchBuffer(uint32(width), cpus)
			for cpu := 0; cpu < cpus; cpu++ {
				values.Index(cpu).Index(0).SetUint(uint64(byte(id)))
			}
			if err := m.Put(id, values.Interface()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestB1Cut5AReceiptSequence(t *testing.T) {
	h, _ := jiaHandler(t)
	var trace []string
	proof, flipped, released := false, false, false
	wlStart := -1
	fail := false
	atomicStageTestHook = func(stage string, got *Handlers) {
		if got != h {
			return
		}
		trace = append(trace, stage)
		switch stage {
		case "3a":
			if !proof {
				t.Fatalf("R0 missing before 3a after most recent flip: %v", trace)
			}
		case "flip":
			proof = false
			flipped = true
			released = false
		case "5b":
			released = true
		case "6":
			if !proof || !h.quiescenceConfirmed {
				t.Fatalf("Step 6 without successful R5c: %v", trace)
			}
		}
	}
	defer func() { atomicStageTestHook = nil }()
	h.quiescer = cut5ReceiptFunc(func() error {
		if h.syncMu.TryLock() {
			h.syncMu.Unlock()
			t.Fatal("receipt released syncMu")
		}
		if h.publishMu.TryLock() {
			h.publishMu.Unlock()
			t.Fatal("receipt released publishMu")
		}
		if wlStart < 0 && flipped && !released {
			t.Fatalf("R5c before 5b: %v", trace)
		}
		label := "R0"
		if wlStart < 0 && flipped || wlStart >= 0 && h.activeSlot != wlStart {
			label = "R5c"
		}
		trace = append(trace, label)
		if fail {
			return errors.New("injected receipt failure")
		}
		proof = true
		return nil
	})
	run := func(rules []Rule, wantError bool) {
		t.Helper()
		flipped, released = false, false
		_, err := h.DoAtomicSync(rules)
		if (err != nil) != wantError {
			t.Fatalf("sync err=%v wantError=%v trace=%v", err, wantError, trace)
		}
	}
	plain := Rule{LogicalID: 544001, ID: "pure", SrcIP: "203.0.113.1", Action: "drop"}
	wlStart = h.activeSlot
	if err := h.DoWhitelistAtomicSync([]SyncWhitelistEntry{{ID: "w", SrcIP: "192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	wlStart = -1
	if strings.Join(trace, ",") != "R0,R5c" || !h.quiescenceConfirmed {
		t.Fatalf("whitelist receipt sequence=%v", trace)
	}
	trace = nil
	a := Rule{ID: "a", SrcCIDR: "192.0.2.0/24", Action: "drop", LogicalID: 3}
	b := Rule{ID: "b", SrcCIDR: "198.51.100.0/24", Action: "drop", LogicalID: 7}
	run([]Rule{a}, false)
	if strings.Join(trace, ",") != "1,3a,flip,5b,R5c,6" {
		t.Fatalf("first operation sequence=%v", trace)
	}
	// A/B reuse twice; each opposite config reuse has a successful receipt
	// after its latest flip, even when this round does not need another R0.
	for _, r := range []Rule{b, a} {
		trace = nil
		run([]Rule{r}, false)
		if strings.Join(trace, ",") != "1,3a,flip,5b,R5c,6" {
			t.Fatalf("A/B reuse sequence=%v", trace)
		}
	}
	for _, increment := range []string{"whitelist"} {
		t.Run(increment, func(t *testing.T) {
			trace = nil
			wlStart = h.activeSlot
			if err := h.DoWhitelistAtomicSync([]SyncWhitelistEntry{{ID: "w", SrcIP: "192.0.2.3"}}); err != nil {
				t.Fatal(err)
			}
			wlStart = -1
			if strings.Join(trace, ",") != "R5c" || !h.quiescenceConfirmed {
				t.Fatalf("confirmed whitelist receipt sequence=%v", trace)
			}
			trace = nil
			run([]Rule{b}, false)
			if strings.Join(trace, ",") != "1,3a,flip,5b,R5c,6" {
				t.Fatalf("rule sync after confirmed whitelist=%v", trace)
			}
		})
	}
	// A whitelist publication, failed atomic flip, then another full sync.
	wlStart = h.activeSlot
	if err := h.DoWhitelistAtomicSync([]SyncWhitelistEntry{{ID: "w", SrcIP: "192.0.2.4"}}); err != nil {
		t.Fatal(err)
	}
	wlStart = -1
	trace = nil
	restore := dingFreezeFlip(t, h)
	run([]Rule{a}, true)
	restore()
	if strings.Join(trace, ",") != "1,3a" {
		t.Fatalf("failed flip sequence=%v", trace)
	}
	trace = nil
	run([]Rule{a}, false)
	// Shadow construction failure happens after R0 but never flips or reclaims.
	h.publishMu.Lock()
	h.quiescenceConfirmed = false
	h.publishMu.Unlock()
	proof = false
	trace = nil
	saved := h.shadowBlacklist()
	closed := b7Map(t, ebpf.Hash, 40, 32)
	closed.Close()
	if int(h.activeRuleSlot.Load()) == 0 {
		h.blacklistB = closed
	} else {
		h.blacklist = closed
	}
	run([]Rule{plain}, true)
	if int(h.activeRuleSlot.Load()) == 0 {
		h.blacklistB = saved
	} else {
		h.blacklist = saved
	}
	if strings.Join(trace, ",") != "R0,1" {
		t.Fatalf("shadow construction failure sequence=%v", trace)
	}
	trace = nil
	run([]Rule{b}, false)
	// R5c failure preserves the pending marker and forbids Step 6; next round
	// must repay at R0 before it can reuse either shadow table or config.
	trace = nil
	fail = true
	run([]Rule{a}, false)
	if strings.Join(trace, ",") != "1,3a,flip,5b,R5c,R5c,R5c" || h.quiescenceConfirmed {
		t.Fatalf("R5c failure sequence=%v confirmed=%v", trace, h.quiescenceConfirmed)
	}
	trace = nil
	fail = false
	run([]Rule{b}, false)
	if strings.Join(trace, ",") != "R0,1,3a,flip,5b,R5c,6" {
		t.Fatalf("deferred R0 repayment=%v", trace)
	}
	t.Log("B1_CUT5A_SEQUENCE whitelist_flip=3 reuse=2 flip_failure=1 shadow_failure=1 R5c_failure=1 recovered=1")
}

func TestB1Cut5AR0FailureNoWrites(t *testing.T) {
	h, _ := jiaHandler(t)
	maps := []*ebpf.Map{h.blacklist, h.blacklistB, h.cidrBlacklist, h.cidrBlacklistB, h.condA, h.condB, h.cidrCondA, h.cidrCondB, h.configA, h.configB, h.activeConfig}
	before := []map[string]string{}
	for _, m := range maps {
		before = append(before, b7Snapshot(t, m))
	}
	calls := 0
	h.quiescer = cut5ReceiptFunc(func() error { calls++; return errors.New("R0 failure") })
	result, err := h.DoAtomicSync([]Rule{{LogicalID: 544003, ID: "r", SrcIP: "192.0.2.1", Action: "drop"}})
	if !errors.Is(err, errQuiescence) || result.Added != 0 || calls != 3 || h.quiescenceConfirmed {
		t.Fatalf("R0 result=%+v err=%v calls=%d", result, err, calls)
	}
	for i, m := range maps {
		if !reflect.DeepEqual(before[i], b7Snapshot(t, m)) {
			t.Fatalf("R0 failure changed table %d", i)
		}
	}
}

func TestB1Cut5AConditionReclamation(t *testing.T) {
	h, _ := jiaHandler(t)
	for _, m := range []*ebpf.Map{h.condA, h.condB, h.cidrCondA, h.cidrCondB} {
		v := make([]byte, m.ValueSize())
		v[0] = 1
		if err := m.Put(make([]byte, m.KeySize()), v); err != nil {
			t.Fatal(err)
		}
	}
	seenBuild, seenCleanup := false, false
	atomicStageTestHook = func(stage string, got *Handlers) {
		if got != h {
			return
		}
		if stage == "3a" {
			seenBuild = true
			if len(b7Snapshot(t, h.shadowCond())) != 0 || len(b7Snapshot(t, h.shadowCidrCond())) != 0 {
				t.Fatal("Step 1 left shadow conditions")
			}
			if len(b7Snapshot(t, h.activeCond())) != 1 || len(b7Snapshot(t, h.activeCidrCond())) != 1 {
				t.Fatal("Step 1 cleared active conditions")
			}
		}
		if stage == "6" {
			seenCleanup = true
			if !h.quiescenceConfirmed {
				t.Fatal("condition reclamation lacks receipt")
			}
			if len(b7Snapshot(t, h.shadowCond())) != 1 || len(b7Snapshot(t, h.shadowCidrCond())) != 1 {
				t.Fatal("old conditions cleared before Step 6")
			}
		}
	}
	defer func() { atomicStageTestHook = nil }()
	if _, err := h.DoAtomicSync(nil); err != nil {
		t.Fatal(err)
	}
	if !seenBuild || !seenCleanup {
		t.Fatal("condition lifecycle not reached")
	}
	for _, m := range []*ebpf.Map{h.condA, h.condB, h.cidrCondA, h.cidrCondB} {
		if len(b7Snapshot(t, m)) != 0 {
			t.Fatal("Step 6 left retired conditions")
		}
	}
}

func TestB1Cut5AStartupPending(t *testing.T) {
	h, _ := jiaHandler(t)
	oldFactory := newQuiescer
	newQuiescer = func() (quiescer, error) { return cut5ReceiptFunc(func() error { return nil }), nil }
	defer func() { newQuiescer = oldFactory }()
	started := NewHandlers(h.blacklist, nil, nil, nil, h.configA, h.configB, h.activeConfig,
		h.cidrBlacklist, h.cidrMgr, h.blacklistB, h.cidrBlacklistB, nil, h.idCounts,
		h.condA, h.condB, h.cidrCondA, h.cidrCondB, h.idRLStates, h.condRowMissing)
	defer started.Shutdown()
	if started.quiescenceConfirmed {
		t.Fatal("startup selector flip failed to leave receipt pending")
	}
	if started.activeCond() != h.condA || started.activeCidrCond() != h.cidrCondA || started.idRLStates != h.idRLStates {
		t.Fatal("startup lost condition/state handles")
	}
}

func TestB1Cut5ALogicalReconciliation(t *testing.T) {
	h, _ := jiaHandler(t)
	old := Rule{ID: "old", SrcIP: "192.0.2.1", Action: "drop", LogicalID: 3}
	active := Rule{ID: "live", SrcIP: "198.51.100.1", Action: "drop", LogicalID: 7}
	if _, err := h.DoAtomicSync([]Rule{old}); err != nil {
		t.Fatal(err)
	}
	cut5SeedLogical(t, h, 3, 7, 99)
	h.quiescer = cut5ReceiptFunc(func() error { return errors.New("R5c failure") })
	if _, err := h.DoAtomicSync([]Rule{active}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*ebpf.Map{h.idCounts, h.idRLStates} {
		if !reflect.DeepEqual(cut5Keys(t, m), map[uint32]bool{3: true, 7: true, 99: true}) {
			t.Fatal("R5c failure deleted logical state")
		}
	}
	if len(b7Snapshot(t, h.shadowBlacklist())) != 1 {
		t.Fatal("R5c failure cleared old generation")
	}
	h.quiescer = cut5ReceiptFunc(func() error { return nil })
	if _, err := h.DoAtomicSync([]Rule{active}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*ebpf.Map{h.idCounts, h.idRLStates} {
		if !reflect.DeepEqual(cut5Keys(t, m), map[uint32]bool{7: true}) {
			t.Fatalf("stale actual key survived deferred reconciliation: %v", cut5Keys(t, m))
		}
		cpus, err := ebpf.PossibleCPU()
		if err != nil {
			t.Fatal(err)
		}
		v := atomicBatchBuffer(m.ValueSize(), cpus)
		if err := m.Lookup(uint32(7), v.Interface()); err != nil {
			t.Fatal(err)
		}
		for cpu := 0; cpu < cpus; cpu++ {
			if v.Index(cpu).Index(0).Uint() != 7 {
				t.Fatal("valid logical state was changed")
			}
		}
	}
	if !reflect.DeepEqual(b7Snapshot(t, h.shadowBlacklist()), b7Snapshot(t, p7ActiveBlacklist(h))) {
		t.Fatal("old generation not mirrored after recovery")
	}
	t.Log("B1_CUT5A_RECONCILE tables=2 retained=2 stale_removed=4 deferred_round=1 recovery_round=1")
}
