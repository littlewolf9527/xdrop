package api

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// Check the preflight row/bitmap snapshots after step 3 retires a prefix and
// step 4 allocates a new ID. Shared by memory and real-map witnesses.
func cut55R1Counts(t *testing.T, h *Handlers) {
	t.Helper()
	var rows [4]int
	for kind := range rows {
		snapshot, err := mirrorSnapshot(h.mirrorTable(int(h.activeRuleSlot.Load()), kind))
		if err != nil {
			t.Fatal(err)
		}
		rows[kind] = len(snapshot)
	}
	if !h.ruleRowCountsKnown || h.ruleRowCounts != rows {
		t.Fatalf("R1 cached row counts differ from active maps: cached=%v actual=%v", h.ruleRowCounts, rows)
	}
	_, active, _ := h.configPublishTables()
	for _, item := range []struct {
		count, bitmap uint32
		refs          [64]int
		want          int
	}{
		{ConfigBlacklistCount, ConfigRuleBitmap, h.comboRefCount, len(h.rules)},
		{ConfigCIDRRuleCount, ConfigCIDRBitmap, h.cidrComboRefCount, len(h.cidrRules)},
	} {
		var count, bitmap, wantBitmap uint64
		sum := 0
		for i, n := range item.refs {
			if n > 0 {
				wantBitmap |= 1 << uint(i)
				sum += n
			}
		}
		if err := active.Lookup(item.count, &count); err != nil {
			t.Fatal(err)
		}
		if err := active.Lookup(item.bitmap, &bitmap); err != nil {
			t.Fatal(err)
		}
		if count != uint64(item.want) || sum != item.want || bitmap != wantBitmap {
			t.Fatalf("R1 config/member snapshots diverged: count=%d members=%d refs=%d bitmap=%x want=%x", count, item.want, sum, bitmap, wantBitmap)
		}
	}
}

func cut55R1Recreate(t *testing.T, h *Handlers, src bool, trieID func(int) (uint32, bool), mode string) Rule {
	t.Helper()
	h.logicalRetireThreshold, h.logicalStateCapacity = 16, 16
	h.commitTableCapacity = [4]int{1, 1, 1, 1}
	h.commitTrieCapacity = [4]int{1, 1, 1, 1}
	old := Rule{ID: "old", LogicalID: 71, Protocol: "tcp", Action: "drop"}
	if src {
		old.SrcCIDR = "192.0.2.0/24"
	} else {
		old.DstCIDR = "192.0.2.0/24"
	}
	unrelated := cut55Rule("unrelated", 73, "203.0.113.73")
	seed := cut55Commit(t, h, cut55Group(t, h, old, old), cut55Group(t, h, unrelated, unrelated))
	if seed.Code != "committed" || seed.Receipt != "confirmed" || !h.quiescenceConfirmed {
		t.Fatal("R1 prefix seed not confirmed")
	}
	oldSlot := int(h.activeRuleSlot.Load())
	oldID, ok := trieID(oldSlot)
	if !ok || oldID == 0 {
		t.Fatal("R1 prefix seed not published")
	}
	exactBefore, err := mirrorSnapshot(h.mirrorTable(int(h.activeRuleSlot.Load()), mirrorExact))
	if err != nil {
		t.Fatal(err)
	}
	receipt := h.quiescer
	h.quiescer = cut5ReceiptFunc(func() error { return errors.New("R1 delete Rc failure") })
	deleted := cut55Commit(t, h, cut55Group(t, h, old))
	if deleted.Code != "committed" || deleted.Receipt != "deferred" || h.quiescenceConfirmed {
		t.Fatal("R1 deferred delete did not leave the old copy intact")
	}
	if id, ok := trieID(oldSlot); !ok || id != oldID {
		t.Fatal("R1 deferred prefix withdrawn before receipt")
	}
	h.quiescer = receipt
	next := old
	next.ID, next.LogicalID = "new", 72
	prior := h.commitStageTestHook
	settled := false
	h.commitStageTestHook = func(stage string) {
		if prior != nil {
			prior(stage)
		}
		if stage == "c-3" {
			settled = true
			if _, exists := trieID(oldSlot); exists {
				t.Fatal("R1 old prefix was not removed from the shadow copy at c-3")
			}
		}
	}
	t.Cleanup(func() { h.commitStageTestHook = prior })
	result := cut55Commit(t, h, cut55Group(t, h, next, next))
	if !settled || result.Code != "committed" || result.Receipt != "confirmed" {
		t.Fatal("R1 prefix recreation did not reach confirmed commit")
	}
	stored, ok := h.cidrRules["new"]
	if !ok {
		t.Fatal("R1 new CIDR member absent")
	}
	row, err := readCommitRow(h.mirrorTable(int(h.activeRuleSlot.Load()), mirrorCIDR), cidrRuleKeyToBytes(stored.Key), true)
	if err != nil || len(row) != 32 || commitUint32(row[8:12]) != 72 {
		t.Fatalf("R1 new active CIDR row absent: %v", err)
	}
	wantID := stored.Key.DstID
	if src {
		wantID = stored.Key.SrcID
	}
	id, ok := trieID(int(h.activeRuleSlot.Load()))
	if !ok || id != wantID || id == oldID {
		t.Fatalf("R1 recreated prefix missing or wrong trie ID: published=%v trie=%d active=%d old=%d", ok, id, wantID, oldID)
	}
	var managerID uint32
	if src {
		managerID, ok = h.cidrMgr.GetSrcID(next.SrcCIDR)
	} else {
		managerID, ok = h.cidrMgr.GetDstID(next.DstCIDR)
	}
	if !ok || managerID != id {
		t.Fatal("R1 prefix Manager/active trie disagree")
	}
	exactAfter, err := mirrorSnapshot(h.mirrorTable(int(h.activeRuleSlot.Load()), mirrorExact))
	if err != nil || !reflect.DeepEqual(exactBefore, exactAfter) {
		t.Fatal("R1 prefix recreation changed unrelated exact bytes")
	}
	cut55R1Counts(t, h)
	t.Logf("CUT55_R1_PREFIX_RECREATE%s src=%v deferred=1 settled=1 id_changed=1 trie_matches_active=1 snapshot_counts=1", mode, src)
	return next
}

func TestCut55R1DeferredPrefixRecreate(t *testing.T) {
	for _, src := range []bool{true, false} {
		t.Run(fmt.Sprintf("src=%v", src), func(t *testing.T) {
			f := cut55Memory(t)
			direction := 1
			if src {
				direction = 0
			}
			read := func(slot int) (uint32, bool) {
				trie := f.tries[direction]
				if slot == 1 {
					trie = f.triesB[direction]
				}
				for _, id := range trie.rows {
					return id, true
				}
				return 0, false
			}
			cut55R1Recreate(t, f.h, src, read, "")
			cut55Mirror(t, f)
		})
	}
}

// Commit retirement with deferred Rc supplies real pending logical debt.
func cut55R1DeleteReceipt(t *testing.T, h *Handlers, seedBuckets func(), readBuckets func() [2][]byte, abort, deferred bool, mode string) {
	t.Helper()
	h.logicalRetireThreshold, h.logicalStateCapacity = 8, 8
	old := cut55Rule("old", 81, "192.0.2.81")
	seed := cut55Commit(t, h, cut55Group(t, h, old, old))
	if seed.Receipt != "confirmed" || !h.quiescenceConfirmed {
		t.Fatal("R1 delete seed requires confirmed receipt")
	}
	seedBuckets()
	before := readBuckets()
	if len(before[0]) == 0 || len(before[1]) == 0 {
		t.Fatal("R1 logical buckets not seeded")
	}
	receipt := h.quiescer
	h.quiescer = cut5ReceiptFunc(func() error { return errors.New("P7 retirement Rc failure") })
	retired := cut55Commit(t, h, cut55Group(t, h, old))
	if retired.Receipt != "deferred" || !h.pendingLogicalIDs[81] || h.quiescenceConfirmed {
		t.Fatal("P7 retirement did not retain real pending debt")
	}
	// A real R0 receipt followed by c-4 abort settles the mirror while preserving
	// logical debt. The witness below must still obtain its own Rc before reclaim.
	h.quiescer = receipt
	h.commitFaultTestHook = func(stage string) error {
		if stage == "c-4" {
			return errors.New("P7 preparation abort")
		}
		return nil
	}
	next := cut55Rule("new", 82, "10.20.100.82")
	_, prepErr := h.DoCommitRules([]CommitGroup{cut55Group(t, h, next, next)})
	h.commitFaultTestHook = nil
	if prepErr == nil || prepErr.Message != "P7 preparation abort" || !h.quiescenceConfirmed {
		t.Fatal("P7 preparation did not stop after confirmed R0", prepErr)
	}
	if _, exists := h.rules["old"]; exists || !h.pendingLogicalIDs[81] {
		t.Fatal("P7 retirement did not retain ID 81")
	}
	if rows, err := mirrorSnapshot(h.mirrorTable(int(h.activeRuleSlot.Load()), mirrorExact)); err != nil || len(rows) != 0 {
		t.Fatal("P7 retirement active rule still present", err)
	}
	if after := readBuckets(); !bytes.Equal(before[0], after[0]) || !bytes.Equal(before[1], after[1]) {
		t.Fatal("P7 retirement unexpectedly paid logical debt")
	}
	if len(h.pendingLogicalIDs) != 1 || h.logicalUnionLocked(map[uint32]bool{82: true}) != 2 {
		t.Fatal("R1 M5a/M5b guard would mask receipt witness")
	}
	fresh, successful := 0, 0
	h.quiescer = cut5ReceiptFunc(func() error {
		// Check inside the receipt boundary, after c-Rc's observation hook.
		v := readBuckets()
		if !h.pendingLogicalIDs[81] || !bytes.Equal(before[0], v[0]) || !bytes.Equal(before[1], v[1]) {
			t.Fatal("R2 logical buckets reclaimed before actual Rc execution")
		}
		t.Logf("CUT55_R2_RECEIPT_ENTRY_%s deferred=%v pending=1 buckets=1/1 successful_receipts=%d", mode, deferred, successful)
		fresh++
		if deferred {
			return errors.New("R2 Rc failure")
		}
		err := receipt.Quiesce()
		if err == nil {
			successful++
		}
		return err
	})
	reached, preReceipt, finished := false, false, false
	prior := h.commitStageTestHook
	h.commitStageTestHook = func(stage string) {
		if prior != nil {
			prior(stage)
		}
		if stage == "c-Rc" {
			preReceipt = true
			v := readBuckets()
			if fresh != 0 || !h.pendingLogicalIDs[81] || !bytes.Equal(before[0], v[0]) || !bytes.Equal(before[1], v[1]) {
				t.Fatal("R1 logical debt reclaimed before this commit Rc")
			}
		}
		if stage == "c-9" {
			finished = true
		}
	}
	h.commitFaultTestHook = func(stage string) error {
		if stage == "c-4" {
			reached = true
			if abort {
				return errors.New("R1 c-4 abort")
			}
		}
		return nil
	}
	t.Cleanup(func() { h.commitStageTestHook = prior; h.commitFaultTestHook = nil })
	result, commitErr := h.DoCommitRules([]CommitGroup{cut55Group(t, h, next, next)})
	after := readBuckets()
	if !reached {
		t.Fatal("R1 witness never reached c-4")
	}
	if abort {
		if commitErr == nil || commitErr.Code != "commit_failed" || commitErr.Message != "R1 c-4 abort" || fresh != 0 || preReceipt || finished {
			t.Fatalf("R1 c-4 abort guard: err=%v receipts=%d Rc=%v finished=%v", commitErr, fresh, preReceipt, finished)
		}
		if !bytes.Equal(before[0], after[0]) || !bytes.Equal(before[1], after[1]) || !h.pendingLogicalIDs[81] {
			t.Fatal("R1 c-4 abort reclaimed logical state without a fresh receipt")
		}
	} else if deferred {
		if commitErr != nil || result.Code != "committed" || result.Receipt != "deferred" || fresh != 3 || successful != 0 || !preReceipt || finished || h.quiescenceConfirmed {
			t.Fatalf("R2 deferred receipt sequence: result=%+v err=%v receipts=%d successful=%d", result, commitErr, fresh, successful)
		}
		if !bytes.Equal(before[0], after[0]) || !bytes.Equal(before[1], after[1]) || !h.pendingLogicalIDs[81] {
			t.Fatal("R2 failed Rc reclaimed retired logical state")
		}
		cut55R1Counts(t, h)
	} else {
		if commitErr != nil || result.Code != "committed" || result.Receipt != "confirmed" || fresh != 1 || !preReceipt || !finished {
			t.Fatalf("R1 success receipt sequence: result=%+v err=%v receipts=%d", result, commitErr, fresh)
		}
		if len(after[0]) != 0 || len(after[1]) != 0 || h.pendingLogicalIDs[81] {
			t.Fatal("R1 successful Rc did not reclaim retired logical state at c-9")
		}
		if successful != 1 {
			t.Fatal("R2 successful Rc count differs")
		}
		cut55R1Counts(t, h)
	}
	if deferred {
		t.Logf("CUT55_R2_DELETE_DEFERRED_%s fresh_receipts=%d successful_receipts=%d pending=1 buckets=1/1", mode, fresh, successful)
		return
	}
	t.Logf("CUT55_R1_DELETE_RECEIPT_%s abort=%v retirement_deferred=1 preparation_R0=1 reached_c4=1 fresh_receipts=%d pending=%v buckets=%v/%v", mode, abort, fresh, h.pendingLogicalIDs[81], len(after[0]) > 0, len(after[1]) > 0)
}
