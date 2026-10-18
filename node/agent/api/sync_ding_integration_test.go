//go:build linux && integration

package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

// Failure injection wraps the real ELF maps before installing any generation.
// Neither production Manager nor production handlers contain fault switches.
type dingTrie struct {
	table               *ebpf.Map
	failPut, failDelete bool
	puts, deletes       int
	beforePut           func(interface{}, interface{})
}

func (w *dingTrie) KeySize() uint32                { return w.table.KeySize() }
func (w *dingTrie) NextKey(k, v interface{}) error { return w.table.NextKey(k, v) }
func (w *dingTrie) Lookup(k, v interface{}) error  { return w.table.Lookup(k, v) }
func (w *dingTrie) Put(k, v interface{}) error {
	w.puts++
	if w.beforePut != nil {
		w.beforePut(k, v)
	}
	if w.failPut {
		return fmt.Errorf("injected trie Put")
	}
	return w.table.Put(k, v)
}
func (w *dingTrie) Delete(k interface{}) error {
	w.deletes++
	if w.failDelete {
		return fmt.Errorf("injected trie Delete")
	}
	return w.table.Delete(k)
}
func dingELF(t *testing.T) (*Handlers, *gin.Engine, *ebpf.Program, []*dingTrie) {
	t.Helper()
	h, r, p := b7ELF(t)
	maps := yiELFTries(t, p)
	ws := make([]*dingTrie, 8)
	for i, m := range maps {
		ws[i] = &dingTrie{table: m}
	}
	h.cidrMgr = cidr.NewManager(ws[0], ws[1], ws[2], ws[3], ws[4], ws[5], ws[6], ws[7])
	return h, r, p, ws
}
func dingDebt(t *testing.T, w *httptest.ResponseRecorder, status int, pending bool) {
	t.Helper()
	var body struct {
		WithdrawalPending *bool `json:"withdrawal_pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != status || body.WithdrawalPending != nil {
		t.Fatalf("status/debt=%d/%s want=%d/%v", w.Code, w.Body.String(), status, pending)
	}
}
func dingHasPrefix(t *testing.T, m *ebpf.Map, prefix uint32, ip [4]byte) bool {
	t.Helper()
	key := make([]byte, 8)
	binary.LittleEndian.PutUint32(key, prefix)
	copy(key[4:], ip[:])
	_, ok := b7Snapshot(t, m)[string(key)] // Enumerate exact keys, never LPM lookup.
	return ok
}

func dingFreezeFlip(t *testing.T, h *Handlers) func() {
	t.Helper()
	old := h.activeConfig
	failed := newActiveCfg(t)
	if err := failed.Freeze(); err != nil {
		t.Fatal(err)
	}
	h.activeConfig = failed
	return func() { h.activeConfig = old }
}

func TestDingAtomicLatePublication(t *testing.T) {
	h, r, p, ws := dingELF(t)
	old := Rule{LogicalID: 541001, ID: "old", SrcCIDR: "10.0.0.0/16", Action: "drop"}
	dingDebt(t, yiAtomicCall(t, r, []Rule{old}), 200, false)
	b7Verdict(t, p, 1)
	active := int(h.activeRuleSlot.Load())
	reached := 0
	cidrBeforeAtomicPublishTestHook = func(got *Handlers) {
		if got != h {
			t.Fatal("unexpected handler")
		}
		reached++
		b7Verdict(t, p, 1)
		for _, w := range []*dingTrie{ws[0], ws[4]} {
			if dingHasPrefix(t, w.table, 24, [4]byte{10, 0, 0, 0}) {
				t.Fatal("new prefix before publication")
			}
		}
		if !dingHasPrefix(t, ws[4*active].table, 16, [4]byte{10, 0, 0, 0}) {
			t.Fatal("old active prefix disappeared")
		}
	}
	defer func() { cidrBeforeAtomicPublishTestHook = nil }()
	restore := flipBReceipt(t, h, func() error {
		if !dingHasPrefix(t, ws[4*active].table, 16, [4]byte{10, 0, 0, 0}) {
			t.Error("old prefix absent at R5c entry")
		}
		return nil
	})
	defer restore()
	dingDebt(t, yiAtomicCall(t, r, []Rule{{LogicalID: 541002, ID: "new", SrcCIDR: "10.0.0.0/24", Action: "drop"}}), 200, false)
	if reached != 1 || int(h.activeRuleSlot.Load()) == active {
		t.Fatal("publication not reached once")
	}
	if !dingHasPrefix(t, ws[4*(1-active)].table, 24, [4]byte{10, 0, 0, 0}) || dingHasPrefix(t, ws[4*(1-active)].table, 16, [4]byte{10, 0, 0, 0}) || dingHasPrefix(t, ws[4*active].table, 16, [4]byte{10, 0, 0, 0}) || !dingHasPrefix(t, ws[4*active].table, 24, [4]byte{10, 0, 0, 0}) {
		t.Fatal("A/B generation contents wrong")
	}
	b7Verdict(t, p, 1)
	t.Log("DING_LATE_PUBLICATION old_verdict=1 new_prefix_before_publish=false stage=after_3b reached=1")
}
func TestDingFlipRollbackAndUnknownCopy(t *testing.T) {
	for _, deleteFault := range []bool{false, true} {
		t.Run(fmt.Sprint(deleteFault), func(t *testing.T) {
			h, r, _, ws := dingELF(t)
			dingDebt(t, yiAtomicCall(t, r, []Rule{{LogicalID: 541003, ID: "old", SrcIP: "10.93.0.1", Action: "drop"}}), 200, false)
			slot := int(h.activeRuleSlot.Load())
			shadow := ws[4*(1-slot)]
			restore := dingFreezeFlip(t, h)
			dingDebt(t, yiAtomicCall(t, r, []Rule{{LogicalID: 541004, ID: "new", SrcCIDR: "10.4.0.0/24", Action: "drop"}}), 500, false)
			restore()
			if !dingHasPrefix(t, shadow.table, 24, [4]byte{10, 4, 0, 0}) || len(h.cidrMgr.ListSrcCIDRs()) != 0 || int(h.activeRuleSlot.Load()) != slot {
				t.Fatal("preflip failure must retain only unknown shadow residue")
			}
			target := []Rule{{LogicalID: 541005, ID: "next", SrcCIDR: "10.4.0.0/25", Action: "drop"}}
			if deleteFault {
				shadow.failDelete = true
				before := []map[string]string{b7Snapshot(t, p7ActiveBlacklist(h)), b7Snapshot(t, h.activeMap()), b7Snapshot(t, ws[4*slot].table)}
				w := yiAtomicCall(t, r, target)
				dingDebt(t, w, 500, false)
				var body map[string]interface{}
				if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
					t.Fatal(e)
				}
				if _, exists := body["code"]; exists {
					t.Fatal("atomic trie failure must use generic 500", w.Body.String())
				}
				after := []map[string]string{b7Snapshot(t, p7ActiveBlacklist(h)), b7Snapshot(t, h.activeMap()), b7Snapshot(t, ws[4*slot].table)}
				if !reflect.DeepEqual(before, after) || int(h.activeRuleSlot.Load()) != slot {
					t.Fatal("unknown alignment failure changed active generation")
				}
				shadow.failDelete = false
			}
			dingDebt(t, yiAtomicCall(t, r, target), 200, false)
			if dingHasPrefix(t, shadow.table, 24, [4]byte{10, 4, 0, 0}) || !dingHasPrefix(t, shadow.table, 25, [4]byte{10, 4, 0, 0}) {
				t.Fatal("actual-content recovery wrong")
			}
		})
	}
}
func TestDingRetirementAndDeletionRecovery(t *testing.T) {
	h, r, _, ws := dingELF(t)
	old := Rule{LogicalID: 541007, ID: "old", SrcCIDR: "10.0.0.0/25", Action: "drop"}
	dingDebt(t, yiAtomicCall(t, r, []Rule{old}), 200, false)
	oldCopy := ws[4*int(h.activeRuleSlot.Load())]
	oldCopy.failDelete = true
	target := []Rule{{LogicalID: 541008, ID: "new", SrcCIDR: "10.0.0.0/24", Action: "drop"}}
	restore := flipBReceipt(t, h, func() error {
		if oldCopy.deletes != 0 || !dingHasPrefix(t, oldCopy.table, 25, [4]byte{10, 0, 0, 0}) {
			t.Error("atomic wrote old copy before R5c")
		}
		return nil
	})
	dingDebt(t, yiAtomicCall(t, r, target), 200, false)
	restore()
	if oldCopy.deletes != 1 || !dingHasPrefix(t, oldCopy.table, 25, [4]byte{10, 0, 0, 0}) {
		t.Fatal("atomic wrote old copy after flip")
	}
	if _, ok := h.cidrMgr.GetSrcID(old.SrcCIDR); ok {
		t.Fatal("retired reference retained")
	}
	slot := h.activeRuleSlot.Load()
	dingDebt(t, yiAtomicCall(t, r, target), 500, false)
	if h.activeRuleSlot.Load() != slot || len(h.cidrRules) != 1 {
		t.Fatal("delete fault published")
	}
	oldCopy.failDelete = false
	dingDebt(t, yiAtomicCall(t, r, target), 200, false)
	if dingHasPrefix(t, oldCopy.table, 25, [4]byte{10, 0, 0, 0}) || !dingHasPrefix(t, oldCopy.table, 24, [4]byte{10, 0, 0, 0}) {
		t.Fatal("retired prefix recovery wrong")
	}
	t.Log("DING_RECOVERY old_copy_retained=1 failed_alignment_no_flip=1 next_atomic_recovered=1")
}
func TestDingDuplicateIDZeroMutation(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			h, r, _, ws := dingELF(t)
			dingDebt(t, yiAtomicCall(t, r, []Rule{{LogicalID: 541018, ID: "old", SrcCIDR: "10.14.0.0/24", Action: "drop"}}), 200, false)
			if unknown {
				restore := flipBReceipt(t, h, func() error { return fmt.Errorf("R5c deferred fixture") })
				dingDebt(t, yiAtomicCall(t, r, nil), 200, false)
				restore()
				if !dingHasPrefix(t, ws[4].table, 24, [4]byte{10, 14, 0, 0}) {
					t.Fatal("unknown old-copy guard")
				}
			}
			snapshot := func() []interface{} {
				out := []interface{}{fmt.Sprintf("%#v", h.cidrMgr), fmt.Sprintf("%#v %#v %#v %#v %#v %#v %d %d", h.rules, h.cidrRules, h.ruleKeyIndex, h.cidrRuleKeyIndex, h.comboRefCount, h.cidrComboRefCount, h.activeSlot, int(h.activeRuleSlot.Load()))}
				for _, m := range []*ebpf.Map{h.blacklist, h.blacklistB, h.cidrBlacklist, h.cidrBlacklistB, h.configA, h.configB, h.activeConfig} {
					out = append(out, b7Snapshot(t, m))
				}
				for _, w := range ws {
					out = append(out, b7Snapshot(t, w.table), w.puts, w.deletes)
				}
				return out
			}
			before := snapshot()
			w := yiAtomicCall(t, r, []Rule{{LogicalID: 541019, ID: "same", SrcCIDR: "10.12.0.0/24", Action: "drop"}, {LogicalID: 541020, ID: "same", SrcCIDR: "10.13.0.0/24", Action: "drop"}})
			dingAssertDuplicateID(t, w, "same", 0, 1, false)
			if !reflect.DeepEqual(before, snapshot()) {
				t.Fatal("duplicate ID changed either generation")
			}
			slot := h.activeSlot
			valid := []Rule{{LogicalID: 541021, ID: "first", SrcCIDR: "10.12.0.0/24", Action: "drop"}, {LogicalID: 541022, ID: "second", SrcCIDR: "10.13.0.0/24", Action: "drop"}}
			dingDebt(t, yiAtomicCall(t, r, valid), 200, false)
			active := ws[4*int(h.activeRuleSlot.Load())]
			if h.activeSlot == slot || len(h.cidrRules) != 2 || len(h.cidrMgr.ListSrcCIDRs()) != 2 || !dingHasPrefix(t, active.table, 24, [4]byte{10, 12, 0, 0}) || !dingHasPrefix(t, active.table, 24, [4]byte{10, 13, 0, 0}) {
				t.Fatal("legal batch not published")
			}
			restore := flipBReceipt(t, h, func() error {
				if len(b7Snapshot(t, active.table)) != 2 {
					t.Error("old prefixes missing at R5c entry")
				}
				return nil
			})
			dingDebt(t, yiAtomicCall(t, r, nil), 200, false)
			restore()
			if len(h.cidrMgr.ListSrcCIDRs()) != 0 || len(b7Snapshot(t, ws[4*int(h.activeRuleSlot.Load())].table)) != 0 || len(b7Snapshot(t, active.table)) != 0 {
				t.Fatal("reference release or old-copy retention wrong")
			}
			t.Logf("DING_DUPLICATE_ID zero_state_components=%d unknown_before=%v legal_next_flip=true residual_refs=0", len(before), unknown)
		})
	}
}

// Protocol-2 controller withdrawal bridge retired: protocol 8 rejects that controller.
func TestDingDeleteFailureRecovery(t *testing.T) {
	h, r, _, ws := dingELF(t)
	seed := []Rule{{LogicalID: 541015, ID: "src", SrcCIDR: "10.10.0.0/24", Action: "drop"}, {LogicalID: 541016, ID: "dst", DstCIDR: "10.11.0.0/24", Action: "drop"}}
	cut55KernelReceipt(t, h)
	cut55Commit(t, h, cut55Group(t, h, seed[0], seed[0]), cut55Group(t, h, seed[1], seed[1]))
	oldSlot := int(h.activeRuleSlot.Load())
	shadowSlot := 1 - oldSlot
	ws[4*shadowSlot+1].failDelete = true
	before := b7Snapshot(t, h.activeConfig)
	dingDebt(t, yiAtomicCall(t, r, nil), 500, false)
	if len(b7Snapshot(t, ws[4*shadowSlot].table)) != 0 || len(b7Snapshot(t, ws[4*shadowSlot+1].table)) != 1 {
		t.Fatal("partial progress was restored or lost")
	}
	if !reflect.DeepEqual(before, b7Snapshot(t, h.activeConfig)) || len(h.cidrRules) != 2 {
		t.Fatal("delete failure changed active policy")
	}
	ws[4*shadowSlot+1].failDelete = false
	restore := flipBReceipt(t, h, func() error {
		for _, i := range []int{0, 1} {
			if len(b7Snapshot(t, ws[4*oldSlot+i].table)) != 1 {
				t.Error("old prefix missing at R5c entry")
			}
		}
		return nil
	})
	defer restore()
	dingDebt(t, yiAtomicCall(t, r, nil), 200, false)
	for _, i := range []int{0, 1} {
		if len(b7Snapshot(t, ws[4*shadowSlot+i].table)) != 0 || len(b7Snapshot(t, ws[4*oldSlot+i].table)) != 0 {
			t.Fatal("unknown recovery or old-copy retention wrong")
		}
	}
}
