package api

import (
	"fmt"
	"github.com/cilium/ebpf"
	"testing"
)

func cut54OrphanInstall(h *Handlers, id uint32, cidr bool) {
	name := fmt.Sprint(id)
	if cidr {
		h.cidrRules[name] = StoredCIDRRule{LogicalID: id}
	} else {
		h.rules[name] = StoredRule{LogicalID: id}
	}
	h.rememberLogicalIDLocked(name, id)
}
func cut54OrphanRemoveMemory(h *Handlers, id uint32, cidr bool) {
	if cidr {
		delete(h.cidrRules, fmt.Sprint(id))
	} else {
		delete(h.rules, fmt.Sprint(id))
	}
}

// Rulings 8/9: keep ownership after failed Delete; U and exits use owners.
// Business-row Delete and packet lazy creation are modeled; payment/admission are production.
func TestCut54OrphanRollbackCapacity(t *testing.T) {
	for _, cidr := range []bool{false, true} {
		for _, deleted := range []bool{true, false} {
			t.Run(fmt.Sprintf("cidr=%v/delete_succeeded=%v", cidr, deleted), func(t *testing.T) {
				h := cut53MemoryHandler(t)
				h.logicalStateCapacity = 2
				cut54OrphanInstall(h, 1, cidr)
				cut54OrphanInstall(h, 17, cidr)
				rows := map[uint32]bool{1: true, 17: true}
				counts, rates := cut54StateMaps()
				counts.keys[1], rates.keys[1] = true, true
				counts.keys[17], rates.keys[17] = true, true
				cut54OrphanRemoveMemory(h, 17, cidr)
				if deleted {
					delete(rows, 17)
					h.retireLogicalIDLocked("17", 17)
				} // A: retain owner on failed Delete.
				h.quiescer = cut53Receipt(func() error { return nil })
				if err := h.payPendingLogicalWithMapsLocked(counts, rates); err != nil {
					t.Fatal(err)
				}
				for id := range rows {
					counts.keys[id], rates.keys[id] = true, true
				}
				before := h.logicalUnionLocked(nil)
				err := h.admitAtomicLogicalIDs([]Rule{cut53Pure(false, "18", 18)})
				admitted := 0
				if err == nil {
					admitted = 1
					cut54OrphanInstall(h, 18, cidr)
					counts.keys[18], rates.keys[18] = true, true
				}
				t.Logf("PLAN_A cidr=%v delete_succeeded=%v union=%d actual_keys=%d pending=%d admitted_new=%d owner17=%v union_before=%d", cidr, deleted, h.logicalUnionLocked(nil), len(counts.keys), len(h.pendingLogicalIDs), admitted, h.logicalOwners[17] != "", before)
				if !deleted && (before != 2 || admitted != 0) {
					t.Errorf("A(a) failed: retained logicalOwners ID is absent from current union; before=%d admitted_new=%d", before, admitted)
				}
				if deleted && (admitted != 1 || len(counts.keys) != 2) {
					t.Errorf("successful-delete positive control failed")
				}
			})
		}
	}
}
func TestCut54OrphanPaymentRecheck(t *testing.T) {
	for _, cidr := range []bool{false, true} {
		t.Run(fmt.Sprint(cidr), func(t *testing.T) {
			h := cut53MemoryHandler(t)
			cut54OrphanInstall(h, 17, cidr)
			cut54OrphanRemoveMemory(h, 17, cidr)
			// Independently exercise the real recheck branch with pre-existing pending debt.
			h.pendingLogicalIDs[17] = true
			h.quiescer = cut53Receipt(func() error { return nil })
			counts, rates := cut54StateMaps()
			counts.keys[17], rates.keys[17] = true, true
			if err := h.payPendingLogicalWithMapsLocked(counts, rates); err != nil {
				t.Fatal(err)
			}
			t.Logf("PLAN_A_B cidr=%v seeded_pending=1 owner17=%v counts17=%v rates17=%v pending17=%v deletes=%d", cidr, h.logicalOwners[17] != "", counts.keys[17], rates.keys[17], h.pendingLogicalIDs[17], counts.deletes+rates.deletes)
			if !counts.keys[17] || !rates.keys[17] || h.logicalOwners[17] == "" || counts.deletes+rates.deletes != 0 {
				t.Fatal("A(b) payment removed a retained owner bucket")
			}
		})
	}
}

type cut54OrphanKeys struct{ *cut54StateMap }

func (m cut54OrphanKeys) NextKey(cursor interface{}, out interface{}) error {
	var prev uint32
	if cursor != nil {
		prev = cursor.(uint32)
	}
	var found bool
	var next uint32
	for id := range m.keys {
		if (cursor == nil || id > prev) && (!found || id < next) {
			found = true
			next = id
		}
	}
	if !found {
		return ebpf.ErrKeyNotExist
	}
	*out.(*uint32) = next
	return nil
}

// Invoke the actual post-flip owner transition used by DoAtomicSync.
func cut54OrphanActualStep5(h *Handlers, newRules map[string]StoredRule, newCidrRules map[string]StoredCIDRRule) {
	h.replaceLogicalOwnersLocked(newRules, newCidrRules)
	h.rules, h.cidrRules = newRules, newCidrRules
}
func TestCut54OrphanFullSyncExit(t *testing.T) {
	for _, cidr := range []bool{false, true} {
		for _, receiptOK := range []bool{false, true} {
			t.Run(fmt.Sprintf("cidr=%v/receipt_ok=%v", cidr, receiptOK), func(t *testing.T) {
				h := cut53MemoryHandler(t)
				cut54OrphanInstall(h, 1, cidr)
				cut54OrphanInstall(h, 17, cidr)
				cut54OrphanRemoveMemory(h, 17, cidr)
				counts, rates := cut54StateMaps()
				counts.keys[17], rates.keys[17] = true, true
				next := map[string]StoredRule{}
				nextCIDR := map[string]StoredCIDRRule{}
				if cidr {
					nextCIDR["1"] = StoredCIDRRule{LogicalID: 1}
				} else {
					next["1"] = StoredRule{LogicalID: 1}
				}
				cut54OrphanActualStep5(h, next, nextCIDR)
				pendingAtFlip := h.pendingLogicalIDs[17]
				t.Logf("PLAN_A_C_FLIP cidr=%v owner17=%v pending17=%v counts17=%v rates17=%v", cidr, h.logicalOwners[17] != "", pendingAtFlip, counts.keys[17], rates.keys[17])
				if receiptOK {
					// Match Step 6's actual logical-key reconciliation after a successful receipt.
					valid := map[uint32]bool{1: true}
					if err := reconcileLogicalKeys(cut54OrphanKeys{counts}, valid); err != nil {
						t.Fatal(err)
					}
					if err := reconcileLogicalKeys(cut54OrphanKeys{rates}, valid); err != nil {
						t.Fatal(err)
					}
					h.pendingLogicalIDs = make(map[uint32]bool)
				}
				if pendingAtFlip && (counts.keys[17] == receiptOK || rates.keys[17] == receiptOK || h.pendingLogicalIDs[17] == receiptOK) {
					t.Fatal("post-flip debt/state must persist until a successful receipt")
				}
				t.Logf("PLAN_A_C_AFTER cidr=%v receipt_ok=%v owner17=%v pending17=%v counts17=%v rates17=%v", cidr, receiptOK, h.logicalOwners[17] != "", h.pendingLogicalIDs[17], counts.keys[17], rates.keys[17])
				if !pendingAtFlip {
					t.Error("A(c) failed: full-sync Step 5 discards orphan owner without retirement before receipt")
				}
			})
		}
	}
}

func cut54AssertOwnerInvariant(t *testing.T, h *Handlers) {
	t.Helper()
	ids := make(map[uint32]bool)
	for _, r := range h.rules {
		if r.LogicalID != 0 {
			ids[r.LogicalID] = true
		}
	}
	for _, r := range h.cidrRules {
		if r.LogicalID != 0 {
			ids[r.LogicalID] = true
		}
	}
	if len(ids) != len(h.logicalOwners) {
		t.Fatalf("normal owner invariant: memory=%v owners=%v", ids, h.logicalOwners)
	}
	for id := range ids {
		if _, ok := h.logicalOwners[id]; !ok {
			t.Fatalf("normal owner invariant missing logical ID %d", id)
		}
	}
}
func TestCut54OrphanOwnerInvariantModel(t *testing.T) {
	h := cut53MemoryHandler(t)
	cut54OrphanActualStep5(h, map[string]StoredRule{"1": {LogicalID: 1}}, map[string]StoredCIDRRule{"2": {LogicalID: 2}})
	cut54AssertOwnerInvariant(t, h)
	cut54OrphanInstall(h, 3, false)
	cut54AssertOwnerInvariant(t, h)
	cut54OrphanInstall(h, 4, false)
	cut54OrphanInstall(h, 5, true)
	cut54AssertOwnerInvariant(t, h)
	cut54OrphanRemoveMemory(h, 3, false)
	h.retireLogicalIDLocked("3", 3)
	cut54AssertOwnerInvariant(t, h)
	t.Log("CUT54_OWNER_INVARIANT model_stages=4 full=1 single=1 batch=1 delete=1")
}
