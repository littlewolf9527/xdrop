package api

import (
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
)

type cut54StateMap struct {
	keys    map[uint32]bool
	fail    bool
	deletes int
}

func (m *cut54StateMap) NextKey(interface{}, interface{}) error { return ebpf.ErrKeyNotExist }
func (m *cut54StateMap) Delete(key interface{}) error {
	m.deletes++
	if m.fail {
		return errors.New("delete failure")
	}
	id := key.(uint32)
	if !m.keys[id] {
		return ebpf.ErrKeyNotExist
	}
	delete(m.keys, id)
	return nil
}
func cut54StateMaps() (*cut54StateMap, *cut54StateMap) {
	return &cut54StateMap{keys: map[uint32]bool{}}, &cut54StateMap{keys: map[uint32]bool{}}
}
func cut54LedgerInstall(h *Handlers, id uint32) {
	name := fmt.Sprint(id)
	h.rules[name] = StoredRule{LogicalID: id}
	h.rememberLogicalIDLocked(name, id)
}
func TestCut54LogicalTurnoverStateMachine(t *testing.T) {
	for _, failure := range []string{"none", "receipt", "counts", "rates"} {
		t.Run(failure, func(t *testing.T) {
			h := cut53MemoryHandler(t)
			h.logicalStateCapacity = 8
			counts, rates := cut54StateMaps()
			receipts := 0
			h.quiescer = cut53Receipt(func() error {
				receipts++
				if failure == "receipt" {
					return errors.New("receipt failure")
				}
				return nil
			})
			if failure == "counts" {
				counts.fail = true
			}
			if failure == "rates" {
				rates.fail = true
			}
			for id := uint32(1); id <= 64; id++ {
				err := h.admitAtomicLogicalIDs([]Rule{cut53Pure(false, fmt.Sprint(id), id)})
				if err != nil {
					if failure == "none" {
						t.Fatalf("turnover exhausted capacity at %d: %v", id, err)
					}
					var full *logicalTableFullError
					if !errors.As(err, &full) || full.Used != 9 || full.Capacity != 8 {
						t.Fatalf("full union rejected incorrectly: %v", err)
					}
					if len(h.pendingLogicalIDs) != 8 {
						t.Fatal("failed payment discarded debt")
					}
					return
				}
				cut54LedgerInstall(h, id)
				counts.keys[id], rates.keys[id] = true, true
				delete(h.rules, fmt.Sprint(id))
				h.retireLogicalIDLocked(fmt.Sprint(id), id)
				if len(h.pendingLogicalIDs) >= 4 {
					err := h.payPendingLogicalWithMapsLocked(counts, rates)
					if failure == "none" && err != nil {
						t.Fatal(err)
					}
					if failure != "none" && err == nil {
						t.Fatal("injected payment failure was not reached")
					}
				}
				if len(counts.keys) > 8 || len(rates.keys) > 8 || h.logicalUnionLocked(nil) > 8 {
					t.Fatal("logical state exceeded capacity")
				}
			}
			if failure != "none" || receipts != 16 || len(counts.keys)+len(rates.keys)+len(h.pendingLogicalIDs) != 0 {
				t.Fatalf("turnover receipts=%d debt=%v state=%v/%v", receipts, h.pendingLogicalIDs, counts.keys, rates.keys)
			}
		})
	}
	t.Log("CUT54_LEDGER_MACHINE scenarios=4 successful_turnovers=64 payments=16 failed_payment_capacity_rejections=3")
}
func TestCut54LogicalUnionAndBatchReservations(t *testing.T) {
	h := cut53MemoryHandler(t)
	h.logicalStateCapacity = 4
	cut54LedgerInstall(h, 1)
	cut54LedgerInstall(h, 2)
	// Equal-size replacement still needs simultaneous old and new generations.
	h.logicalStateCapacity = 2
	h.pendingLogicalIDs = map[uint32]bool{}
	err := h.admitAtomicLogicalIDs([]Rule{cut53Pure(false, "n3", 3), cut53Pure(false, "n4", 4)})
	var full *logicalTableFullError
	if !errors.As(err, &full) || full.Used != 4 || len(h.rules) != 2 {
		t.Fatalf("equal-size replacement omitted current IDs: %v", err)
	}
	t.Log("CUT54_UNION equal_replacement=1")
}
func TestCut54PaymentRechecksReestablishedOwner(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		h := cut53MemoryHandler(t, cut53Pure(isCIDR, "live", 17))
		h.pendingLogicalIDs[17] = true
		h.quiescer = cut53Receipt(func() error { return nil })
		counts, rates := cut54StateMaps()
		counts.keys[17], rates.keys[17] = true, true
		if err := h.payPendingLogicalWithMapsLocked(counts, rates); err != nil {
			t.Fatal(err)
		}
		if !counts.keys[17] || !rates.keys[17] || counts.deletes+rates.deletes != 0 || h.pendingLogicalIDs[17] {
			t.Fatal("payment deleted a currently effective logical ID")
		}
	}
	t.Log("CUT54_REVALIDATION current_owner_cases=2 deleted_live_keys=0 cleared_debt=2")
}

func TestCut54EqualReplacementCapacity(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprint(isCIDR), func(t *testing.T) {
			a, b := cut53Pure(isCIDR, "old-a", 1), cut53Pure(isCIDR, "old-b", 2)
			c, d := cut53Pure(isCIDR, "new-c", 3), cut53Pure(isCIDR, "new-d", 4)
			if isCIDR {
				a.SrcCIDR, b.SrcCIDR = "192.0.2.0/25", "192.0.2.128/25"
				c.SrcCIDR, d.SrcCIDR = "198.51.100.0/25", "198.51.100.128/25"
			} else {
				b.SrcIP = "192.0.2.2"
				c.SrcIP, d.SrcIP = "198.51.100.1", "198.51.100.2"
			}
			h := cut53MemoryHandler(t, a, b)
			h.logicalStateCapacity = 2
			before := cut54StableState(h)
			err := h.admitAtomicLogicalIDs([]Rule{c, d})
			var full *logicalTableFullError
			if !errors.As(err, &full) || full.Used != 4 || full.Capacity != 2 || before != cut54StableState(h) {
				t.Fatalf("equal replacement must account for current and next IDs: error=%v", err)
			}
		})
	}
	t.Log("CUT54_EQUAL_REPLACEMENT cases=2 current=2 next=2 union=4 capacity=2 zero_business_writes=2")
}

// Prefix manager map iteration is unordered. Only this new witness changes;
// all state fields remain present in the comparison.
func cut54StableState(h *Handlers) string {
	src, dst := h.cidrMgr.ListSrcCIDRs(), h.cidrMgr.ListDstCIDRs()
	sort.Strings(src)
	sort.Strings(dst)
	return fmt.Sprintf("%#v/%#v/%#v/%#v/%#v/%#v/%#v/%#v", h.rules, h.cidrRules, h.ruleKeyIndex, h.cidrRuleKeyIndex, h.logicalOwners, h.pendingLogicalIDs, src, dst)
}
