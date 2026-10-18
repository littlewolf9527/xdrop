//go:build linux && integration

package api

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func cut53AssertWriterLocks(t *testing.T, h *Handlers) {
	t.Helper()
	if h.syncMu.TryLock() {
		h.syncMu.Unlock()
		t.Fatal("logical payment released syncMu")
	}
	if h.publishMu.TryLock() {
		h.publishMu.Unlock()
		t.Fatal("logical payment released publishMu")
	}
	if h.rulesMu.TryRLock() {
		h.rulesMu.RUnlock()
		t.Fatal("logical payment must use current owner index under rulesMu")
	}
}
func TestCut53LogicalAdmission(t *testing.T) {
	cells := 0
	for _, kind := range []string{"invalid_no_payment", "payment_accepts", "payment_still_full", "receipt_failure", "count_delete_failure", "rate_delete_failure", "effective_ids_over_capacity"} {
		t.Run(kind, func(t *testing.T) {
			h, router, _ := b7Handler(t)
			old := cut53Pure(false, "old", 1)
			if _, err := h.DoAtomicSync([]Rule{old}); err != nil {
				t.Fatal(err)
			}
			cut5SeedLogical(t, h, 1, 2)
			cut53SeedPendingLogical(h, 2)
			h.logicalStateCapacity = 2
			next := cut53Pure(false, "next", 3)
			next.TTL = cut4BString("64")
			receipts := 0
			receipt := h.quiescer
			h.quiescer = cut5ReceiptFunc(func() error {
				receipts++
				if kind == "receipt_failure" {
					return errors.New("cut53 admission receipt failure")
				}
				return receipt.Quiesce()
			})
			switch kind {
			case "invalid_no_payment":
				next.LogicalID = 0
				h.logicalRetireThreshold = 1
			case "payment_still_full":
				h.logicalStateCapacity = 1
			case "count_delete_failure":
				b7Freeze(t, h.idCounts)
			case "rate_delete_failure":
				b7Freeze(t, h.idRLStates)
			case "effective_ids_over_capacity":
				h.pendingLogicalIDs = map[uint32]bool{}
				h.logicalStateCapacity = 1
				// Keep actual state inside the current effective set in this fixture.
				if err := h.idCounts.Delete(uint32(2)); err != nil {
					t.Fatal(err)
				}
				if err := h.idRLStates.Delete(uint32(2)); err != nil {
					t.Fatal(err)
				}
			}
			before := cut53BusinessSnapshot(t, h)
			debtBefore := cut53KernelMapBytes(t, h.idCounts)
			w := yiAtomicCall(t, router, []Rule{next})
			if kind == "payment_accepts" {
				if w.Code != 200 || receipts != 2 || len(h.rules) != 1 || h.rules["next"].LogicalID != 3 || len(h.pendingLogicalIDs) != 0 {
					t.Fatalf("CUT53_CAPACITY paid admission failed receipts=%d response=%d %s pending=%v", receipts, w.Code, w.Body.String(), h.pendingLogicalIDs)
				}
				if len(cut5Keys(t, h.idCounts)) != 0 || len(cut5Keys(t, h.idRLStates)) != 0 {
					t.Fatal("successful payment/reconciliation left old state")
				}
			} else {
				code := "table_full"
				if kind == "invalid_no_payment" {
					code = "condition_group_invalid"
				}
				if w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"`+code+`"`) {
					t.Fatalf("CUT53_CAPACITY rejection=%d %s", w.Code, w.Body.String())
				}
				if !reflect.DeepEqual(before, cut53BusinessSnapshot(t, h)) || h.rules["old"].LogicalID != 1 || len(h.rules) != 1 {
					t.Fatal("CUT53_CAPACITY rejection performed a business write")
				}
				switch kind {
				case "invalid_no_payment":
					if receipts != 0 || !h.pendingLogicalIDs[2] || !reflect.DeepEqual(debtBefore, cut53KernelMapBytes(t, h.idCounts)) {
						t.Fatal("invalid group triggered logical payment")
					}
				case "payment_still_full":
					if receipts != 1 || h.pendingLogicalIDs[2] || cut5Keys(t, h.idCounts)[2] || !cut5Keys(t, h.idCounts)[1] {
						t.Fatal("M5b paid request exits or failed to pay existing debt")
					}
				case "receipt_failure":
					if receipts != 3 || !h.pendingLogicalIDs[2] || !reflect.DeepEqual(debtBefore, cut53KernelMapBytes(t, h.idCounts)) {
						t.Fatal("receipt failure lost debt or state")
					}
				case "count_delete_failure", "rate_delete_failure":
					if receipts != 1 || !h.pendingLogicalIDs[2] || h.logicalPaymentFailures != 1 {
						t.Fatal("delete failure lost logical debt")
					}
				case "effective_ids_over_capacity":
					if receipts != 0 {
						t.Fatal("empty debt unnecessarily paid")
					}
				}
			}
			cells++
		})
	}
	t.Logf("CUT53_CAPACITY cases=%d invalid_no_payment=1 paid_accept=1 paid_reject=1 payment_failure=3 effective_over=1", cells)
}

func cut53PinCPU(t *testing.T) func() {
	t.Helper()
	runtime.LockOSThread()
	var before unix.CPUSet
	if err := unix.SchedGetaffinity(0, &before); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	cpu := 0
	for !before.IsSet(cpu) {
		cpu++
	}
	var one unix.CPUSet
	one.Set(cpu)
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	return func() {
		if err := unix.SchedSetaffinity(0, &before); err != nil {
			t.Error(err)
		}
		runtime.UnlockOSThread()
	}
}
func TestCut53PaymentRechecksCurrentOwners(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprintf("cidr=%v", isCIDR), func(t *testing.T) {
			h, _, program, _ := b7ELFCollection(t)
			unpin := cut53PinCPU(t)
			defer unpin()
			// One token, replenishing only after 4096 seconds, makes exhaustion stable
			// across the actual full-sync receipts without changing token timestamps.
			for _, m := range []*ebpf.Map{h.configA, h.configB} {
				if err := m.Put(uint32(ConfigRLCPUDivisor), uint64(4096)); err != nil {
					t.Fatal(err)
				}
			}
			r := cut53Pure(isCIDR, "r", 17)
			r.TTL = cut4BString("64")
			r.Action = "rate_limit"
			r.RateLimit = 1
			if _, err := h.DoAtomicSync([]Rule{r}); err != nil {
				t.Fatal(err)
			}
			packet := cut53Packet([4]byte{192, 0, 2, 1}, 64)
			cut53Verdict(t, program, packet, 2)
			cut53Verdict(t, program, packet, 1)
			beforeCounts, err := h.idCounts.LookupBytes(uint32(17))
			if err != nil || beforeCounts == nil {
				t.Fatalf("counter fixture=%x %v", beforeCounts, err)
			}
			beforeRate, err := h.idRLStates.LookupBytes(uint32(17))
			if err != nil || beforeRate == nil {
				t.Fatalf("rate fixture=%x %v", beforeRate, err)
			}
			r.TTL = nil
			r.Action = "drop"
			r.RateLimit = 0
			if _, err := h.DoAtomicSync([]Rule{r}); err != nil {
				t.Fatal(err)
			}
			p7DeferredCommit(t, h, cut55Group(t, h, r))
			// This read is deliberately BEFORE re-establishment and payment.
			if !h.pendingLogicalIDs[17] || h.logicalIDOwnerLocked("", 17) != "" {
				t.Fatal("recheck witness guard: ID 17 must still be pending and currently absent")
			}
			h.logicalRetireThreshold = 1024
			p7DeferredCommit(t, h, cut55Group(t, h, r, r))
			if !h.pendingLogicalIDs[17] || h.logicalIDOwnerLocked("", 17) != "r" {
				t.Fatal("recheck witness guard: real pure POST must restore a still-pending ID")
			}
			h.logicalRetireThreshold = 1
			receipts := 0
			receipt := h.quiescer
			h.quiescer = cut5ReceiptFunc(func() error { receipts++; cut53AssertWriterLocks(t, h); return receipt.Quiesce() })
			cut54Pay(t, h)
			afterCounts, ce := h.idCounts.LookupBytes(uint32(17))
			afterRate, re := h.idRLStates.LookupBytes(uint32(17))
			if receipts != 1 || h.pendingLogicalIDs[17] || ce != nil || re != nil || !bytes.Equal(beforeCounts, afterCounts) || !bytes.Equal(beforeRate, afterRate) {
				t.Fatalf("payment erased live logical state: receipts=%d pending=%v counts=%x/%x rate=%x/%x errors=%v/%v", receipts, h.pendingLogicalIDs, beforeCounts, afterCounts, beforeRate, afterRate, ce, re)
			}
			h.quiescer = receipt
			r.TTL = cut4BString("64")
			r.Action = "rate_limit"
			r.RateLimit = 1
			if _, err := h.DoAtomicSync([]Rule{r}); err != nil {
				t.Fatal(err)
			}
			cut53Verdict(t, program, packet, 1)
			t.Logf("CUT53_PAYMENT_RECHECK cidr=%v pending_before_post=1 current_before_pay=1 payment_receipts=1 state_bytes_unchanged=2 resumed_first_packet=DROP", isCIDR)
		})
	}
}

func TestCut53CrossPathDeferredLedger(t *testing.T) {
	cells := 0
	for _, isCIDR := range []bool{false, true} {
		for _, phase := range []string{"R5c", "id_counts", "id_rl_states"} {
			for _, failPayment := range []bool{false, true} {
				t.Run(fmt.Sprintf("cidr=%v/%s/pay_failure=%v", isCIDR, phase, failPayment), func(t *testing.T) {
					h, router, _ := b7Handler(t)
					r := cut53Pure(isCIDR, "r", 17)
					r.TTL = cut4BString("64")
					exit := Rule{ID: "exit", LogicalID: 99, SrcIP: "203.0.113.9", Action: "drop"}
					if _, err := h.DoAtomicSync([]Rule{r, exit}); err != nil {
						t.Fatal(err)
					}
					cut5SeedLogical(t, h, 17, 99)
					receipt, counts, rates := h.quiescer, h.idCounts, h.idRLStates
					if phase == "R5c" {
						h.quiescer = cut53Receipt(func() error { return errors.New("cross-path R5c fault") })
					} else {
						atomicStageTestHook = func(stage string, got *Handlers) {
							if stage != "6" || got != h {
								return
							}
							m := counts
							if phase == "id_rl_states" {
								m = rates
							}
							closed, err := m.Clone()
							if err != nil {
								t.Fatal(err)
							}
							if err := closed.Close(); err != nil {
								t.Fatal(err)
							}
							if phase == "id_counts" {
								h.idCounts = closed
							} else {
								h.idRLStates = closed
							}
						}
						defer func() { atomicStageTestHook = nil }()
					}
					r.TTL = nil
					if _, err := h.DoAtomicSync([]Rule{r}); err != nil {
						t.Fatal(err)
					}
					atomicStageTestHook = nil
					h.quiescer, h.idCounts, h.idRLStates = receipt, counts, rates
					if !h.pendingLogicalIDs[99] {
						t.Fatal("R5c/Step6 failure lost full-exit logical debt")
					}
					if !cut5Keys(t, counts)[17] || !cut5Keys(t, rates)[17] {
						t.Fatal("condition-to-pure lost current logical state")
					}
					p7DeferredCommit(t, h, cut55Group(t, h, r))
					if !h.pendingLogicalIDs[17] || !h.pendingLogicalIDs[99] || len(h.logicalOwners) != 0 {
						t.Fatal("CUT53_CROSS_PATH pure delete did not join full-exit debt")
					}
					h.logicalStateCapacity = 1
					receipts := 0
					h.quiescer = cut53Receipt(func() error {
						receipts++
						if failPayment {
							return errors.New("cross-path payment fault")
						}
						return receipt.Quiesce()
					})
					next := cut53Pure(isCIDR, "next", 18)
					next.TTL = cut4BString("64")
					before := cut53BusinessSnapshot(t, h)
					w := yiAtomicCall(t, router, []Rule{next})
					if failPayment {
						if w.Code != 409 || !strings.Contains(w.Body.String(), `"code":"table_full"`) || receipts != 3 || !h.pendingLogicalIDs[17] || !h.pendingLogicalIDs[99] || !reflect.DeepEqual(before, cut53BusinessSnapshot(t, h)) {
							t.Fatalf("CUT53_CROSS_PATH failed payment did not retain/refuse: %d %s receipts=%d debt=%v", w.Code, w.Body.String(), receipts, h.pendingLogicalIDs)
						}
					} else {
						if w.Code != 200 || receipts != 2 || len(h.pendingLogicalIDs) != 0 {
							t.Fatalf("CUT53_CROSS_PATH payment recovery failed: %d %s receipts=%d debt=%v", w.Code, w.Body.String(), receipts, h.pendingLogicalIDs)
						}
						for _, m := range []*ebpf.Map{counts, rates} {
							if len(cut5Keys(t, m)) != 0 {
								t.Fatal("CUT53_CROSS_PATH recovery left an orphan logical key")
							}
						}
					}
					cells++
				})
			}
		}
	}
	t.Logf("CUT53_CROSS_PATH_DEFERRED cells=%d R5c=4 Step6=8 payment_success=6 payment_failure=6", cells)
}
