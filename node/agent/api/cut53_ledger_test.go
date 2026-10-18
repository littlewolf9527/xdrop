package api

import (
	"errors"
	"testing"
)

func TestCut53LogicalDefaultThresholdAndOwners(t *testing.T) {
	h := cut53MemoryHandler(t)
	for i := uint32(1); i <= 1023; i++ {
		h.retireLogicalIDLocked("gone", i)
	}
	hits := 0
	h.quiescer = cut53Receipt(func() error { hits++; return errors.New("receipt failure keeps debt") })
	h.maybePayLogicalLocked()
	if hits != 0 || len(h.pendingLogicalIDs) != 1023 {
		t.Fatal("default threshold paid before 1024")
	}
	h.retireLogicalIDLocked("gone", 1024)
	h.maybePayLogicalLocked()
	if hits != 3 || len(h.pendingLogicalIDs) != 1024 || h.logicalPaymentFailures != 1 {
		t.Fatal("default threshold did not pay at 1024 or discarded failed debt")
	}
	h.rememberLogicalIDLocked("live", 9)
	if h.logicalIDOwnerLocked("", 9) != "live" || h.logicalIDOwnerLocked("live", 9) != "" {
		t.Fatal("owner lookup/exceptID mismatch")
	}
	h.forgetLogicalIDLocked("other", 9)
	if h.logicalIDOwnerLocked("", 9) != "live" {
		t.Fatal("non-owner erased live owner")
	}
	h.forgetLogicalIDLocked("live", 9)
	if h.logicalIDOwnerLocked("", 9) != "" {
		t.Fatal("owner removal failed")
	}
	t.Log("CUT53_LEDGER_LOCAL threshold=1024 before_receipts=0 at_threshold_attempts=3 retained=1024 owner_cases=4")
}
