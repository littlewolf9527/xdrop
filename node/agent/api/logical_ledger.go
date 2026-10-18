package api

import (
	"errors"
	"fmt"
	"log"
	"sort"
)

// Owners are protected by rulesMu. Pending IDs and payment statistics are
// protected by publishMu; writers hold syncMu before either lock.
func (h *Handlers) rememberLogicalIDLocked(id string, logicalID uint32) {
	if logicalID == 0 {
		return
	}
	if h.logicalOwners == nil {
		h.logicalOwners = make(map[uint32]string)
	}
	h.logicalOwners[logicalID] = id
}
func (h *Handlers) forgetLogicalIDLocked(id string, logicalID uint32) {
	if logicalID == 0 {
		return
	}
	if h.logicalOwners[logicalID] == id {
		delete(h.logicalOwners, logicalID)
	}
}
func (h *Handlers) retireLogicalIDLocked(id string, logicalID uint32) {
	h.forgetLogicalIDLocked(id, logicalID)
	if logicalID == 0 {
		return
	}
	if h.pendingLogicalIDs == nil {
		h.pendingLogicalIDs = make(map[uint32]bool)
	}
	h.pendingLogicalIDs[logicalID] = true
}
func (h *Handlers) logicalCapacity() int {
	if h.logicalStateCapacity > 0 {
		return h.logicalStateCapacity
	}
	capacity := 1000000 // Two MAX_RULES logical-state slots in the B1 ABI.
	if h.idCounts != nil && int(h.idCounts.MaxEntries()) < capacity {
		capacity = int(h.idCounts.MaxEntries())
	}
	if h.idRLStates != nil && int(h.idRLStates.MaxEntries()) < capacity {
		capacity = int(h.idRLStates.MaxEntries())
	}
	return capacity
}
func (h *Handlers) logicalUnionLocked(next map[uint32]bool) int {
	ids := make(map[uint32]bool, len(h.logicalOwners)+len(next)+len(h.pendingLogicalIDs))
	for id := range h.logicalOwners {
		ids[id] = true
	}
	for id := range next {
		ids[id] = true
	}
	for id := range h.pendingLogicalIDs {
		ids[id] = true
	}
	return len(ids)
}

// payPendingLogicalLocked requires syncMu, publishMu and rulesMu. Revalidation
// uses the current owner index directly; it never recursively takes rulesMu.
func (h *Handlers) payPendingLogicalLocked() error {
	var counts, rates logicalStateMap
	if h.idCounts != nil {
		counts = h.idCounts
	}
	if h.idRLStates != nil {
		rates = h.idRLStates
	}
	return h.payPendingLogicalWithMapsLocked(counts, rates)
}

// The key-only interface also permits state-machine tests without a kernel.
// The caller retains all three writer locks through receipt and revalidation.
func (h *Handlers) payPendingLogicalWithMapsLocked(counts, rates logicalStateMap) error {
	if len(h.pendingLogicalIDs) == 0 {
		return nil
	}
	if err := h.awaitQuiescence(); err != nil {
		h.logicalPaymentFailures++
		return err
	}
	return h.reclaimPendingLogicalWithMapsLocked(counts, rates)
}

// Requires a successful receipt after the last flip/deletion and S+P+R.
// Commit reuses its successful Rc rather than issuing a second receipt.
func (h *Handlers) reclaimPendingLogicalLocked() error {
	var counts, rates logicalStateMap
	if h.idCounts != nil {
		counts = h.idCounts
	}
	if h.idRLStates != nil {
		rates = h.idRLStates
	}
	return h.reclaimPendingLogicalWithMapsLocked(counts, rates)
}

// Requires rulesMu; a recorded ID may remain pending after a partial failure.
func (h *Handlers) recordLogicalReclaimLocked(id uint32) {
	h.logicalReclaimSeq++
	if h.logicalReclaimedAt == nil {
		h.logicalReclaimedAt = make(map[uint32]uint64)
	}
	h.logicalReclaimedAt[id] = h.logicalReclaimSeq
}

func (h *Handlers) reclaimPendingLogicalWithMapsLocked(counts, rates logicalStateMap) error {
	if len(h.pendingLogicalIDs) == 0 {
		return nil
	}
	ids := make([]uint32, 0, len(h.pendingLogicalIDs))
	for id := range h.pendingLogicalIDs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var failures []error
	for _, id := range ids {
		// A pure POST may have re-established this owner since retirement.
		if _, valid := h.logicalOwners[id]; valid {
			delete(h.pendingLogicalIDs, id)
			continue
		}
		var failed bool
		for _, table := range []struct {
			name string
			m    logicalStateMap
		}{{"id_counts", counts}, {"id_rl_states", rates}} {
			if table.m == nil {
				failed = true
				failures = append(failures, fmt.Errorf("%s unavailable", table.name))
				continue
			}
			if err := table.m.Delete(id); err != nil && !isMapEntryMissing(err) {
				failed = true
				failures = append(failures, fmt.Errorf("%s logical ID %d: %w", table.name, id, err))
			} else if table.name == "id_counts" {
				h.recordLogicalReclaimLocked(id)
			}
		}
		if !failed {
			delete(h.pendingLogicalIDs, id)
		}
	}
	if len(failures) > 0 {
		h.logicalPaymentFailures++
	} else {
		h.logicalPayments++
	}
	return errors.Join(failures...)
}
func (h *Handlers) maybePayLogicalLocked() {
	threshold := h.logicalRetireThreshold
	if threshold <= 0 {
		threshold = 1024
	}
	if len(h.pendingLogicalIDs) < threshold {
		return
	}
	if err := h.payPendingLogicalLocked(); err != nil {
		log.Printf("[logical state] pending payment failed: %v", err)
	}
}

type logicalTableFullError struct{ Used, Capacity int }

func (e *logicalTableFullError) Error() string {
	return fmt.Sprintf("logical state capacity %d exceeds %d; batch not published", e.Used, e.Capacity)
}

// admitAtomicLogicalIDs is phase two: phase-one group failure never gets here.
// Only existing debt may be paid; the request's exiting IDs are not retired yet.
func (h *Handlers) admitAtomicLogicalIDs(rules []Rule, memos ...*atomicMemo) error {
	_, err := h.admitAtomicLogicalUsage(rules, memos...)
	return err
}

func (h *Handlers) admitAtomicLogicalUsage(rules []Rule, memos ...*atomicMemo) (int, error) {
	next := make(map[uint32]bool)
	for i, r := range rules {
		if p, err := h.prepareAtomicAt(r, i, firstMemo(memos)); err == nil && p.Rule.LogicalID != 0 {
			next[p.Rule.LogicalID] = true
		}
	}
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	a := h.newLogicalAdmissionLocked()
	for id := range next {
		a.reserve(id)
	}
	if a.used > h.logicalCapacity() {
		h.payAdmissionLocked(a)
	}
	if used := a.used; used > h.logicalCapacity() {
		return used, &logicalTableFullError{used, h.logicalCapacity()}
	}
	return a.used, nil
}

// replaceLogicalOwnersLocked runs only after the full-sync flip, with all writer
// locks held. Exiting owners include active rows left by a failed rollback.
func (h *Handlers) replaceLogicalOwnersLocked(newRules map[string]StoredRule, newCidrRules map[string]StoredCIDRRule) {
	nextOwners := make(map[uint32]string)
	for id, r := range newRules {
		if r.LogicalID != 0 {
			nextOwners[r.LogicalID] = id
		}
	}
	for id, r := range newCidrRules {
		if r.LogicalID != 0 {
			nextOwners[r.LogicalID] = id
		}
	}
	for logicalID, id := range h.logicalOwners {
		if _, live := nextOwners[logicalID]; !live {
			h.retireLogicalIDLocked(id, logicalID)
		}
	}
	h.logicalOwners = nextOwners
}
