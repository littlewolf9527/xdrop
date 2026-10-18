package api

import (
	"fmt"
	"log"
)

// validateLogicalID is independent of duplicate-ID and group validation.
// Callers place it after their existing per-item validation, before any write.
func validateLogicalID(id uint32) error {
	if id == 0 {
		return fmt.Errorf("logical_id must be nonzero")
	}
	return nil
}

// logicalAdmission is request-local. Writers hold syncMu throughout its life;
// constructing or reserving requires publishMu and rulesMu as well.
// Count the base union without copying the owner table; writers retain all locks.
type logicalAdmission struct {
	owners   map[uint32]string
	pending  map[uint32]bool
	used     int
	reserved map[uint32]bool
	paid     bool
}

func (h *Handlers) newLogicalAdmissionLocked() *logicalAdmission {
	a := &logicalAdmission{owners: h.logicalOwners, pending: h.pendingLogicalIDs, used: len(h.logicalOwners), reserved: make(map[uint32]bool)}
	for id := range h.pendingLogicalIDs {
		if _, live := h.logicalOwners[id]; !live {
			a.used++
		}
	}
	return a
}

// Payment may remove debt but never current owners or this request's accepted
// reservations. Update only the old pending subset, without rescanning owners.
func (h *Handlers) payAdmissionLocked(a *logicalAdmission) {
	a.paid = true
	pending := make([]uint32, 0, len(h.pendingLogicalIDs))
	for id := range h.pendingLogicalIDs {
		pending = append(pending, id)
	}
	if err := h.payPendingLogicalLocked(); err != nil {
		log.Printf("[logical state] admission payment failed: %v", err)
	}
	for _, id := range pending {
		if _, live := h.logicalOwners[id]; !live && !h.pendingLogicalIDs[id] && !a.reserved[id] {
			a.used--
		}
	}
}

func (a *logicalAdmission) reserve(id uint32) {
	_, pending := a.pending[id]
	if _, live := a.owners[id]; !live && !pending && !a.reserved[id] {
		a.used++
	}
	a.reserved[id] = true
}
