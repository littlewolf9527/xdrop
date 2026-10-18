package api

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

type quiescer interface{ Quiesce() error }

var errQuiescence = errors.New("quiescence_failed")

// Test observer only; it cannot change the production operation or its result.
var atomicStageTestHook func(string, *Handlers)

func (h *Handlers) observeAtomicStage(stage string) {
	if atomicStageTestHook != nil {
		atomicStageTestHook(stage, h)
	}
}

type atomicDuplicateLogicalIDError struct {
	LogicalID uint32
	Conflicts [2]atomicRuleIdentity
}

func (e *atomicDuplicateLogicalIDError) Error() string {
	return fmt.Sprintf("duplicate logical ID %d between rule %q at index %d and rule %q at index %d; batch not published",
		e.LogicalID, e.Conflicts[0].ID, *e.Conflicts[0].Index, e.Conflicts[1].ID, *e.Conflicts[1].Index)
}

func checkAtomicLogicalIDs(rules []Rule) error {
	owners := make(map[uint32]int)
	for index, r := range rules {
		if r.LogicalID == 0 {
			continue
		}
		if first, ok := owners[r.LogicalID]; ok {
			return &atomicDuplicateLogicalIDError{r.LogicalID, [2]atomicRuleIdentity{{ID: rules[first].ID, Index: &first}, {ID: r.ID, Index: &index}}}
		}
		owners[r.LogicalID] = index
	}
	return nil
}

type kernelQuiescer struct{ outer, inner *ebpf.Map }

// Tests may replace the factory before invoking the production startup path.
var newQuiescer = func() (quiescer, error) { return newKernelQuiescer() }

func newKernelQuiescer() (*kernelQuiescer, error) {
	innerSpec := &ebpf.MapSpec{Name: "xdrop_rcu_inner", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
	inner, err := ebpf.NewMap(innerSpec)
	if err != nil {
		return nil, fmt.Errorf("create receipt inner map: %w", err)
	}
	outer, err := ebpf.NewMap(&ebpf.MapSpec{Name: "xdrop_rcu", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: innerSpec})
	if err != nil {
		inner.Close()
		return nil, fmt.Errorf("create receipt outer map: %w", err)
	}
	return &kernelQuiescer{outer: outer, inner: inner}, nil
}

func (q *kernelQuiescer) Quiesce() error {
	return q.outer.Update(uint32(0), q.inner, ebpf.UpdateAny)
}

func (q *kernelQuiescer) Close() error { return errors.Join(q.outer.Close(), q.inner.Close()) }

// awaitQuiescence requires publishMu, held across all attempts and the caller's
// subsequent reclamation. Failure preserves the pending state.
func (h *Handlers) awaitQuiescence() error {
	if h.quiescer == nil {
		return fmt.Errorf("quiescence receipt unavailable")
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = h.quiescer.Quiesce(); err == nil {
			h.quiescenceConfirmed = true
			return nil
		}
	}
	return fmt.Errorf("quiescence failed after 3 attempts: %w", err)
}

func (h *Handlers) activeCond() *ebpf.Map {
	if int(h.activeRuleSlot.Load()) == 0 {
		return h.condA
	}
	return h.condB
}
func (h *Handlers) shadowCond() *ebpf.Map {
	if int(h.activeRuleSlot.Load()) == 0 {
		return h.condB
	}
	return h.condA
}
func (h *Handlers) activeCidrCond() *ebpf.Map {
	if int(h.activeRuleSlot.Load()) == 0 {
		return h.cidrCondA
	}
	return h.cidrCondB
}
func (h *Handlers) shadowCidrCond() *ebpf.Map {
	if int(h.activeRuleSlot.Load()) == 0 {
		return h.cidrCondB
	}
	return h.cidrCondA
}

// Key-only traversal is required for PERCPU maps: clearMap's value buffer is
// unsuitable. Collect before deleting, so deleting the cursor cannot restart
// enumeration. These maps are populated lazily; valid IDs need not have keys.
type logicalStateMap interface {
	NextKey(interface{}, interface{}) error
	Delete(interface{}) error
}

func reconcileLogicalKeys(m logicalStateMap, valid map[uint32]bool) error {
	_, err := reconcileLogicalKeysDeleted(m, valid)
	return err
}

func reconcileLogicalKeysDeleted(m logicalStateMap, valid map[uint32]bool) ([]uint32, error) {
	var cursor interface{}
	var stale []uint32
	for {
		var key uint32
		if err := m.NextKey(cursor, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("enumerate logical state: %w", err)
		}
		if !valid[key] {
			stale = append(stale, key)
		}
		cursor = key
	}
	var failures []error
	deleted := stale[:0]
	for _, key := range stale {
		if err := m.Delete(key); err != nil && !isMapEntryMissing(err) {
			failures = append(failures, fmt.Errorf("delete logical ID %d: %w", key, err))
		} else {
			deleted = append(deleted, key)
		}
	}
	return deleted, errors.Join(failures...)
}

func (h *Handlers) reconcileLogicalState() ([]uint32, error) {
	valid := make(map[uint32]bool)
	h.rulesMu.RLock()
	for _, r := range h.rules {
		if r.LogicalID != 0 {
			valid[r.LogicalID] = true
		}
	}
	for _, r := range h.cidrRules {
		if r.LogicalID != 0 {
			valid[r.LogicalID] = true
		}
	}
	h.rulesMu.RUnlock()
	var failures []error
	var deleted []uint32
	for _, table := range []struct {
		name string
		m    *ebpf.Map
	}{{"id_rl_states", h.idRLStates}, {"id_counts", h.idCounts}} {
		removed, err := reconcileLogicalKeysDeleted(table.m, valid)
		if table.name == "id_counts" {
			deleted = removed
		}
		if err != nil {
			log.Printf("[AtomicSync Step 6] %s reconciliation: %v", table.name, err)
			failures = append(failures, err)
		}
	}
	return deleted, errors.Join(failures...)
}
