package api

import (
	"errors"
	"fmt"
	"log"
	"sort"

	"github.com/cilium/ebpf"
)

const (
	mirrorExact = iota
	mirrorCIDR
	mirrorCondition
	mirrorCIDRCondition
)

// Bound bookkeeping independently of the number of requests. Once exceeded,
// a full alignment subsumes all keys; 4096 keeps the normal set modest while
// allowing a substantial burst of pure writes before an O(N) alignment.
const mirrorDirtyLimit = 4096

var mirrorNames = [4]string{"blacklist", "cidr_blacklist", "cond", "cidr_cond"}

// Extends StartupMap without coupling faults in iteration, deletion and write.
type ruleMirrorMap interface {
	StartupMap
	ValueSize() uint32
	MaxEntries() uint32
	Lookup(interface{}, interface{}) error
	Update(interface{}, interface{}, ebpf.MapUpdateFlags) error
	BatchLookup(*ebpf.MapBatchCursor, interface{}, interface{}, *ebpf.BatchOptions) (int, error)
	BatchUpdate(interface{}, interface{}, *ebpf.BatchOptions) (int, error)
	BatchDelete(interface{}, *ebpf.BatchOptions) (int, error)
}

func (h *Handlers) ruleTablesAt(slot int) [4]*ebpf.Map {
	if slot == 0 {
		return [4]*ebpf.Map{h.blacklist, h.cidrBlacklist, h.condA, h.cidrCondA}
	}
	return [4]*ebpf.Map{h.blacklistB, h.cidrBlacklistB, h.condB, h.cidrCondB}
}

func (h *Handlers) mirrorTable(slot, kind int) ruleMirrorMap {
	if h.mirrorTableFixture != nil {
		return h.mirrorTableFixture(slot, kind)
	}
	m := h.ruleTablesAt(slot)[kind]
	if m == nil {
		return nil
	}
	return m
}

func mirrorKeys(m StartupMap) ([][]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("map unavailable")
	}
	var cursor interface{}
	var keys [][]byte
	for {
		key := make([]byte, m.KeySize())
		if err := m.NextKey(cursor, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return keys, nil
			}
			return nil, fmt.Errorf("enumerate: %w", err)
		}
		keys = append(keys, key)
		cursor = key
	}
}

func mirrorSnapshot(m ruleMirrorMap) (map[string][]byte, error) {
	keys, err := mirrorKeys(m)
	if err != nil {
		return nil, err
	}
	rows := make(map[string][]byte, len(keys))
	for _, key := range keys {
		value := make([]byte, m.ValueSize())
		if err := m.Lookup(key, &value); err != nil {
			return nil, fmt.Errorf("read active row: %w", err)
		}
		rows[string(key)] = value
	}
	return rows, nil
}

// Each table deletes first, then writes. The source is the actual active map,
// including orphan rows unknown to the in-memory rule indexes.
func alignRuleTable(active, shadow ruleMirrorMap) (int, error) {
	rows, err := mirrorSnapshot(active)
	if err != nil {
		return 0, err
	}
	keys, err := mirrorKeys(shadow)
	if err != nil {
		return 0, err
	}
	for _, key := range keys {
		if _, live := rows[string(key)]; !live {
			if err := shadow.Delete(key); err != nil {
				return 0, fmt.Errorf("delete shadow row: %w", err)
			}
		}
	}
	for _, key := range sortedMirrorKeys(rows) {
		if err := shadow.Update([]byte(key), rows[key], ebpf.UpdateAny); err != nil {
			return 0, fmt.Errorf("write shadow row: %w", err)
		}
	}
	return len(rows), nil
}

func sortedMirrorKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (h *Handlers) markMirrorDirty(kind int, key []byte) {
	if h.mirrorDirtyTestHook != nil {
		h.mirrorDirtyTestHook(kind, key)
	}
	if h.mirrorDirty[kind] == nil {
		h.mirrorDirty[kind] = make(map[string]struct{})
	}
	h.mirrorDirty[kind][string(key)] = struct{}{}
	n := 0
	for _, keys := range h.mirrorDirty {
		n += len(keys)
	}
	if n > mirrorDirtyLimit {
		h.mirrorReady = false
		h.mirrorDirty = [4]map[string]struct{}{}
	}
}

func (h *Handlers) alignWholeRuleMirrorLocked() error {
	h.mirrorReady = false
	h.mirrorAlignments++
	active := int(h.activeRuleSlot.Load())
	var counts [4]int
	for kind := range counts {
		n, err := alignRuleTable(h.mirrorTable(active, kind), h.mirrorTable(1-active, kind))
		if err != nil {
			h.mirrorFailures++
			return fmt.Errorf("%s alignment: %w", mirrorNames[kind], err)
		}
		counts[kind] = n
	}
	h.ruleRowCounts, h.ruleRowCountsKnown = counts, true
	h.mirrorDirty, h.mirrorDebt = [4]map[string]struct{}{}, [4]map[string]struct{}{}
	h.mirrorReady = true
	return nil
}

func alignRuleKeys(active, shadow ruleMirrorMap, keys map[string]struct{}) error {
	rows := make(map[string][]byte, len(keys))
	var deletes []string
	for _, key := range sortedMirrorKeys(keys) {
		value := make([]byte, active.ValueSize())
		if err := active.Lookup([]byte(key), &value); errors.Is(err, ebpf.ErrKeyNotExist) {
			deletes = append(deletes, key)
		} else if err != nil {
			return fmt.Errorf("read dirty active row: %w", err)
		} else {
			rows[key] = value
		}
	}
	for _, key := range deletes {
		if err := shadow.Delete([]byte(key)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete dirty shadow row: %w", err)
		}
	}
	for _, key := range sortedMirrorKeys(rows) {
		if err := shadow.Update([]byte(key), rows[key], ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write dirty shadow row: %w", err)
		}
	}
	return nil
}

func (h *Handlers) catchUpRuleMirrorLocked() error {
	if !h.mirrorReady {
		log.Printf("[commit mirror] full alignment required")
		return h.alignWholeRuleMirrorLocked()
	}
	active := int(h.activeRuleSlot.Load())
	for kind := range h.mirrorDirty {
		keys := make(map[string]struct{}, len(h.mirrorDirty[kind])+len(h.mirrorDebt[kind]))
		for key := range h.mirrorDirty[kind] {
			keys[key] = struct{}{}
		}
		for key := range h.mirrorDebt[kind] {
			keys[key] = struct{}{}
		}
		if len(keys) == 0 {
			continue
		}
		if err := alignRuleKeys(h.mirrorTable(active, kind), h.mirrorTable(1-active, kind), keys); err != nil {
			h.mirrorReady = false
			h.mirrorFailures++
			return fmt.Errorf("%s catch-up: %w", mirrorNames[kind], err)
		}
	}
	h.mirrorDirty, h.mirrorDebt = [4]map[string]struct{}{}, [4]map[string]struct{}{}
	return nil
}

type commitPrefix struct {
	Prefix string
	Src    bool
}

func (h *Handlers) finishAtomicMirrorLocked(rows atomicTableRows) {
	if err := h.alignAtomicMirrorLocked(rows); err != nil {
		log.Printf("[AtomicSync Step 6] mirror alignment deferred: %v", err)
	}
	h.finishLogicalReconcileLocked(h.reconcileLogicalState())
}

// syncMu and publishMu remain held while publishing reconciliation results.
func (h *Handlers) finishLogicalReconcileLocked(deleted []uint32, err error) {
	h.rulesMu.Lock()
	defer h.rulesMu.Unlock()
	for _, id := range deleted {
		h.recordLogicalReclaimLocked(id)
	}
	if err == nil {
		for id := range h.pendingLogicalIDs {
			if _, live := h.logicalOwners[id]; !live {
				h.recordLogicalReclaimLocked(id)
			}
		}
		clear(h.pendingLogicalIDs)
	}
}
