package api

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
)

const atomicBatchSize = 4096

type atomicTableRows [4]map[string][]byte

func newAtomicTableRows() (rows atomicTableRows) {
	for i := range rows {
		rows[i] = make(map[string][]byte)
	}
	return
}

// Fixed-width array elements are required: []byte would count bytes as rows.
func atomicBatchBuffer(width uint32, count int) reflect.Value {
	return reflect.MakeSlice(reflect.SliceOf(reflect.ArrayOf(int(width), reflect.TypeOf(byte(0)))), count, count)
}

func atomicBatchBytes(v reflect.Value, i int) []byte {
	x := v.Index(i)
	return x.Slice(0, x.Len()).Bytes()
}

func atomicReadTable(m ruleMirrorMap) (map[string][]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("enumerate: map unavailable")
	}
	for size := atomicBatchSize; ; size *= 2 {
		rows := make(map[string][]byte)
		cursor := new(ebpf.MapBatchCursor)
		keys, values := atomicBatchBuffer(m.KeySize(), size), atomicBatchBuffer(m.ValueSize(), size)
		for {
			n, err := m.BatchLookup(cursor, keys.Interface(), values.Interface(), nil)
			for i := 0; i < n; i++ {
				rows[string(atomicBatchBytes(keys, i))] = bytes.Clone(atomicBatchBytes(values, i))
			}
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return rows, nil
			}
			if errors.Is(err, syscall.ENOSPC) && size < 65536 {
				break // Discard this table's partial scan and restart with a new cursor.
			}
			if err != nil {
				return nil, fmt.Errorf("enumerate: %w", err)
			}
		}
	}
}

// New prefixes have never-used IDs, so no residual key can refer to them.
// This is a keep-set only; Step 2 builds the authoritative expected bytes.
func (h *Handlers) atomicKeepKeys(rules []Rule, groups map[int]*atomicConditionGroup, memo *atomicMemo) atomicTableRows {
	keep := newAtomicTableRows()
	for i, rule := range rules {
		p, err := h.prepareAtomicAt(rule, i, memo)
		if err != nil || validateLogicalID(p.Rule.LogicalID) != nil {
			continue
		}
		kind, key := mirrorExact, ruleKeyToBytes(p.Exact)
		if p.IsCIDR {
			var ok bool
			if p.Rule.SrcCIDR != "" {
				p.CIDR.SrcID, ok = h.cidrMgr.GetSrcID(p.Rule.SrcCIDR)
				if !ok {
					continue
				}
			}
			if p.Rule.DstCIDR != "" {
				p.CIDR.DstID, ok = h.cidrMgr.GetDstID(p.Rule.DstCIDR)
				if !ok {
					continue
				}
			}
			kind, key = mirrorCIDR, cidrRuleKeyToBytes(p.CIDR)
		}
		keep[kind][string(key)] = nil
		if g := groups[i]; g != nil && g.Condition {
			keep[kind+2][string(key)] = nil
		}
	}
	return keep
}

// Only rule tables use batch writes. Condition rows retain single-key calls.
// A failed batch leaves its successful prefix in the map; no rollback is tried.
func atomicWriteRows(m ruleMirrorMap, kind int, keys []string, rows map[string][]byte, remove bool) error {
	for start := 0; start < len(keys); start += atomicBatchSize {
		end := min(start+atomicBatchSize, len(keys))
		if kind >= mirrorCondition {
			for _, key := range keys[start:end] {
				var err error
				if remove {
					err = m.Delete([]byte(key))
				} else {
					err = m.Update([]byte(key), rows[key], ebpf.UpdateAny)
				}
				if err != nil {
					return err
				}
			}
			continue
		}
		kb := atomicBatchBuffer(m.KeySize(), end-start)
		vb := atomicBatchBuffer(m.ValueSize(), end-start)
		for i, key := range keys[start:end] {
			copy(atomicBatchBytes(kb, i), key)
			if !remove {
				copy(atomicBatchBytes(vb, i), rows[key])
			}
		}
		var err error
		if remove {
			_, err = m.BatchDelete(kb.Interface(), nil)
		} else {
			_, err = m.BatchUpdate(kb.Interface(), vb.Interface(), nil)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func atomicDeleteExtra(m ruleMirrorMap, kind int, have, want map[string][]byte) error {
	var keys []string
	for _, key := range sortedMirrorKeys(have) {
		if _, keep := want[key]; !keep {
			keys = append(keys, key)
		}
	}
	if err := atomicWriteRows(m, kind, keys, nil, true); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	for _, key := range keys {
		delete(have, key)
	}
	return nil
}

func (h *Handlers) prepareAtomicShadow(keep atomicTableRows) (atomicTableRows, error) {
	have := newAtomicTableRows()
	slot := 1 - int(h.activeRuleSlot.Load())
	for kind := range have {
		m := h.mirrorTable(slot, kind)
		rows, err := atomicReadTable(m)
		if err == nil {
			err = atomicDeleteExtra(m, kind, rows, keep[kind])
		}
		if err != nil {
			return have, fmt.Errorf("clear shadow %s: %w", mirrorNames[kind], err)
		}
		have[kind] = rows
	}
	return have, nil
}

func atomicWriteRow(m ruleMirrorMap, have, want map[string][]byte, key, value []byte, flags ebpf.MapUpdateFlags) error {
	k := string(key)
	want[k] = value
	if old, exists := have[k]; exists {
		if bytes.Equal(old, value) {
			return nil
		}
		flags = ebpf.UpdateExist
	}
	return m.Update(key, value, flags)
}

func (h *Handlers) readAtomicShadow(want atomicTableRows) (atomicTableRows, error) {
	got := newAtomicTableRows()
	slot := 1 - int(h.activeRuleSlot.Load())
	for kind := range got {
		rows, err := atomicReadTable(h.mirrorTable(slot, kind))
		if err == nil && len(rows) != len(want[kind]) {
			err = fmt.Errorf("row count %d, want %d", len(rows), len(want[kind]))
		}
		if err == nil {
			for key, value := range want[kind] {
				if !bytes.Equal(rows[key], value) {
					err = fmt.Errorf("row bytes differ")
					break
				}
			}
		}
		if err != nil {
			return got, fmt.Errorf("verify shadow %s: %w", mirrorNames[kind], err)
		}
		got[kind] = rows
	}
	return got, nil
}

func (h *Handlers) alignAtomicMirrorLocked(want atomicTableRows) error {
	h.mirrorReady = false
	h.mirrorAlignments++
	slot := 1 - int(h.activeRuleSlot.Load())
	var counts [4]int
	for kind := range want {
		m := h.mirrorTable(slot, kind)
		have, err := atomicReadTable(m)
		if err == nil {
			err = atomicDeleteExtra(m, kind, have, want[kind])
		}
		if err == nil {
			var keys []string
			for _, key := range sortedMirrorKeys(want[kind]) {
				if !bytes.Equal(have[key], want[kind][key]) {
					keys = append(keys, key)
				}
			}
			err = atomicWriteRows(m, kind, keys, want[kind], false)
		}
		if err != nil {
			h.mirrorFailures++
			return fmt.Errorf("%s alignment: %w", mirrorNames[kind], err)
		}
		counts[kind] = len(want[kind])
	}
	h.ruleRowCounts, h.ruleRowCountsKnown = counts, true
	h.mirrorDirty, h.mirrorDebt = [4]map[string]struct{}{}, [4]map[string]struct{}{}
	h.mirrorReady = true
	return nil
}
