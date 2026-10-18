package cidr

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// TrieEntries is a request-local snapshot, never retained by Manager.
type TrieEntries [4]map[string]uint32

// Snapshot excludes references retiring in this transaction, after reservations.
func (m *Manager) Snapshot(exclude [2][]string) TrieEntries {
	var result TrieEntries
	if m == nil {
		return result
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range result {
		p := prefixIdentity{Src: i%2 == 0, V6: i >= 2}
		ids, refs, _ := m.mapsFor(p)
		removed := make(map[string]int)
		for _, prefix := range exclude[i%2] {
			removed[prefix]++
		}
		result[i] = make(map[string]uint32)
		for prefix, id := range ids {
			if refs[prefix] > removed[prefix] {
				key, _ := trieKey(prefix, p.V6) // reserve already validated the prefix
				result[i][string(key)] = id
			}
		}
	}
	return result
}

func (m *Manager) Invalidate(slot int) {
	if m != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.known[slot] = false
	}
}

// CatchUp is independent of rule-row mirror readiness. The caller has R0.
func (m *Manager) CatchUp(slot int) error {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	known := m.known[slot]
	m.mu.RUnlock()
	if known {
		return nil
	}
	return m.Align(slot, m.Snapshot([2][]string{}))
}

func (m *Manager) Align(slot int, want TrieEntries) error {
	m.Invalidate(slot)
	return m.Apply(slot, TrieEntries{}, want)
}

// Apply uses a transaction-local delta when known, actual keys/values otherwise.
// Every table deletes before it writes, including full-capacity unknown copies.
func (m *Manager) Apply(slot int, before, want TrieEntries) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	known := m.known[slot]
	m.known[slot] = false
	desired := want
	for i, table := range m.tries[slot] {
		if table == nil {
			return fmt.Errorf("trie copy %d table %d unavailable", slot, i)
		}
		have := before[i]
		if known {
			have, want[i] = make(map[string]uint32), make(map[string]uint32)
			// Scope only K copies; U still reconciles the complete desired set.
			for key, id := range before[i] {
				if id != desired[i][key] {
					have[key] = id
				}
			}
			for key, id := range desired[i] {
				if id != before[i][key] {
					want[i][key] = id
				}
			}
		} else {
			have = make(map[string]uint32)
			var cursor interface{}
			for {
				key := make([]byte, table.KeySize())
				if err := table.NextKey(cursor, &key); err != nil {
					if errors.Is(err, ebpf.ErrKeyNotExist) {
						break
					}
					return err
				}
				var id uint32
				if err := table.Lookup(key, &id); err != nil {
					return err
				}
				have[string(key)] = id
				cursor = key
			}
		}
		for key := range have {
			if _, keep := want[i][key]; !keep {
				if err := table.Delete([]byte(key)); err != nil {
					return err
				}
			}
		}
		for key, id := range want[i] {
			if have[key] != id {
				if err := table.Put([]byte(key), id); err != nil {
					return err
				}
			}
		}
	}
	m.known[slot] = true
	return nil
}
