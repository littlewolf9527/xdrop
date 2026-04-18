// Package cidr implements CIDR ID allocation and LPM Trie management for XDrop.
//
// Two-stage identity lookup: IP in LPM Trie → integer ID, then (ID, port, proto)
// in hash map for exact match. IDs are Node-local, monotonically increasing, and
// never reused after deletion.
package cidr

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/dropbox/goebpf"
)

// Manager manages CIDR → ID mappings and LPM Trie operations.
// IDs start from 1, 0 is reserved as wildcard/unmatched.
type Manager struct {
	mu sync.RWMutex

	srcV4CIDRs map[string]uint32 // normalized CIDR → id
	dstV4CIDRs map[string]uint32
	srcV6CIDRs map[string]uint32
	dstV6CIDRs map[string]uint32

	srcV4Refs map[string]int // reference count per CIDR
	dstV4Refs map[string]int
	srcV6Refs map[string]int
	dstV6Refs map[string]int

	nextID uint32 // monotonically increasing, never reused

	srcV4Trie goebpf.Map
	dstV4Trie goebpf.Map
	srcV6Trie goebpf.Map
	dstV6Trie goebpf.Map
}

// NewManager creates a new CIDR Manager with trie map references.
func NewManager(srcV4, dstV4, srcV6, dstV6 goebpf.Map) *Manager {
	return &Manager{
		srcV4CIDRs: make(map[string]uint32),
		dstV4CIDRs: make(map[string]uint32),
		srcV6CIDRs: make(map[string]uint32),
		dstV6CIDRs: make(map[string]uint32),
		srcV4Refs:  make(map[string]int),
		dstV4Refs:  make(map[string]int),
		srcV6Refs:  make(map[string]int),
		dstV6Refs:  make(map[string]int),
		nextID:     1, // 0 is reserved
		srcV4Trie:  srcV4,
		dstV4Trie:  dstV4,
		srcV6Trie:  srcV6,
		dstV6Trie:  dstV6,
	}
}

// AllocSrcID allocates or returns existing src CIDR ID, writes trie entry.
// cidr must be pre-normalized via NormalizeCIDR.
func (m *Manager) AllocSrcID(cidr string) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	isV6 := isIPv6CIDR(cidr)
	cidrs, refs, trie := m.getSrcMaps(isV6)

	if id, ok := cidrs[cidr]; ok {
		refs[cidr]++
		return id, nil
	}

	id := m.nextID
	m.nextID++

	if err := m.writeTrie(trie, cidr, id, isV6); err != nil {
		return 0, fmt.Errorf("failed to write src trie for %s: %w", cidr, err)
	}

	cidrs[cidr] = id
	refs[cidr] = 1
	return id, nil
}

// AllocDstID allocates or returns existing dst CIDR ID, writes trie entry.
func (m *Manager) AllocDstID(cidr string) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	isV6 := isIPv6CIDR(cidr)
	cidrs, refs, trie := m.getDstMaps(isV6)

	if id, ok := cidrs[cidr]; ok {
		refs[cidr]++
		return id, nil
	}

	id := m.nextID
	m.nextID++

	if err := m.writeTrie(trie, cidr, id, isV6); err != nil {
		return 0, fmt.Errorf("failed to write dst trie for %s: %w", cidr, err)
	}

	cidrs[cidr] = id
	refs[cidr] = 1
	return id, nil
}

// ReleaseSrcID decrements ref count; deletes trie entry when it reaches zero.
// Mutation order: when this release would drop the refcount to zero, the trie
// delete is attempted first. On trie failure no map state is changed, so the
// caller can safely retry (refs[cidr] stays at its pre-call value).
func (m *Manager) ReleaseSrcID(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	isV6 := isIPv6CIDR(cidr)
	cidrs, refs, trie := m.getSrcMaps(isV6)

	ref, ok := refs[cidr]
	if !ok {
		return fmt.Errorf("src CIDR %s not found", cidr)
	}

	if ref <= 1 {
		if err := m.deleteTrie(trie, cidr, isV6); err != nil {
			return fmt.Errorf("failed to delete src trie for %s: %w", cidr, err)
		}
		delete(cidrs, cidr)
		delete(refs, cidr)
		return nil
	}
	refs[cidr] = ref - 1
	return nil
}

// ReleaseDstID decrements ref count; deletes trie entry when it reaches zero.
// Same mutation-order guarantee as ReleaseSrcID: trie delete happens before
// any local state change, so a failed release is safely retryable.
func (m *Manager) ReleaseDstID(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	isV6 := isIPv6CIDR(cidr)
	cidrs, refs, trie := m.getDstMaps(isV6)

	ref, ok := refs[cidr]
	if !ok {
		return fmt.Errorf("dst CIDR %s not found", cidr)
	}

	if ref <= 1 {
		if err := m.deleteTrie(trie, cidr, isV6); err != nil {
			return fmt.Errorf("failed to delete dst trie for %s: %w", cidr, err)
		}
		delete(cidrs, cidr)
		delete(refs, cidr)
		return nil
	}
	refs[cidr] = ref - 1
	return nil
}

// ListSrcCIDRs returns all src CIDRs (both v4 and v6).
func (m *Manager) ListSrcCIDRs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, 0, len(m.srcV4CIDRs)+len(m.srcV6CIDRs))
	for c := range m.srcV4CIDRs {
		result = append(result, c)
	}
	for c := range m.srcV6CIDRs {
		result = append(result, c)
	}
	return result
}

// ListDstCIDRs returns all dst CIDRs (both v4 and v6).
func (m *Manager) ListDstCIDRs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, 0, len(m.dstV4CIDRs)+len(m.dstV6CIDRs))
	for c := range m.dstV4CIDRs {
		result = append(result, c)
	}
	for c := range m.dstV6CIDRs {
		result = append(result, c)
	}
	return result
}

// GetSrcID returns the ID for a src CIDR without allocating.
func (m *Manager) GetSrcID(cidr string) (uint32, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if isIPv6CIDR(cidr) {
		id, ok := m.srcV6CIDRs[cidr]
		return id, ok
	}
	id, ok := m.srcV4CIDRs[cidr]
	return id, ok
}

// GetDstID returns the ID for a dst CIDR without allocating.
func (m *Manager) GetDstID(cidr string) (uint32, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if isIPv6CIDR(cidr) {
		id, ok := m.dstV6CIDRs[cidr]
		return id, ok
	}
	id, ok := m.dstV4CIDRs[cidr]
	return id, ok
}

// ClearAll removes all CIDR entries from tries and resets state.
// Used during FullSync to cleanly rebuild.
func (m *Manager) ClearAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Delete all trie entries (best-effort)
	for cidr := range m.srcV4CIDRs {
		m.deleteTrie(m.srcV4Trie, cidr, false)
	}
	for cidr := range m.dstV4CIDRs {
		m.deleteTrie(m.dstV4Trie, cidr, false)
	}
	for cidr := range m.srcV6CIDRs {
		m.deleteTrie(m.srcV6Trie, cidr, true)
	}
	for cidr := range m.dstV6CIDRs {
		m.deleteTrie(m.dstV6Trie, cidr, true)
	}

	// Reset maps (don't reset nextID to preserve monotonic guarantee)
	m.srcV4CIDRs = make(map[string]uint32)
	m.dstV4CIDRs = make(map[string]uint32)
	m.srcV6CIDRs = make(map[string]uint32)
	m.dstV6CIDRs = make(map[string]uint32)
	m.srcV4Refs = make(map[string]int)
	m.dstV4Refs = make(map[string]int)
	m.srcV6Refs = make(map[string]int)
	m.dstV6Refs = make(map[string]int)
}

// ============ Static helpers ============

// NormalizeCIDR returns the network address form of a CIDR.
// e.g., "192.168.1.5/24" → "192.168.1.0/24"
func NormalizeCIDR(cidr string) (string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %s", cidr)
	}
	return network.String(), nil
}

// CheckOverlap checks for strict containment between newCIDR and existing CIDRs.
// Returns the conflicting CIDR string if overlap found, empty string otherwise.
// Same CIDR is NOT a conflict (handled by duplicate key check).
func CheckOverlap(newCIDR string, existingCIDRs []string) (string, error) {
	_, newNet, err := net.ParseCIDR(newCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %s", newCIDR)
	}

	for _, existing := range existingCIDRs {
		_, existNet, err := net.ParseCIDR(existing)
		if err != nil {
			continue
		}

		// Same CIDR → not a conflict
		if newNet.String() == existNet.String() {
			continue
		}

		// Strict containment: one contains the other
		if existNet.Contains(newNet.IP) || newNet.Contains(existNet.IP) {
			return existing, nil
		}
	}
	return "", nil
}

// ============ Internal helpers ============

func (m *Manager) getSrcMaps(isV6 bool) (map[string]uint32, map[string]int, goebpf.Map) {
	if isV6 {
		return m.srcV6CIDRs, m.srcV6Refs, m.srcV6Trie
	}
	return m.srcV4CIDRs, m.srcV4Refs, m.srcV4Trie
}

func (m *Manager) getDstMaps(isV6 bool) (map[string]uint32, map[string]int, goebpf.Map) {
	if isV6 {
		return m.dstV6CIDRs, m.dstV6Refs, m.dstV6Trie
	}
	return m.dstV4CIDRs, m.dstV4Refs, m.dstV4Trie
}

// writeTrie writes a CIDR → ID mapping to the LPM trie.
// Uses goebpf.CreateLPMtrieKey for key construction.
func (m *Manager) writeTrie(trie goebpf.Map, cidr string, id uint32, isV6 bool) error {
	key := goebpf.CreateLPMtrieKey(cidr)

	value := make([]byte, 4)
	binary.LittleEndian.PutUint32(value, id)

	return trie.Upsert(key, value)
}

// deleteTrie removes a CIDR entry from the LPM trie.
func (m *Manager) deleteTrie(trie goebpf.Map, cidr string, isV6 bool) error {
	key := goebpf.CreateLPMtrieKey(cidr)
	return trie.Delete(key)
}

// isIPv6CIDR checks if a CIDR string is IPv6.
func isIPv6CIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.IP.To4() == nil
}
