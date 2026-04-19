// Package cidr implements CIDR ID allocation and LPM Trie management for XDrop.
//
// Two-stage identity lookup: IP in LPM Trie → integer ID, then (ID, port, proto)
// in hash map for exact match. IDs are Node-local, monotonically increasing, and
// never reused after deletion.
package cidr

import (
	"fmt"
	"net"
	"sync"
)

// TrieWriter is the narrow map interface the Manager needs for LPM trie
// mutation. Extracted per proposal §5.3 / §5.7 so unit tests can inject a
// two-method fake instead of having to satisfy the full `*ebpf.Map`
// surface. `*ebpf.Map` satisfies this implicitly.
type TrieWriter interface {
	// Put creates or overwrites the trie entry (upsert semantics, matching
	// the pre-migration goebpf Upsert call).
	Put(key, value interface{}) error
	// Delete removes the trie entry. Returns an error on missing key; the
	// caller decides whether that is fatal.
	Delete(key interface{}) error
}

// lpmV4Key mirrors the kernel `struct bpf_lpm_trie_key` for IPv4 (8 bytes:
// 4-byte little-endian prefix length, 4-byte IP address in network byte
// order). Layout must match goebpf's prior on-wire bytes exactly; see
// node/agent/cidr/testdata/lpm_keys_goebpf.json for the ground-truth
// fixture.
type lpmV4Key struct {
	PrefixLen uint32
	Data      [4]byte
}

// lpmV6Key is the IPv6 variant (20 bytes: 4-byte LE prefix length, 16-byte
// IPv6 address).
type lpmV6Key struct {
	PrefixLen uint32
	Data      [16]byte
}

// makeLPMv4Key builds an IPv4 LPM trie key from a CIDR string.
func makeLPMv4Key(cidr string) (lpmV4Key, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return lpmV4Key{}, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return lpmV4Key{}, fmt.Errorf("CIDR %q is not IPv4", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	var k lpmV4Key
	k.PrefixLen = uint32(ones)
	copy(k.Data[:], ip4)
	return k, nil
}

// makeLPMv6Key builds an IPv6 LPM trie key from a CIDR string.
func makeLPMv6Key(cidr string) (lpmV6Key, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return lpmV6Key{}, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ip16 := ipnet.IP.To16()
	if ip16 == nil {
		return lpmV6Key{}, fmt.Errorf("CIDR %q is not IPv6", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	var k lpmV6Key
	k.PrefixLen = uint32(ones)
	copy(k.Data[:], ip16)
	return k, nil
}

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

	srcV4Trie TrieWriter
	dstV4Trie TrieWriter
	srcV6Trie TrieWriter
	dstV6Trie TrieWriter
}

// NewManager creates a new CIDR Manager with trie map references.
// Production wiring passes four `*ebpf.Map` values; tests pass fakes.
func NewManager(srcV4, dstV4, srcV6, dstV6 TrieWriter) *Manager {
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

func (m *Manager) getSrcMaps(isV6 bool) (map[string]uint32, map[string]int, TrieWriter) {
	if isV6 {
		return m.srcV6CIDRs, m.srcV6Refs, m.srcV6Trie
	}
	return m.srcV4CIDRs, m.srcV4Refs, m.srcV4Trie
}

func (m *Manager) getDstMaps(isV6 bool) (map[string]uint32, map[string]int, TrieWriter) {
	if isV6 {
		return m.dstV6CIDRs, m.dstV6Refs, m.dstV6Trie
	}
	return m.dstV4CIDRs, m.dstV4Refs, m.dstV4Trie
}

// writeTrie writes a CIDR → ID mapping to the LPM trie. Uses the hand-rolled
// struct keys (see §5.4). cilium/ebpf's marshaller serialises the struct
// into the kernel's bpf_lpm_trie_key layout (u32 LE prefix + IP bytes) —
// byte-identical to goebpf's former encoding (verified in
// cidr/testdata/lpm_keys_goebpf.json fixture).
func (m *Manager) writeTrie(trie TrieWriter, cidr string, id uint32, isV6 bool) error {
	if isV6 {
		k, err := makeLPMv6Key(cidr)
		if err != nil {
			return err
		}
		return trie.Put(k, id)
	}
	k, err := makeLPMv4Key(cidr)
	if err != nil {
		return err
	}
	return trie.Put(k, id)
}

// deleteTrie removes a CIDR entry from the LPM trie.
func (m *Manager) deleteTrie(trie TrieWriter, cidr string, isV6 bool) error {
	if isV6 {
		k, err := makeLPMv6Key(cidr)
		if err != nil {
			return err
		}
		return trie.Delete(k)
	}
	k, err := makeLPMv4Key(cidr)
	if err != nil {
		return err
	}
	return trie.Delete(k)
}

// isIPv6CIDR checks if a CIDR string is IPv6.
func isIPv6CIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.IP.To4() == nil
}
