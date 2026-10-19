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
)

// TrieWriter is the narrow map interface the Manager needs for LPM trie
// mutation and actual-content reconciliation. *ebpf.Map satisfies it.
type TrieWriter interface {
	KeySize() uint32
	NextKey(interface{}, interface{}) error
	Lookup(interface{}, interface{}) error
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
	ones, bits := ipnet.Mask.Size()
	ip4 := ipnet.IP.To4()
	if bits != 32 || ip4 == nil {
		return lpmV4Key{}, fmt.Errorf("CIDR %q is not IPv4", cidr)
	}
	var k lpmV4Key
	k.PrefixLen = uint32(ones)
	copy(k.Data[:], ip4)
	return k, nil
}

// makeLPMv6Key builds an IPv6 LPM trie key from a CIDR string.
func makeLPMv6Key(cidr string) (lpmV6Key, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return lpmV6Key{}, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	ip16 := ipnet.IP.To16()
	if bits != 128 || ip.To4() != nil || ip16 == nil {
		return lpmV6Key{}, fmt.Errorf("CIDR %q is not IPv6", cidr)
	}
	var k lpmV6Key
	k.PrefixLen = uint32(ones)
	copy(k.Data[:], ip16)
	return k, nil
}

// Manager manages CIDR → ID mappings and LPM Trie operations.
// IDs start from 1, 0 is reserved as wildcard/unmatched.
type prefixIdentity struct {
	CIDR string
	Src  bool
	V6   bool
}

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
	tries  [2][4]TrieWriter
	known  [2]bool // only per-copy state; false requires actual-content reconciliation
}

// NewManager creates a new CIDR Manager with trie map references.
// Both copies start unknown, including after startup clearing or fresh maps.
func NewManager(srcV4, dstV4, srcV6, dstV6, srcV4B, dstV4B, srcV6B, dstV6B TrieWriter) *Manager {
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
		tries:      [2][4]TrieWriter{{srcV4, dstV4, srcV6, dstV6}, {srcV4B, dstV4B, srcV6B, dstV6B}},
	}
}

// ReserveSrcID borrows one reference without publishing a new prefix. Every
// successful reservation must be committed or matched by UndoSrcReservation.
func (m *Manager) ReserveSrcID(cidr string) (uint32, error) { return m.reserve(cidr, true) }
func (m *Manager) ReserveDstID(cidr string) (uint32, error) { return m.reserve(cidr, false) }

func (m *Manager) mapsFor(p prefixIdentity) (map[string]uint32, map[string]int, TrieWriter) {
	if p.Src {
		return m.getSrcMaps(p.V6)
	}
	return m.getDstMaps(p.V6)
}
func (m *Manager) reserve(cidr string, src bool) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := prefixIdentity{cidr, src, isIPv6CIDR(cidr)}
	if _, err := trieKey(cidr, p.V6); err != nil {
		return 0, err
	}
	ids, refs, _ := m.mapsFor(p)
	if id, ok := ids[cidr]; ok {
		refs[cidr]++
		return id, nil
	}
	if m.nextID == 0 {
		return 0, fmt.Errorf("CIDR ID space exhausted")
	}
	id := m.nextID
	m.nextID++
	ids[cidr], refs[cidr] = id, 1
	return id, nil
}

// Reference changes never write either trie. Only Align and Apply mutate maps.
func (m *Manager) UndoSrcReservation(cidr string) error { return m.release(cidr, true) }
func (m *Manager) UndoDstReservation(cidr string) error { return m.release(cidr, false) }
func (m *Manager) ReleaseSrcID(cidr string) error       { return m.release(cidr, true) }
func (m *Manager) ReleaseDstID(cidr string) error       { return m.release(cidr, false) }
func (m *Manager) release(cidr string, src bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids, refs, _ := m.mapsFor(prefixIdentity{cidr, src, isIPv6CIDR(cidr)})
	if refs[cidr] == 0 {
		return fmt.Errorf("CIDR %s not found", cidr)
	}
	refs[cidr]--
	if refs[cidr] == 0 {
		delete(ids, cidr)
		delete(refs, cidr)
	}
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
func CheckOverlap(newCIDR string, existingCIDRs []string, parsed ...map[string]*net.IPNet) (string, error) {
	parse := func(s string) *net.IPNet {
		if len(parsed) > 0 {
			if n, ok := parsed[0][s]; ok {
				return n
			}
		}
		_, n, _ := net.ParseCIDR(s)
		if len(parsed) > 0 {
			parsed[0][s] = n
		}
		return n
	}
	newNet := parse(newCIDR)
	if newNet == nil {
		return "", fmt.Errorf("invalid CIDR: %s", newCIDR)
	}

	for _, existing := range existingCIDRs {
		existNet := parse(existing)
		if existNet == nil {
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
		return m.srcV6CIDRs, m.srcV6Refs, m.tries[0][2]
	}
	return m.srcV4CIDRs, m.srcV4Refs, m.tries[0][0]
}

func (m *Manager) getDstMaps(isV6 bool) (map[string]uint32, map[string]int, TrieWriter) {
	if isV6 {
		return m.dstV6CIDRs, m.dstV6Refs, m.tries[0][3]
	}
	return m.dstV4CIDRs, m.dstV4Refs, m.tries[0][1]
}

func trieKey(prefix string, v6 bool) ([]byte, error) {
	if v6 {
		key, err := makeLPMv6Key(prefix)
		if err != nil {
			return nil, err
		}
		b := make([]byte, 20)
		binary.LittleEndian.PutUint32(b, key.PrefixLen)
		copy(b[4:], key.Data[:])
		return b, nil
	}
	key, err := makeLPMv4Key(prefix)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, key.PrefixLen)
	copy(b[4:], key.Data[:])
	return b, nil
}

// isIPv6CIDR checks if a CIDR string is IPv6.
func isIPv6CIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	_, bits := network.Mask.Size()
	return bits == 128
}
