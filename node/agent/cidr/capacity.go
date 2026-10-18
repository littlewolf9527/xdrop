package cidr

// TrieCapacities returns source/destination v4 followed by source/destination
// v6 capacities without reserving or publishing a prefix. Production writers
// are ebpf maps; older key-only test writers use the ABI default.
func (m *Manager) TrieCapacities() [4]uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result [4]uint32
	for i, v6 := range []bool{false, false, true, true} {
		_, _, table := m.getSrcMaps(v6)
		if i%2 != 0 {
			_, _, table = m.getDstMaps(v6)
		}
		result[i] = 50000
		if sized, ok := table.(interface{ MaxEntries() uint32 }); ok {
			result[i] = sized.MaxEntries()
		}
	}
	return result
}

// CountsAfter applies request-local reference deltas to the existing ledger.
func (m *Manager) CountsAfter(delta [2]map[string]int) [4]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := [4]int{len(m.srcV4Refs), len(m.dstV4Refs), len(m.srcV6Refs), len(m.dstV6Refs)}
	for d, changes := range delta {
		for prefix, change := range changes {
			if prefix == "" {
				continue
			}
			v6 := isIPv6CIDR(prefix)
			_, refs, _ := m.mapsFor(prefixIdentity{prefix, d == 0, v6})
			k := d
			if v6 {
				k += 2
			}
			if refs[prefix] > 0 && refs[prefix]+change <= 0 {
				count[k]--
			}
			if refs[prefix] == 0 && change > 0 {
				count[k]++
			}
		}
	}
	return count
}
