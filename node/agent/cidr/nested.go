package cidr

import (
	"bytes"
	"net"
	"sort"
)

// PrefixIndex identifies a canonical prefix and its first accepted input index.
type PrefixIndex struct {
	Prefix string
	Index  int
}

// FindNested returns the first strictly containing adjacent pair after sorting
// by address family, network bytes, and ascending prefix length. The container
// is returned first. Inputs must be valid canonical prefixes, deduplicated by
// the caller for one direction. The input slice is not modified.
func FindNested(prefixes []PrefixIndex) (PrefixIndex, PrefixIndex, bool) {
	type parsedPrefix struct {
		entry   PrefixIndex
		network *net.IPNet
		bits    int
	}
	parsed := make([]parsedPrefix, 0, len(prefixes))
	for _, entry := range prefixes {
		_, network, err := net.ParseCIDR(entry.Prefix)
		if err != nil {
			continue // Outside the input contract; never dereference an invalid net.
		}
		bits, _ := network.Mask.Size()
		parsed = append(parsed, parsedPrefix{entry, network, bits})
	}
	sort.Slice(parsed, func(i, j int) bool {
		a, b := parsed[i], parsed[j]
		if len(a.network.IP) != len(b.network.IP) {
			return len(a.network.IP) < len(b.network.IP)
		}
		if order := bytes.Compare(a.network.IP, b.network.IP); order != 0 {
			return order < 0
		}
		return a.bits < b.bits
	})
	for i := 1; i < len(parsed); i++ {
		a, b := parsed[i-1], parsed[i]
		if len(a.network.IP) == len(b.network.IP) && a.bits < b.bits && a.network.Contains(b.network.IP) {
			return a.entry, b.entry, true
		}
	}
	return PrefixIndex{}, PrefixIndex{}, false
}
