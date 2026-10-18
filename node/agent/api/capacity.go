package api

import "github.com/littlewolf9527/xdrop/node/agent/cidr"

func (r *CapacityReport) entries() [10]*CapacityEntry {
	return [10]*CapacityEntry{&r.Blacklist, &r.CIDRBlacklist, &r.Cond, &r.CIDRCond, &r.Whitelist, &r.SV4CIDRTrie, &r.DV4CIDRTrie, &r.SV6CIDRTrie, &r.DV6CIDRTrie, &r.LogicalState}
}

func (h *Handlers) initialCapacity() *CapacityReport {
	r := &CapacityReport{}
	entries := r.entries()
	// Read A maps: both copies have equal capacities. Nil fixtures use ABI limits.
	for i, m := range h.ruleTablesAt(0) {
		entries[i].Limit = 500000
		if m != nil {
			entries[i].Limit = int(m.MaxEntries())
		}
	}
	r.Whitelist.Limit = 50000
	if h.whitelist != nil {
		r.Whitelist.Limit = int(h.whitelist.MaxEntries())
	}
	tries := [4]uint32{50000, 50000, 50000, 50000}
	if h.cidrMgr != nil {
		tries = h.cidrMgr.TrieCapacities() // Reads A; publishMu -> Manager.mu.
	}
	for i, limit := range tries {
		entries[5+i].Limit = int(limit)
	}
	r.LogicalState.Limit = h.logicalCapacity()
	return r
}

// Writers hold publishMu and store immutable copies, preserving the other path.
func (h *Handlers) capacityBase() CapacityReport {
	if r := h.publishedCapacity.Load(); r != nil {
		return *r
	}
	return *h.initialCapacity()
}

func (h *Handlers) publishAtomicCapacity(rows atomicTableRows, prefixes cidr.TrieEntries, used int) {
	h.publishCommitCapacity([4]int{len(rows[0]), len(rows[1]), len(rows[2]), len(rows[3])}, prefixes, used)
}

func (h *Handlers) publishCommitCapacity(rows [4]int, prefixes cidr.TrieEntries, used int) {
	r := h.initialCapacity()
	r.Whitelist = h.capacityBase().Whitelist
	entries := r.entries()
	for i, count := range rows {
		entries[i].Used = count
		entries[5+i].Used = len(prefixes[i])
	}
	r.LogicalState.Used = used
	h.publishedCapacity.Store(r)
}

func (h *Handlers) publishWhitelistCapacity(used int) {
	r := h.capacityBase()
	r.Whitelist = h.initialCapacity().Whitelist
	r.Whitelist.Used = used
	h.publishedCapacity.Store(&r)
}
