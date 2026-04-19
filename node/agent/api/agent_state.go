// XDrop Agent - Agent state snapshot (logical view of in-memory state)
package api

// AgentState is a logical view of the agent's in-memory state.
// This is NOT a direct BPF map introspection — use bpftool for kernel-side verification.
type AgentState struct {
	ExactRules       int `json:"exact_rules"`
	CIDRRules        int `json:"cidr_rules"`
	WhitelistEntries int `json:"whitelist_entries"`
	ActiveSlot       int `json:"active_slot"`
	RuleMapSelector  int `json:"rule_map_selector"`
}

// getAgentState returns a snapshot of the agent's in-memory state.
//
// Lock ordering (must not reverse):
//
//	publishMu → rulesMu, publishMu → wlMu
//
// activeSlot and activeRuleSlot are owned by publishMu (mutated inside
// publishConfigUpdate and DoAtomicSync, both of which hold publishMu).
// Reading them under rulesMu would violate the lock contract and create
// a data race. We read slot values under publishMu first, then release
// it before taking rulesMu (which is lower in the order).
func (h *Handlers) getAgentState() AgentState {
	// 1. Read slot selectors under publishMu (their owning lock).
	//    Must not hold rulesMu or wlMu at this point — publishMu is higher.
	h.publishMu.Lock()
	activeSlot := h.activeSlot
	ruleMapSel := h.activeRuleSlot
	h.publishMu.Unlock()

	// 2. Read rule counts under rulesMu.
	h.rulesMu.RLock()
	exactRules := len(h.rules)
	cidrRules := len(h.cidrRules)
	h.rulesMu.RUnlock()

	// 3. Read whitelist count under wlMu (independently).
	h.wlMu.RLock()
	wlEntries := len(h.wlEntries)
	h.wlMu.RUnlock()

	return AgentState{
		ExactRules:       exactRules,
		CIDRRules:        cidrRules,
		WhitelistEntries: wlEntries,
		ActiveSlot:       activeSlot,
		RuleMapSelector:  ruleMapSel,
	}
}
