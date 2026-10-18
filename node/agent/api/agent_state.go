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

// getAgentState loads one immutable publication, including for zero-value fixtures.
func (h *Handlers) getAgentState() AgentState {
	if state := h.publishedState.Load(); state != nil {
		return *state
	}
	return AgentState{}
}

// Writers hold publishMu; preserve fields owned by the other publication path.
func (h *Handlers) publishRuleState(exact, prefixes int) {
	state := h.getAgentState()
	state.ActiveSlot, state.RuleMapSelector = h.activeSlot, int(h.activeRuleSlot.Load())
	state.ExactRules, state.CIDRRules = exact, prefixes
	h.publishedState.Store(&state)
}
func (h *Handlers) publishWhitelistState(count int) {
	state := h.getAgentState()
	state.ActiveSlot, state.WhitelistEntries = h.activeSlot, count
	h.publishedState.Store(&state)
}
