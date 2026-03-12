package model

import (
	"time"
)

// Node node model
type Node struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Endpoint  string     `json:"endpoint"`
	ApiKey    string     `json:"api_key,omitempty"` // used when Controller sends requests to this Node
	Status    string     `json:"status"`
	LastSync  *time.Time `json:"last_sync,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	Stats     *NodeStats `json:"stats,omitempty"`
}

// NodeSystemStats node system metrics (Phase 5.1)
type NodeSystemStats struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemTotalMB    uint64  `json:"mem_total_mb"`
	MemUsedMB     uint64  `json:"mem_used_mb"`
	MemPercent    float64 `json:"mem_percent"`
	UptimeSeconds uint64  `json:"uptime_seconds"`
	LoadAvg1      float64 `json:"load_avg_1"`
	LoadAvg5      float64 `json:"load_avg_5"`
	LoadAvg15     float64 `json:"load_avg_15"`
}

// NodeAgentState agent in-memory logical view (Phase 5.1)
type NodeAgentState struct {
	ExactRules       int `json:"exact_rules"`
	CIDRRules        int `json:"cidr_rules"`
	WhitelistEntries int `json:"whitelist_entries"`
	ActiveSlot       int `json:"active_slot"`
	RuleMapSelector  int `json:"rule_map_selector"`
}

// NodeXDPInterface describes a single XDP-attached interface
type NodeXDPInterface struct {
	Name string `json:"name"`
	Role string `json:"role"` // "filter" / "inbound" / "outbound"
}

// NodeXDPInfo reports the XDP operating mode and attached interfaces
type NodeXDPInfo struct {
	Mode       string             `json:"mode"` // "traditional" / "fast_forward"
	Interfaces []NodeXDPInterface `json:"interfaces"`
}

// NodeStats node statistics
type NodeStats struct {
	TotalPackets       uint64           `json:"total_packets"`
	DroppedPackets     uint64           `json:"dropped_packets"`
	PassedPackets      uint64           `json:"passed_packets"`
	WhitelistedPackets uint64           `json:"whitelisted_packets"`
	RateLimitedPackets uint64           `json:"rate_limited_packets"`
	RulesCount         int              `json:"rules_count"`
	WhitelistCount     int              `json:"whitelist_count"`
	DroppedPPS         float64          `json:"dropped_pps"`
	PassedPPS          float64          `json:"passed_pps"`
	TotalPPS           float64          `json:"total_pps"`
	System             *NodeSystemStats `json:"system,omitempty"`
	AgentState         *NodeAgentState  `json:"agent_state,omitempty"`
	XDPInfo            *NodeXDPInfo     `json:"xdp_info,omitempty"`
}

// NodeRequest register node request
type NodeRequest struct {
	Name     string `json:"name" binding:"required"`
	Endpoint string `json:"endpoint" binding:"required"`
	ApiKey   string `json:"api_key"` // optional; used when Controller sends requests to this Node
}

// NodeStatus node status constants
const (
	NodeStatusOnline  = "online"
	NodeStatusOffline = "offline"
	NodeStatusSyncing = "syncing"
	NodeStatusUnknown = "unknown"
)
