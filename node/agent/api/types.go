// XDrop Agent - API-facing types and Controller sync DTOs
package api

// RuleStats contains per-rule statistics
type RuleStats struct {
	MatchCount uint64  `json:"match_count"`
	DropCount  uint64  `json:"drop_count"`
	DropPPS    float64 `json:"drop_pps"`
}

// Rule is the API representation of a rule
type Rule struct {
	ID           string     `json:"id"`
	SrcIP        string     `json:"src_ip,omitempty"`
	DstIP        string     `json:"dst_ip,omitempty"`
	SrcCIDR      string     `json:"src_cidr,omitempty"`
	DstCIDR      string     `json:"dst_cidr,omitempty"`
	SrcPort      uint16     `json:"src_port,omitempty"`
	DstPort      uint16     `json:"dst_port,omitempty"`
	Protocol     string     `json:"protocol,omitempty"`
	Action       string     `json:"action"`
	RateLimit    uint32     `json:"rate_limit,omitempty"`
	PktLenMin    uint16     `json:"pkt_len_min,omitempty"`
	PktLenMax    uint16     `json:"pkt_len_max,omitempty"`
	TcpFlags     string     `json:"tcp_flags,omitempty"`
	MatchAnomaly uint8      `json:"match_anomaly,omitempty"` // v2.6 Phase 4 bit0=bad_fragment bit1=invalid
	Comment      string     `json:"comment,omitempty"`
	Stats        *RuleStats `json:"stats,omitempty"`
}

// WhitelistEntry is the API representation of a whitelist entry
type WhitelistEntry struct {
	ID       string `json:"id"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// XDPInterface describes a single XDP-attached network interface
type XDPInterface struct {
	Name string `json:"name"` // e.g. "ens38"
	Role string `json:"role"` // "filter" (traditional) / "inbound" / "outbound" (fast_forward)
}

// XDPInfo reports the XDP operating mode and attached interfaces
type XDPInfo struct {
	Mode       string         `json:"mode"` // "traditional" / "fast_forward"
	Interfaces []XDPInterface `json:"interfaces"`
}

// Stats represents global statistics
type Stats struct {
	TotalPackets       uint64       `json:"total_packets"`
	DroppedPackets     uint64       `json:"dropped_packets"`
	PassedPackets      uint64       `json:"passed_packets"`
	WhitelistedPackets uint64       `json:"whitelisted_packets"`
	RateLimitedPackets uint64       `json:"rate_limited_packets"`
	RulesCount         int          `json:"rules_count"`
	WhitelistCount     int          `json:"whitelist_count"`
	DroppedPPS         float64      `json:"dropped_pps"`
	PassedPPS          float64      `json:"passed_pps"`
	TotalPPS           float64      `json:"total_pps"`
	System             *SystemStats `json:"system,omitempty"`
	AgentState         *AgentState  `json:"agent_state,omitempty"`
	XDPInfo            *XDPInfo     `json:"xdp_info,omitempty"`
}

// SyncRule represents a rule for sync (matches sync.Rule)
type SyncRule struct {
	ID           string
	SrcIP        string
	DstIP        string
	SrcCIDR      string
	DstCIDR      string
	SrcPort      uint16
	DstPort      uint16
	Protocol     string
	Action       string
	RateLimit    uint32
	PktLenMin    uint16
	PktLenMax    uint16
	TcpFlags     string
	MatchAnomaly uint8 // v2.6 Phase 4: bit0=bad_fragment bit1=invalid
}

// SyncWhitelistEntry represents a whitelist entry for sync (matches sync.WhitelistEntry)
type SyncWhitelistEntry struct {
	ID       string
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// AtomicSyncResult holds the outcome of DoAtomicSync.
type AtomicSyncResult struct {
	Added      int
	Failed     int
	ExactRules int64
	CIDRRules  int64
}
