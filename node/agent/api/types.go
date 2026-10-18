// XDrop Agent - API-facing types and Controller sync DTOs
package api

// RuleStats contains per-rule statistics
type RuleStats struct {
	MatchCount uint64  `json:"match_count"`
	DropCount  uint64  `json:"drop_count"`
	MatchBytes uint64  `json:"match_bytes"`
	DropBytes  uint64  `json:"drop_bytes"`
	DropPPS    float64 `json:"drop_pps"`
}

// Rule is the API representation of a rule
type Rule struct {
	LogicalID uint32  `json:"logical_id,omitempty"`
	TTL       *string `json:"ttl,omitempty"`
	DSCP      *string `json:"dscp,omitempty"`
	ICMPType  *string `json:"icmp_type,omitempty"`
	ICMPCode  *string `json:"icmp_code,omitempty"`
	Fragment  *string `json:"fragment,omitempty"`
	PktLen    *string `json:"pkt_len,omitempty"`

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
	AttachMode string `json:"attach_mode"` // 启动时读回快照 (startup kernel snapshot).
	Name       string `json:"name"`        // e.g. "ens38"
	Role       string `json:"role"`        // "filter" (traditional) / "inbound" / "outbound" (fast_forward)
}

// XDPInfo reports the XDP operating mode and attached interfaces
type XDPInfo struct {
	Mode       string         `json:"mode"` // "traditional" / "fast_forward"
	Interfaces []XDPInterface `json:"interfaces"`
}

// Stats represents global statistics
type Stats struct {
	TotalBytes         uint64       `json:"total_bytes"`
	DroppedBytes       uint64       `json:"dropped_bytes"`
	PassedBytes        uint64       `json:"passed_bytes"`
	TotalPackets       uint64       `json:"total_packets"`
	DroppedPackets     uint64       `json:"dropped_packets"`
	PassedPackets      uint64       `json:"passed_packets"`
	WhitelistedPackets uint64       `json:"whitelisted_packets"`
	RateLimitedPackets uint64       `json:"rate_limited_packets"`
	MappedV6Dropped    uint64       `json:"mapped_v6_dropped"`
	CondRowMissing     uint64       `json:"cond_row_missing"`
	TailcallFail       uint64       `json:"tailcall_fail"` // Phase 8: gate→main tail-call failures (non-zero = BL chain bypassed)
	RulesCount         int          `json:"rules_count"`
	WhitelistCount     int          `json:"whitelist_count"`
	DroppedPPS         float64      `json:"dropped_pps"`
	PassedPPS          float64      `json:"passed_pps"`
	TotalPPS           float64      `json:"total_pps"`
	System             *SystemStats `json:"system,omitempty"`
	AgentState         *AgentState  `json:"agent_state,omitempty"`
	XDPInfo            *XDPInfo     `json:"xdp_info,omitempty"`

	Capacity *CapacityReport `json:"capacity,omitempty"`
}

type CapacityEntry struct {
	Limit int `json:"limit"`
	Used  int `json:"used"`
}

type CapacityReport struct {
	Blacklist     CapacityEntry `json:"blacklist"`
	CIDRBlacklist CapacityEntry `json:"cidr_blacklist"`
	Cond          CapacityEntry `json:"cond"`
	CIDRCond      CapacityEntry `json:"cidr_cond"`
	Whitelist     CapacityEntry `json:"whitelist"`
	SV4CIDRTrie   CapacityEntry `json:"sv4_cidr_trie"`
	DV4CIDRTrie   CapacityEntry `json:"dv4_cidr_trie"`
	SV6CIDRTrie   CapacityEntry `json:"sv6_cidr_trie"`
	DV6CIDRTrie   CapacityEntry `json:"dv6_cidr_trie"`
	LogicalState  CapacityEntry `json:"logical_state"`
}

// SyncRule represents a rule for sync (matches sync.Rule)
type SyncRule struct {
	LogicalID uint32  `json:"logical_id,omitempty"`
	TTL       *string `json:"ttl,omitempty"`
	DSCP      *string `json:"dscp,omitempty"`
	ICMPType  *string `json:"icmp_type,omitempty"`
	ICMPCode  *string `json:"icmp_code,omitempty"`
	Fragment  *string `json:"fragment,omitempty"`
	PktLen    *string `json:"pkt_len,omitempty"`

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
	ID       string `json:"id"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// AtomicSyncRejection identifies the original request item, never a generated ID.
// Index is present only for an empty request ID (zero-based within the batch).
type AtomicSyncRejection struct {
	ID     string `json:"id"`
	Index  *int   `json:"index,omitempty"`
	Reason string `json:"reason"`
}

// AtomicSyncResult holds the outcome of DoAtomicSync.
type AtomicSyncResult struct {
	Rejected   []AtomicSyncRejection
	Added      int
	Failed     int
	ExactRules int64
	CIDRRules  int64
}
