// XDrop Agent - BPF wire types, constants, and Handlers state
package api

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

// Protocol constants (IANA protocol numbers).
const (
	ProtoAll    = 0
	ProtoICMP   = 1
	ProtoIGMP   = 2  // v2.6 Phase 1: IGMP (IANA)
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoGRE    = 47 // v2.6 Phase 1: GRE (IANA)
	ProtoESP    = 50 // v2.6 Phase 1: ESP (IANA)
	ProtoICMPv6 = 58
)

// Action constants
const (
	ActionPass      = 0
	ActionDrop      = 1
	ActionRateLimit = 2
)

// Config map indices (must match xdrop.h)
const (
	ConfigBlacklistCount = 0
	ConfigWhitelistCount = 1
	ConfigRuleBitmap     = 2
	// ConfigBitmapValid (3) is reserved, no longer used in double-buffer mode
	ConfigFastForwardEnabled = 4 // 0=traditional, 1=fast-forward (written by main.go at startup)
	ConfigFilterIfindex      = 5 // ifindex filter target in fast-forward mode, 0=both
	ConfigCIDRRuleCount      = 6
	ConfigCIDRBitmap         = 7
	// ConfigCIDRBitmapValid (8) is reserved, no longer used in double-buffer mode
	ConfigRuleMapSelector = 9 // 0=A, 1=B (dual rule map Phase 4.2)
	// v2.6.1 Phase 4 B5: counts rules with MatchAnomaly != 0 across
	// exact + CIDR blacklist. Non-zero gates main program's tail_call
	// dispatch into xdp_anomaly_verify. MUST match xdrop.h CONFIG_ANOMALY_RULE_COUNT.
	ConfigAnomalyRuleCount = 10
	ConfigMapEntries       = 11
)

// IPAddr represents a 128-bit IP address (IPv4-mapped or native IPv6)
type IPAddr [16]byte

// RuleKey matches the BPF struct rule_key (40 bytes)
type RuleKey struct {
	SrcIP    IPAddr
	DstIP    IPAddr
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]uint8
}

// RuleValue matches the BPF struct rule_value (32 bytes).
// v2.6 Phase 4: MatchAnomaly reuses the pad byte at offset 3 — struct size
// stays 32 bytes so upgrades don't trigger Phase 3 schema-drift auto-wipe
// (see proposal xsight-v13-decoder-adaptation.md §7.2.0).
type RuleValue struct {
	Action        uint8
	TcpFlagsMask  uint8 // TCP flags mask (0=don't check)
	TcpFlagsValue uint8 // TCP flags expected value
	MatchAnomaly  uint8 // v2.6 Phase 4: bit0=bad_fragment bit1=invalid (0=don't check)
	RateLimit     uint32
	MatchCount    uint64
	DropCount     uint64
	PktLenMin     uint16   // Minimum L3 packet length (0=no limit)
	PktLenMax     uint16   // Maximum L3 packet length (0=no limit)
	Pad2          [4]uint8 // Padding for 32-byte alignment (reserved)
}

// Anomaly bits for RuleValue.MatchAnomaly and runtime packet anomaly bitmap.
// Must stay in sync with xdrop.h ANOMALY_* defines.
const (
	AnomalyBadFragment uint8 = 0x01
	AnomalyInvalid     uint8 = 0x02
)

// CIDRRuleKey matches the BPF struct cidr_rule_key (16 bytes)
type CIDRRuleKey struct {
	SrcID    uint32
	DstID    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]uint8
}

// StoredRule stores both key and value for API display
type StoredRule struct {
	Key          RuleKey
	Action       string
	RateLimit    uint32
	PktLenMin    uint16
	PktLenMax    uint16
	TcpFlags     string // human-readable: "SYN,!ACK" etc
	MatchAnomaly uint8  // v2.6.1 Phase 4 B5: 0 = not anomaly rule; non-zero = anomaly bitmask
}

// StoredCIDRRule stores CIDR rule info for API display and deletion
type StoredCIDRRule struct {
	Key          CIDRRuleKey
	SrcCIDR      string // original CIDR string (normalized)
	DstCIDR      string
	Action       string
	RateLimit    uint32
	PktLenMin    uint16
	PktLenMax    uint16
	TcpFlags     string
	MatchAnomaly uint8 // v2.6.1 Phase 4 B5
}

// Handlers holds the BPF maps and rule storage
type Handlers struct {
	blacklist  *ebpf.Map
	blacklistB *ebpf.Map // shadow blacklist (Phase 4.2 dual rule map)
	whitelist  *ebpf.Map
	stats      *ebpf.Map
	rlStates   *ebpf.Map

	// Double-buffer config maps
	configA      *ebpf.Map // config_a
	configB      *ebpf.Map // config_b
	activeConfig *ebpf.Map // active_config selector
	activeSlot   int       // 0 = A is active, 1 = B is active (Agent-side tracking)

	// Dual rule map selector (Phase 4.2)
	activeRuleSlot int // 0 = blacklist/cidrBlacklist active, 1 = blacklistB/cidrBlacklistB active

	// Global publish lock: all publishConfigUpdate() calls must hold this lock.
	// Rule path and whitelist path share configA/configB/activeSlot, must be serialized.
	// Lock order: syncMu → publishMu → rulesMu (or publishMu → wlMu). Never reverse.
	publishMu sync.Mutex

	// Sync mutex: blocks single-rule operations during AtomicSync.
	// Lock order: syncMu → publishMu → rulesMu.
	syncMu sync.Mutex

	rules        map[string]StoredRule
	ruleKeyIndex map[RuleKey]string // reverse index: key → id (protected by rulesMu)
	rulesMu      sync.RWMutex
	wlEntries    map[string]RuleKey
	wlKeyIndex   map[RuleKey]string // reverse index: key → id (protected by wlMu)
	wlMu         sync.RWMutex

	lastStats     [5]uint64
	lastStatsTime int64
	statsMu       sync.Mutex // protects lastStats and lastStatsTime

	// Per-rule PPS cache for incremental calculation
	lastRuleDropCount map[string]uint64
	lastRuleStatsTime map[string]int64 // per-rule timestamp for correct PPS across paginated requests
	rulePPSMu         sync.Mutex       // Separate lock for PPS cache

	// Per-combo reference count for O(1) bitmap updates (protected by rulesMu)
	comboRefCount [64]int

	// === CIDR support ===
	cidrBlacklist  *ebpf.Map
	cidrBlacklistB *ebpf.Map // shadow CIDR blacklist (Phase 4.2 dual rule map)
	cidrRlStates   *ebpf.Map
	cidrMgr        *cidr.Manager

	cidrRules         map[string]StoredCIDRRule // id → stored CIDR rule
	cidrRuleKeyIndex  map[CIDRRuleKey]string    // reverse index: key → id
	cidrComboRefCount [64]int                   // per-combo ref count for CIDR bitmap

	// System stats background sampler cache (Phase 5.1)
	sysStatsCache *SystemStatsCache

	// XDP mode and attached interfaces (set once at startup, read-only)
	xdpInfo *XDPInfo
}
