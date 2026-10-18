// XDrop Agent - BPF wire types, constants, and Handlers state
package api

import (
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
)

// Protocol constants (IANA protocol numbers).
const (
	ProtoAll    = 0
	ProtoICMP   = 1
	ProtoIGMP   = 2 // v2.6 Phase 1: IGMP (IANA)
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
	// Phase 8: whitelist combo bitmap (was reserved ConfigBitmapValid)
	ConfigWLBitmap           = 3
	ConfigFastForwardEnabled = 4 // 0=traditional, 1=fast-forward (written by main.go at startup)
	ConfigFilterIfindex      = 5 // ifindex filter target in fast-forward mode, 0=both
	ConfigCIDRRuleCount      = 6
	ConfigCIDRBitmap         = 7
	// Phase 8: whitelist dual-buffer selector (was reserved ConfigCIDRBitmapValid)
	ConfigWLMapSelector   = 8
	ConfigRuleMapSelector = 9 // 0=A, 1=B (dual rule map Phase 4.2)
	// v2.6.1 Phase 4 B5: counts rules with MatchAnomaly != 0 across
	// exact + CIDR blacklist. Non-zero gates main program's tail_call
	// dispatch into xdp_anomaly_verify. MUST match xdrop.h CONFIG_ANOMALY_RULE_COUNT.
	ConfigAnomalyRuleCount = 10
	ConfigRLCPUDivisor     = 11
	ConfigMapEntries       = 12
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
	Action          uint8
	TcpFlagsMask    uint8 // TCP flags mask (0=don't check)
	TcpFlagsValue   uint8 // TCP flags expected value
	MatchAnomaly    uint8 // v2.6 Phase 4: bit0=bad_fragment bit1=invalid (0=don't check)
	RateLimit       uint32
	LogicalID       uint32
	LogicalReserved [12]uint8
	PktLenMin       uint16   // Minimum L3 packet length (0=no limit)
	PktLenMax       uint16   // Maximum L3 packet length (0=no limit)
	Pad2            [4]uint8 // Padding for 32-byte alignment (reserved)
}

// B1 condition rows are enabled by the low bit of Pad2[0].
const RuleHasConditions uint8 = 0x01

type ConditionSpan struct {
	Lo uint16
	Hi uint16
}

// ConditionValue mirrors xdrop.h cond_value (844 bytes). A nibble contains
// the four candidates allowed by one attribute value; lower bit wins.
type ConditionValue struct {
	Tab     [6][128]uint8
	Frag    [4]uint8
	Len     [4][2]ConditionSpan
	Action  [4]uint8
	Rate    [4]uint32
	RuleID  [4]uint32
	Active  uint8
	ICMPReq uint8
	TCPReq  uint8
	Pad     [1]uint8
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
	LogicalID uint32  `json:"logical_id,omitempty"`
	TTL       *string `json:"ttl,omitempty"`
	DSCP      *string `json:"dscp,omitempty"`
	ICMPType  *string `json:"icmp_type,omitempty"`
	ICMPCode  *string `json:"icmp_code,omitempty"`
	Fragment  *string `json:"fragment,omitempty"`
	PktLen    *string `json:"pkt_len,omitempty"`

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
	LogicalID uint32  `json:"logical_id,omitempty"`
	TTL       *string `json:"ttl,omitempty"`
	DSCP      *string `json:"dscp,omitempty"`
	ICMPType  *string `json:"icmp_type,omitempty"`
	ICMPCode  *string `json:"icmp_code,omitempty"`
	Fragment  *string `json:"fragment,omitempty"`
	PktLen    *string `json:"pkt_len,omitempty"`

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
	hits              hitsCache
	publishedState    atomic.Pointer[AgentState]
	publishedCapacity atomic.Pointer[CapacityReport]
	// Full snapshots received in this process; commit never marks recovery.
	rulesSynced, whitelistSynced atomic.Bool

	// Per-instance fault fixture; production always uses the actual BPF maps.
	configPublishFixture *configPublishTableSet

	condA, condB, cidrCondA, cidrCondB *ebpf.Map
	idRLStates                         *ebpf.Map
	quiescer                           quiescer
	// Zero means pending, including a Handlers constructed around reused maps.
	// Every access is protected by publishMu.
	quiescenceConfirmed bool
	idCounts            *ebpf.Map // logical counters for every active rule
	blacklist           *ebpf.Map
	blacklistB          *ebpf.Map // shadow blacklist (Phase 4.2 dual rule map)
	whitelist           *ebpf.Map
	whitelistB          *ebpf.Map // shadow whitelist (Phase 8 dual-buffer)
	stats               *ebpf.Map
	condRowMissing      *ebpf.Map

	// Double-buffer config maps
	configA      *ebpf.Map // config_a
	configB      *ebpf.Map // config_b
	activeConfig *ebpf.Map // active_config selector
	activeSlot   int       // 0 = A is active, 1 = B is active (Agent-side tracking)

	// Dual rule map selector (Phase 4.2)
	activeRuleSlot atomic.Int32 // writers hold publishMu; lists load once per request

	// Zero means alignment pending, including literal fixtures and reused maps.
	// All mirror accounting is protected by publishMu.
	mirrorReady                                      bool
	mirrorDirty                                      [4]map[string]struct{}
	mirrorDebt                                       [4]map[string]struct{}
	ruleRowCounts                                    [4]int
	ruleRowCountsKnown                               bool
	mirrorAlignments, mirrorFailures, commitDeferred uint64
	commitTableCapacity                              [4]int // zero uses the selected map's MaxEntries
	commitTrieCapacity                               [4]int // source v4, destination v4, source v6, destination v6
	mirrorTableFixture                               func(int, int) ruleMirrorMap
	mirrorDirtyTestHook                              func(int, []byte) // nil in production; observes each write/rollback mark
	commitStageTestHook                              func(string)
	commitFaultTestHook                              func(string) error

	// Phase 8: whitelist dual-buffer selector (independent from blacklist)
	activeWLSlot    int     // 0 = whitelist active, 1 = whitelistB active
	wlComboRefCount [64]int // per-combo ref count for whitelist bitmap (protected by publishMu+wlMu)

	// Global publish lock: all publishConfigUpdate() calls must hold this lock.
	// Rule path and whitelist path share configA/configB/activeSlot, must be serialized.
	// Lock order: syncMu → publishMu → rulesMu (or publishMu → wlMu). Never reverse.
	publishMu sync.Mutex

	// Sync mutex: blocks single-rule operations during AtomicSync.
	// Lock order: syncMu → publishMu → rulesMu.
	syncMu sync.Mutex

	logicalOwners                           map[uint32]string // rulesMu: logical ID -> rule ID
	logicalReclaimSeq                       uint64            // rulesMu: completed reclamations
	logicalReclaimedAt                      map[uint32]uint64 // rulesMu: last reclamation per ID
	pendingLogicalIDs                       map[uint32]bool   // publishMu: not yet safely reclaimed
	logicalRetireThreshold                  int               // zero selects the production default 1024
	logicalStateCapacity                    int               // zero derives the actual logical map capacity
	logicalPayments, logicalPaymentFailures uint64            // publishMu

	rules        map[string]StoredRule
	ruleKeyIndex map[RuleKey]ruleIDSet // reverse index: key → id (protected by rulesMu)
	rulesMu      sync.RWMutex
	wlEntries    map[string]RuleKey
	wlKeyIndex   map[RuleKey]string // reverse index: key → id (protected by wlMu)
	wlMu         sync.RWMutex

	lastStats     [6]uint64
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
	cidrMgr        *cidr.Manager

	cidrRules         map[string]StoredCIDRRule // id → stored CIDR rule
	cidrRuleKeyIndex  map[CIDRRuleKey]ruleIDSet // reverse index: key → id
	cidrComboRefCount [64]int                   // per-combo ref count for CIDR bitmap

	// Phase 8: tail-call failure counter (gate-owned PERCPU_ARRAY, max_entries=1).
	// Non-zero = prog_tail_map slot 1 missing → blacklist chain bypassed (fail-open).
	tailcallFailStats *ebpf.Map

	// System stats background sampler cache (Phase 5.1)
	sysStatsCache *SystemStatsCache

	// XDP mode and attached interfaces (set once at startup, read-only)
	xdpInfo   *XDPInfo
	rateLimit ratelimit.Snapshot // set once before HTTP serving
}
