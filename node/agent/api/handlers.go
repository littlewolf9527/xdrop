// XDrop Agent - API Handlers
// Supports IPv4 and IPv6 dual-stack
package api

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/http"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func NewHandlers(blacklist, whitelist, whitelistB, stats, configA, configB, activeConfig *ebpf.Map,
	cidrBlacklist *ebpf.Map, cidrMgr *cidr.Manager,
	blacklistB, cidrBlacklistB *ebpf.Map,
	tailcallFailStats, idCounts *ebpf.Map,
	condA, condB, cidrCondA, cidrCondB, idRLStates, condRowMissing *ebpf.Map) *Handlers {
	receipt, err := newQuiescer()
	if err != nil {
		log.Fatalf("[NewHandlers] Failed to create quiescence receipt: %v", err)
	}
	h := &Handlers{
		condA: condA, condB: condB, cidrCondA: cidrCondA, cidrCondB: cidrCondB,
		idRLStates: idRLStates, quiescer: receipt,
		idCounts:          idCounts,
		blacklist:         blacklist,
		blacklistB:        blacklistB,
		whitelist:         whitelist,
		whitelistB:        whitelistB, // Phase 8
		stats:             stats,
		configA:           configA,
		configB:           configB,
		activeConfig:      activeConfig,
		condRowMissing:    condRowMissing,
		logicalOwners:     make(map[uint32]string),
		pendingLogicalIDs: make(map[uint32]bool),
		rules:             make(map[string]StoredRule),
		ruleKeyIndex:      make(map[RuleKey]ruleIDSet),
		wlEntries:         make(map[string]RuleKey),
		wlKeyIndex:        make(map[RuleKey]string),
		lastRuleDropCount: make(map[string]uint64),
		lastRuleStatsTime: make(map[string]int64),
		activeSlot:        0,

		activeWLSlot:      0, // Phase 8
		cidrBlacklist:     cidrBlacklist,
		cidrBlacklistB:    cidrBlacklistB,
		cidrMgr:           cidrMgr,
		cidrRules:         make(map[string]StoredCIDRRule),
		cidrRuleKeyIndex:  make(map[CIDRRuleKey]ruleIDSet),
		tailcallFailStats: tailcallFailStats, // Phase 8
	}

	h.publishMu.Lock()
	defer h.publishMu.Unlock()

	// Initialize dynamic config items before startup-specific config writes.
	if err := h.initDynamicConfig(configA); err != nil {
		log.Fatalf("[NewHandlers] Failed to init config_a: %v", err)
	}
	if err := h.initDynamicConfig(configB); err != nil {
		log.Fatalf("[NewHandlers] Failed to init config_b: %v", err)
	}

	// Set selector to point at A (slot 0). active_config is an ARRAY map
	// so the slot always exists — Update(UpdateExist) is the strict §5.2
	// translation of the pre-migration goebpf.Update (BPF_EXIST) semantics.
	selKey := make([]byte, 4)
	selValue := make([]byte, 8) // 0
	if err := activeConfig.Update(selKey, selValue, ebpf.UpdateExist); err != nil {
		log.Fatalf("[NewHandlers] Failed to init active_config selector: %v", err)
	}

	h.quiescenceConfirmed = false
	h.publishedState.Store(&AgentState{})
	h.publishedCapacity.Store(h.initialCapacity())

	log.Printf("[NewHandlers] Double-buffer config initialized, active slot = 0")

	// Start system stats background sampler (Phase 5.1)
	h.sysStatsCache = &SystemStatsCache{}
	startSystemStatsSampler(h.sysStatsCache)

	return h
}

// SetXDPInfo sets the XDP operating mode and attached interfaces (called once at startup)
func (h *Handlers) SetXDPInfo(info *XDPInfo) {
	h.xdpInfo = info
}

// Shutdown signals background goroutines owned by this Handlers to exit.
// Safe to call multiple times.
func (h *Handlers) Shutdown() {
	stopSystemStatsSampler(h.sysStatsCache)
	if q, ok := h.quiescer.(*kernelQuiescer); ok {
		_ = q.Close()
	}
}

// initDynamicConfig zeros business config slots in both startup arrays.
// FF slots are owned by main: FF restart preserves forwarding, while the
// traditional branch clears them before publishing programs (AUD-PH3-001).
func (h *Handlers) initDynamicConfig(m *ebpf.Map) error {
	for _, idx := range []uint32{
		ConfigBlacklistCount, ConfigWhitelistCount, ConfigRuleBitmap,
		ConfigWLBitmap, // Phase 8: slot 3
		ConfigCIDRRuleCount, ConfigCIDRBitmap,
		ConfigWLMapSelector, // Phase 8: slot 8
		ConfigRuleMapSelector,
		ConfigAnomalyRuleCount, ConfigRLCPUDivisor,
	} {
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, idx)
		value := make([]byte, 8) // 0
		if err := m.Update(key, value, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("failed to init config index %d: %w", idx, err)
		}
	}
	return nil
}

// SyncProtocol is the node synchronization contract version.
const SyncProtocol = 11

// Version is supplied by the build; source-only builds identify themselves as dev.
var Version = "dev"

// Welcome handler
func (h *Handlers) Welcome(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"sync_protocol": SyncProtocol,
		"name":          "XDrop Agent",
		"version":       Version,
	})
}

// Health check
func (h *Handlers) Health(c *gin.Context) {
	rules, whitelist := h.rulesSynced.Load(), h.whitelistSynced.Load()
	if rules && whitelist {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "degraded", "reason": "awaiting_full_sync", "rules_synced": rules, "whitelist_synced": whitelist})
}
