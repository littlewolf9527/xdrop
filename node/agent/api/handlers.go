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

func NewHandlers(blacklist, whitelist, stats, configA, configB, activeConfig, rlStates *ebpf.Map,
	cidrBlacklist, cidrRlStates *ebpf.Map, cidrMgr *cidr.Manager,
	blacklistB, cidrBlacklistB *ebpf.Map) *Handlers {
	h := &Handlers{
		blacklist:         blacklist,
		blacklistB:        blacklistB,
		whitelist:         whitelist,
		stats:             stats,
		configA:           configA,
		configB:           configB,
		activeConfig:      activeConfig,
		rlStates:          rlStates,
		rules:             make(map[string]StoredRule),
		ruleKeyIndex:      make(map[RuleKey]string),
		wlEntries:         make(map[string]RuleKey),
		wlKeyIndex:        make(map[RuleKey]string),
		lastRuleDropCount: make(map[string]uint64),
		lastRuleStatsTime: make(map[string]int64),
		activeSlot:        0,
		activeRuleSlot:    0,
		cidrBlacklist:     cidrBlacklist,
		cidrBlacklistB:    cidrBlacklistB,
		cidrRlStates:      cidrRlStates,
		cidrMgr:           cidrMgr,
		cidrRules:         make(map[string]StoredCIDRRule),
		cidrRuleKeyIndex:  make(map[CIDRRuleKey]string),
	}

	// Initialize dynamic config items (bitmap=0, count=0, wl_count=0)
	// Only writes index 0/1/2, does not touch 3(reserved)/4(FF)/5(ifindex)
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
}

// initDynamicConfig zeros every dynamic-scope config slot in a single
// config_a / config_b array map. config_a / config_b are ARRAY maps —
// all max_entries slots are pre-allocated zero by the kernel on create,
// so Update(UpdateExist) always succeeds and reproduces the
// pre-migration goebpf.Update semantics per proposal §5.2.
//
// AUD-PH3-001 fix: the list explicitly includes CONFIG_FAST_FORWARD_ENABLED
// and CONFIG_FILTER_IFINDEX. Before Phase 3 map pinning these were left
// out because the maps were recreated empty on every agent boot, so
// main.go's configureFastForward() could simply populate them in FF
// mode and leave them zero in traditional mode. With pinning, config
// maps survive agent restart. Without zeroing here, a node that ran
// in FF mode and then restarts into traditional mode would leave
// FF_ENABLED=1 in the pinned config, and the BPF program would keep
// branching into fast-forward code. Restoring the zero-on-every-boot
// invariant fixes this; main.go's configureFastForward() runs AFTER
// NewHandlers and overwrites with real values when FF is actually on.
func (h *Handlers) initDynamicConfig(m *ebpf.Map) error {
	for _, idx := range []uint32{
		ConfigBlacklistCount, ConfigWhitelistCount, ConfigRuleBitmap,
		ConfigFastForwardEnabled, ConfigFilterIfindex,
		ConfigCIDRRuleCount, ConfigCIDRBitmap, ConfigRuleMapSelector,
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

// Welcome handler
func (h *Handlers) Welcome(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"name":     "XDrop Agent",
		"version":  "2.6.1",
		"status":   "running",
		"features": []string{"ipv4", "ipv6", "rate_limit", "decoder_sugar", "anomaly_match"},
	})
}

// Health check
func (h *Handlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}
