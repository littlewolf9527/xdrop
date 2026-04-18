// XDrop Agent - API Handlers
// Supports IPv4 and IPv6 dual-stack
package api

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/http"

	"github.com/dropbox/goebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func NewHandlers(blacklist, whitelist, stats, configA, configB, activeConfig, rlStates goebpf.Map,
	cidrBlacklist, cidrRlStates goebpf.Map, cidrMgr *cidr.Manager,
	blacklistB, cidrBlacklistB goebpf.Map) *Handlers {
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

	// Set selector to point at A (slot 0)
	selKey := make([]byte, 4)
	selValue := make([]byte, 8) // 0
	if err := activeConfig.Update(selKey, selValue); err != nil {
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

// initDynamicConfig initializes dynamic config items in one config map
// Does not touch FF_ENABLED or FILTER_IFINDEX (written by main.go separately)
func (h *Handlers) initDynamicConfig(m goebpf.Map) error {
	for _, idx := range []uint32{ConfigBlacklistCount, ConfigWhitelistCount, ConfigRuleBitmap,
		ConfigCIDRRuleCount, ConfigCIDRBitmap, ConfigRuleMapSelector} {
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, idx)
		value := make([]byte, 8) // 0
		if err := m.Update(key, value); err != nil {
			return fmt.Errorf("failed to init config index %d: %w", idx, err)
		}
	}
	return nil
}

// Welcome handler
func (h *Handlers) Welcome(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"name":     "XDrop Agent",
		"version":  "2.4.1",
		"status":   "running",
		"features": []string{"ipv4", "ipv6", "rate_limit"},
	})
}

// Health check
func (h *Handlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
	})
}
