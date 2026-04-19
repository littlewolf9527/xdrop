// XDrop Agent - GetStats handler
package api

import (
	"encoding/binary"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) GetStats(c *gin.Context) {
	h.rulesMu.RLock()
	rulesCount := len(h.rules) + len(h.cidrRules)
	h.rulesMu.RUnlock()

	h.wlMu.RLock()
	wlCount := len(h.wlEntries)
	h.wlMu.RUnlock()

	var current [5]uint64
	for i := 0; i < 5; i++ {
		key := make([]byte, 4)
		binary.LittleEndian.PutUint32(key, uint32(i))
		// stats is a PERCPU_ARRAY of u64 — cilium/ebpf returns one
		// element per CPU in the slice; sum them for a global counter,
		// preserving the pre-migration behaviour.
		var perCPU []uint64
		if err := h.stats.Lookup(key, &perCPU); err == nil {
			var total uint64
			for _, v := range perCPU {
				total += v
			}
			current[i] = total
		}
	}

	now := time.Now().UnixNano()
	var droppedPPS, passedPPS, totalPPS float64

	h.statsMu.Lock()
	if h.lastStatsTime > 0 {
		elapsed := float64(now-h.lastStatsTime) / 1e9
		if elapsed > 0 {
			if current[1] >= h.lastStats[1] {
				droppedPPS = float64(current[1]-h.lastStats[1]) / elapsed
			}
			if current[2] >= h.lastStats[2] {
				passedPPS = float64(current[2]-h.lastStats[2]) / elapsed
			}
			if current[0] >= h.lastStats[0] {
				totalPPS = float64(current[0]-h.lastStats[0]) / elapsed
			}
		}
	}

	h.lastStats = current
	h.lastStatsTime = now
	h.statsMu.Unlock()

	sysStats := getSystemStats(h.sysStatsCache)
	agentState := h.getAgentState()

	c.JSON(http.StatusOK, Stats{
		TotalPackets:       current[0],
		DroppedPackets:     current[1],
		PassedPackets:      current[2],
		WhitelistedPackets: current[3],
		RateLimitedPackets: current[4],
		RulesCount:         rulesCount,
		WhitelistCount:     wlCount,
		DroppedPPS:         droppedPPS,
		PassedPPS:          passedPPS,
		TotalPPS:           totalPPS,
		System:             &sysStats,
		AgentState:         &agentState,
		XDPInfo:            h.xdpInfo,
	})
}
