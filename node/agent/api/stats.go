// XDrop Agent - GetStats handler
package api

import (
	"encoding/binary"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) GetStats(c *gin.Context) {
	agentState := h.getAgentState()
	rulesCount := agentState.ExactRules + agentState.CIDRRules
	wlCount := agentState.WhitelistEntries

	var current [6]uint64
	for i := 0; i < len(current); i++ {
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

	// Phase 8: read tailcall_fail_stats (separate PERCPU_ARRAY, gate-owned)
	var tailcallFail uint64
	if h.tailcallFailStats != nil {
		tcKey := make([]byte, 4) // key=0
		var tcPerCPU []uint64
		if err := h.tailcallFailStats.Lookup(tcKey, &tcPerCPU); err == nil {
			for _, v := range tcPerCPU {
				tailcallFail += v
			}
		}
	}

	var condRowMissing uint64
	if h.condRowMissing != nil {
		var perCPU []uint64
		if err := h.condRowMissing.Lookup(uint32(0), &perCPU); err == nil {
			for _, v := range perCPU {
				condRowMissing += v
			}
		}
	}

	sysStats := getSystemStats(h.sysStatsCache)
	var byteCounts [3]uint64
	for i := range byteCounts {
		var perCPU []uint64
		if err := h.stats.Lookup(uint32(6+i), &perCPU); err == nil {
			for _, v := range perCPU {
				byteCounts[i] += v
			}
		}
	}
	c.JSON(http.StatusOK, Stats{
		TotalBytes:         byteCounts[0],
		DroppedBytes:       byteCounts[1],
		PassedBytes:        byteCounts[2],
		TotalPackets:       current[0],
		DroppedPackets:     current[1],
		PassedPackets:      current[2],
		WhitelistedPackets: current[3],
		RateLimitedPackets: current[4],
		MappedV6Dropped:    current[5],
		TailcallFail:       tailcallFail,
		CondRowMissing:     condRowMissing,
		RulesCount:         rulesCount,
		WhitelistCount:     wlCount,
		DroppedPPS:         droppedPPS,
		PassedPPS:          passedPPS,
		TotalPPS:           totalPPS,
		System:             &sysStats,
		AgentState:         &agentState,
		XDPInfo:            h.xdpInfo,
		Capacity:           h.publishedCapacity.Load(),
	})
}
