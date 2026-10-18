package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
)

type CPUStats struct {
	CPU                int    `json:"cpu"`
	TotalPackets       uint64 `json:"total_packets"`
	DroppedPackets     uint64 `json:"dropped_packets"`
	PassedPackets      uint64 `json:"passed_packets"`
	WhitelistedPackets uint64 `json:"whitelisted_packets"`
	RateLimitedPackets uint64 `json:"rate_limited_packets"`
}

type CPUStatsResponse struct {
	PerCPU            []CPUStats         `json:"per_cpu"`
	RateLimit         ratelimit.Snapshot `json:"rate_limit"`
	DivisorInMap      *uint64            `json:"divisor_in_map"`
	DivisorInMapError string             `json:"divisor_in_map_error,omitempty"`
}

// SetRateLimitSnapshot is called once at startup, before HTTP serving.
// Copy count values so callers cannot mutate the stored snapshot through pointers.
func (h *Handlers) SetRateLimitSnapshot(s ratelimit.Snapshot) {
	if s.OnlineCPUs != nil {
		n := *s.OnlineCPUs
		s.OnlineCPUs = &n
	}
	if s.PossibleCPUs != nil {
		n := *s.PossibleCPUs
		s.PossibleCPUs = &n
	}
	h.rateLimit = s
}

func (h *Handlers) readRateLimitDivisor() (*uint64, error) {
	h.publishMu.Lock()
	defer h.publishMu.Unlock()
	var slot uint64
	if err := h.activeConfig.Lookup(uint32(0), &slot); err != nil {
		return nil, fmt.Errorf("read active_config[0]: %w", err)
	}
	selected := h.configA
	if slot != 0 {
		selected = h.configB
	}
	var divisor uint64
	if err := selected.Lookup(uint32(ConfigRLCPUDivisor), &divisor); err != nil {
		return nil, fmt.Errorf("read active config slot 11: %w", err)
	}
	return &divisor, nil
}

// GetCPUStats uses independent lookup slices; it never updates the PPS baseline.
// Slots and CPUs are read independently, not as an atomic snapshot.
func (h *Handlers) GetCPUStats(c *gin.Context) {
	var slots [5][]uint64
	for i := range slots {
		if err := h.stats.Lookup(uint32(i), &slots[i]); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "stats_read_failed", "error": fmt.Sprintf("read stats slot %d: %v", i, err)})
			return
		}
		if len(slots[i]) == 0 || (i > 0 && len(slots[i]) != len(slots[0])) {
			c.JSON(http.StatusInternalServerError, gin.H{"code": "stats_read_failed", "error": fmt.Sprintf("invalid CPU count in stats slot %d", i)})
			return
		}
	}
	response := CPUStatsResponse{PerCPU: make([]CPUStats, len(slots[0])), RateLimit: h.rateLimit}
	for cpu := range response.PerCPU {
		response.PerCPU[cpu] = CPUStats{cpu, slots[0][cpu], slots[1][cpu], slots[2][cpu], slots[3][cpu], slots[4][cpu]}
	}
	var err error
	response.DivisorInMap, err = h.readRateLimitDivisor()
	if err != nil {
		response.DivisorInMapError = err.Error()
	}
	c.JSON(http.StatusOK, response)
}
