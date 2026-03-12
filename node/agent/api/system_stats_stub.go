//go:build !linux

// XDrop Agent - System stats stub for non-Linux platforms (macOS/Windows)
package api

// SystemStats holds system-level metrics (stub: returns zero values on non-Linux)
type SystemStats struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemTotalMB    uint64  `json:"mem_total_mb"`
	MemUsedMB     uint64  `json:"mem_used_mb"`
	MemPercent    float64 `json:"mem_percent"`
	UptimeSeconds uint64  `json:"uptime_seconds"`
	LoadAvg1      float64 `json:"load_avg_1"`
	LoadAvg5      float64 `json:"load_avg_5"`
	LoadAvg15     float64 `json:"load_avg_15"`
}

// SystemStatsCache stub (no-op on non-Linux)
type SystemStatsCache struct{}

func startSystemStatsSampler(_ *SystemStatsCache) {}

func getSystemStats(_ *SystemStatsCache) SystemStats { return SystemStats{} }
