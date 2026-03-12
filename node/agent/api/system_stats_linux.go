//go:build linux

// XDrop Agent - System stats collection (Linux only)
package api

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SystemStats holds system-level metrics exposed via /api/v1/stats
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

// SystemStatsCache holds the latest sampled values, protected by sync.RWMutex
// (SystemStats is a multi-field struct, cannot be atomically replaced)
type SystemStatsCache struct {
	mu    sync.RWMutex
	stats SystemStats
}

// startSystemStatsSampler launches a background goroutine that samples every 10s
func startSystemStatsSampler(cache *SystemStatsCache) {
	go func() {
		for {
			s := sampleSystemStats()
			cache.mu.Lock()
			cache.stats = s
			cache.mu.Unlock()
			time.Sleep(10 * time.Second)
		}
	}()
}

func getSystemStats(cache *SystemStatsCache) SystemStats {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return cache.stats
}

// sampleSystemStats reads /proc/* to collect system metrics.
// CPU sampling reads /proc/stat twice with a 200ms gap (runs in background goroutine, not request path).
func sampleSystemStats() SystemStats {
	var s SystemStats

	// CPU: two samples of /proc/stat with 200ms gap
	idle1, total1 := readCPU()
	time.Sleep(200 * time.Millisecond)
	idle2, total2 := readCPU()

	totalDelta := total2 - total1
	idleDelta := idle2 - idle1
	if totalDelta > 0 {
		s.CPUPercent = float64(totalDelta-idleDelta) / float64(totalDelta) * 100.0
	}

	// Memory: /proc/meminfo
	s.MemTotalMB, s.MemUsedMB, s.MemPercent = readMemInfo()

	// Uptime: /proc/uptime
	s.UptimeSeconds = readUptime()

	// Load average: /proc/loadavg
	s.LoadAvg1, s.LoadAvg5, s.LoadAvg15 = readLoadAvg()

	return s
}

// readCPU parses the first "cpu" line of /proc/stat, returns (idle, total) jiffies
func readCPU() (uint64, uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, 0
	}
	line := scanner.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return 0, 0
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return 0, 0
	}

	// fields: cpu user nice system idle iowait irq softirq steal ...
	//   index:  1    2     3      4    5      6   7       8
	// We treat idle (4) + iowait (5) as "not busy" so the reported CPU%
	// matches what tools like top/htop show (busy = everything except idle+iowait).
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			continue
		}
		total += v
		if i == 4 || i == 5 { // idle + iowait both count as non-busy
			idle += v
		}
	}

	return idle, total
}

// readMemInfo parses /proc/meminfo for MemTotal, MemAvailable
func readMemInfo() (totalMB, usedMB uint64, percent float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	var memTotal, memAvailable uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = parseMemValue(line)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			memAvailable = parseMemValue(line)
		}
		if memTotal > 0 && memAvailable > 0 {
			break
		}
	}

	totalMB = memTotal / 1024 // kB → MB
	if memTotal > 0 {
		usedMB = (memTotal - memAvailable) / 1024
		percent = float64(memTotal-memAvailable) / float64(memTotal) * 100.0
	}
	return
}

// parseMemValue extracts the numeric kB value from a /proc/meminfo line like "MemTotal:  8192000 kB"
func parseMemValue(line string) uint64 {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(parts[1], 10, 64)
	return v
}

// readUptime parses /proc/uptime (first field, seconds as float)
func readUptime() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(v)
}

// readLoadAvg parses /proc/loadavg (first 3 fields)
func readLoadAvg() (avg1, avg5, avg15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return
	}
	avg1, _ = strconv.ParseFloat(fields[0], 64)
	avg5, _ = strconv.ParseFloat(fields[1], 64)
	avg15, _ = strconv.ParseFloat(fields[2], 64)
	return
}

func init() {
	// Verify /proc/stat is readable at startup
	if _, err := os.Stat("/proc/stat"); err != nil {
		fmt.Fprintf(os.Stderr, "[SystemStats] Warning: /proc/stat not accessible: %v\n", err)
	}
}
