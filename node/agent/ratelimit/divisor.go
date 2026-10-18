// Package ratelimit defines the startup divisor and a test reference model.
package ratelimit

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const MaxDivisor = 4096

// Snapshot is computed once before XDP attach. Unknown counts serialize as null.
type Snapshot struct {
	Divisor      int    `json:"divisor"`
	Source       string `json:"source"`
	OnlineCPUs   *int   `json:"online_cpus"`
	PossibleCPUs *int   `json:"possible_cpus"`
}

// Resolve computes the divisor using only the supplied system CPU sources.
// It never uses process affinity. possible is normally ebpf.PossibleCPU.
func Resolve(onlinePath string, possible func() (int, error), override int) (Snapshot, error) {
	var s Snapshot
	if override < 0 || override > MaxDivisor {
		return s, fmt.Errorf("bpf.rate_limit_divisor must be an integer in 0..4096, got %d", override)
	}
	raw, onlineErr := os.ReadFile(onlinePath)
	if onlineErr == nil {
		var n int
		n, onlineErr = parseOnline(string(raw))
		if onlineErr == nil {
			s.OnlineCPUs = &n
		}
	}
	p, possibleErr := possible()
	if possibleErr == nil && p < 1 {
		possibleErr = fmt.Errorf("invalid count %d", p)
	}
	if possibleErr == nil {
		s.PossibleCPUs = &p
	}
	switch {
	case override > 0:
		s.Divisor, s.Source = override, "config"
	case onlineErr == nil:
		s.Divisor, s.Source = *s.OnlineCPUs, "auto"
	case possibleErr == nil:
		s.Divisor, s.Source = p, "possible"
	default:
		return s, fmt.Errorf("rate-limit CPU sources failed: online %s: %v; possible: %v", onlinePath, onlineErr, possibleErr)
	}
	if s.Divisor > MaxDivisor {
		return s, fmt.Errorf("rate-limit %s CPU count %d exceeds 4096; bpf.rate_limit_divisor also accepts only 0..4096", s.Source, s.Divisor)
	}
	return s, nil
}

// parseOnline accepts Linux comma-separated CPU IDs and inclusive ranges.
// Reject overlap/duplicates and unsorted ranges instead of double-counting CPUs.
func parseOnline(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty online CPU list")
	}
	count, previous := uint64(0), int64(-1)
	for _, part := range strings.Split(raw, ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return 0, fmt.Errorf("invalid online CPU range %q", part)
		}
		lo, err := strconv.ParseUint(bounds[0], 10, 31)
		if err != nil {
			return 0, fmt.Errorf("invalid online CPU ID %q", part)
		}
		hi := lo
		if len(bounds) == 2 {
			hi, err = strconv.ParseUint(bounds[1], 10, 31)
			if err != nil {
				return 0, fmt.Errorf("invalid online CPU range %q", part)
			}
		}
		if hi < lo || int64(lo) <= previous {
			return 0, fmt.Errorf("invalid online CPU order %q", part)
		}
		count += hi - lo + 1
		previous = int64(hi)
	}
	return int(count), nil
}

// LogLine has the same values as the API startup snapshot.
func (s Snapshot) LogLine() string {
	count := func(n *int) string {
		if n == nil {
			return "unknown"
		}
		return strconv.Itoa(*n)
	}
	return fmt.Sprintf("[rate_limit] divisor=%d source=%s online_cpus=%s possible_cpus=%s", s.Divisor, s.Source, count(s.OnlineCPUs), count(s.PossibleCPUs))
}
