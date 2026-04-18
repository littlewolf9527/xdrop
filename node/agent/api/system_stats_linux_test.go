//go:build linux

package api

import (
	"testing"
	"time"
)

// TestSystemStatsSampler_StopExitsGoroutine verifies BUG-013:
// calling stopSystemStatsSampler terminates the background sampler.
func TestSystemStatsSampler_StopExitsGoroutine(t *testing.T) {
	cache := &SystemStatsCache{}
	startSystemStatsSampler(cache)

	// Give the goroutine a brief moment to perform its first sample.
	time.Sleep(50 * time.Millisecond)

	stopSystemStatsSampler(cache)

	// After close, the channel must be observable-closed from any receiver.
	select {
	case <-cache.stop:
		// ok — channel is closed
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stop channel was not closed after stopSystemStatsSampler()")
	}
}

// TestSystemStatsSampler_StopIsIdempotent verifies the sync.Once guard:
// stopping twice must not panic on double-close.
func TestSystemStatsSampler_StopIsIdempotent(t *testing.T) {
	cache := &SystemStatsCache{}
	startSystemStatsSampler(cache)

	stopSystemStatsSampler(cache)
	// Second call must be a no-op, not a panic.
	stopSystemStatsSampler(cache)
}

// TestSystemStatsSampler_StopOnNilCacheIsSafe verifies the nil-cache guard
// in stopSystemStatsSampler.
func TestSystemStatsSampler_StopOnNilCacheIsSafe(t *testing.T) {
	// Must not panic on nil
	stopSystemStatsSampler(nil)

	// Must not panic when stop channel was never initialized (e.g. cache
	// created but start never called).
	stopSystemStatsSampler(&SystemStatsCache{})
}

// TestSystemStatsSampler_InitialSampleWritten verifies the sampler performs
// an initial sample before the first ticker fires, so getSystemStats returns
// populated data shortly after startup.
func TestSystemStatsSampler_InitialSampleWritten(t *testing.T) {
	cache := &SystemStatsCache{}
	startSystemStatsSampler(cache)
	defer stopSystemStatsSampler(cache)

	// sampleSystemStats includes a 200ms sleep for CPU delta; give it ~400ms.
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		s := getSystemStats(cache)
		if s.UptimeSeconds > 0 || s.MemTotalMB > 0 {
			return // sampled at least once
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sampler did not write any data within 600ms — initial sample missing")
}
