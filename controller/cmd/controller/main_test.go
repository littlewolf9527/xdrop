package main

import (
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/config"
)

// TestBuildStatsCacheConfig_SecondsConversion is the round-2 P2-5 / round-9
// rev10 acceptance criterion in test form: the wiring layer must turn an
// int seconds value into a time.Duration that's actually `n * time.Second`,
// not `n * time.Nanosecond`.
//
// A bug here (e.g. assigning the int directly to a time.Duration field)
// would silently change the cache refresh interval from 5 seconds to 5
// nanoseconds — almost certainly hammering the cluster with millions of
// /api/v1/rules calls per second before anyone noticed.
func TestBuildStatsCacheConfig_SecondsConversion(t *testing.T) {
	raw := config.StatsCacheRawConfig{
		RefreshIntervalSeconds:  5,
		StaleThresholdSeconds:   15,
		PerNodeTimeoutSeconds:   2,
		MaxConcurrency:          4,
		BackoffOnAllFailSeconds: 30,
		TopNCacheSize:           50,
		Disabled:                false,
	}

	rt := buildStatsCacheConfig(raw)

	if rt.RefreshInterval != 5*time.Second {
		t.Fatalf("RefreshInterval should be 5*time.Second (5_000_000_000 ns), got %v (%d ns)",
			rt.RefreshInterval, rt.RefreshInterval.Nanoseconds())
	}
	if rt.StaleThreshold != 15*time.Second {
		t.Fatalf("StaleThreshold = %v, want 15s", rt.StaleThreshold)
	}
	if rt.PerNodeTimeout != 2*time.Second {
		t.Fatalf("PerNodeTimeout = %v, want 2s", rt.PerNodeTimeout)
	}
	if rt.BackoffOnAllFail != 30*time.Second {
		t.Fatalf("BackoffOnAllFail = %v, want 30s", rt.BackoffOnAllFail)
	}
	if rt.MaxConcurrency != 4 {
		t.Fatalf("MaxConcurrency = %d, want 4", rt.MaxConcurrency)
	}
	if rt.TopNCacheSize != 50 {
		t.Fatalf("TopNCacheSize = %d, want 50", rt.TopNCacheSize)
	}
	if rt.Disabled {
		t.Fatalf("Disabled should be false")
	}
}

// TestBuildStatsCacheConfig_DisabledFlagPasses confirms the flag flows
// through the wiring layer untouched. Easy to break if someone refactors
// the conversion to use a struct literal that omits Disabled.
func TestBuildStatsCacheConfig_DisabledFlagPasses(t *testing.T) {
	raw := config.StatsCacheRawConfig{
		RefreshIntervalSeconds:  5,
		StaleThresholdSeconds:   15,
		PerNodeTimeoutSeconds:   2,
		MaxConcurrency:          4,
		BackoffOnAllFailSeconds: 30,
		TopNCacheSize:           50,
		Disabled:                true,
	}
	rt := buildStatsCacheConfig(raw)
	if !rt.Disabled {
		t.Fatalf("Disabled flag should propagate through wiring")
	}
}
