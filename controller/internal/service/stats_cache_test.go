package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock is the test clock — call Advance to push virtual time forward
// and emit a tick. The cache's runLoop blocks on the ticker channel so
// callers can drive refresh rounds deterministically.
//
// We keep a separate "tick" channel so a test can advance time without
// triggering a refresh (Advance) or trigger a refresh without advancing
// time (Tick). This split is what lets TestCache_StatusPartialStaleCombo
// freeze refresh while pushing time forward.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	ticker *fakeTicker
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) NewTicker(d time.Duration) Ticker {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTicker{ch: make(chan time.Time, 1)}
	f.ticker = t
	return t
}

// Advance pushes virtual time forward; does NOT emit a tick. Use to drive
// stale derivation tests where we want to age the snapshot without a fresh
// refresh.
func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

// Tick emits a single ticker event at the current virtual time. The runLoop
// will pick it up and execute one refresh round.
func (f *fakeClock) Tick() {
	f.mu.Lock()
	t := f.ticker
	now := f.now
	f.mu.Unlock()
	if t == nil {
		return
	}
	t.ch <- now
}

type fakeTicker struct {
	ch chan time.Time
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }
func (t *fakeTicker) Stop()               {}

// fakeSource is a programmable statsSource. Each call to
// GetAggregatedRuleStatsDetailed returns the next queued result; if the
// queue is empty it returns the lastResult repeatedly. This shape lets
// individual tests script a sequence of "first refresh succeeds, second
// fails, third partial" without rewriting test scaffolding.
type fakeSource struct {
	mu      sync.Mutex
	queue   []AggregatedStatsResult
	lastRes AggregatedStatsResult
	calls   int
}

func (s *fakeSource) push(r AggregatedStatsResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, r)
}

func (s *fakeSource) GetAggregatedRuleStatsDetailed(_ context.Context, _ AggregatedFetchConfig) AggregatedStatsResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if len(s.queue) == 0 {
		return s.lastRes
	}
	r := s.queue[0]
	s.queue = s.queue[1:]
	s.lastRes = r
	return r
}

// getCalls is the race-safe accessor for the call counter. The test
// goroutine and the cache's refresh goroutine both touch s.calls, so
// reading it from a test must go through the same mutex that
// GetAggregatedRuleStatsDetailed uses.
func (s *fakeSource) getCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// helper: assemble a "1 online node fully succeeded" result
func resultOK(stats map[string]*AggregatedRuleStats) AggregatedStatsResult {
	return AggregatedStatsResult{
		Stats:           stats,
		ConfiguredNodes: 1,
		AttemptedNodes:  1,
		SucceededNodes:  1,
		NodeErrors:      map[string]error{},
	}
}

func defaultCfg() StatsCacheConfig {
	return StatsCacheConfig{
		RefreshInterval:  100 * time.Millisecond, // unused in tests; we drive ticks manually
		StaleThreshold:   1 * time.Second,
		PerNodeTimeout:   50 * time.Millisecond,
		MaxConcurrency:   2,
		BackoffOnAllFail: 30 * time.Second,
		TopNCacheSize:    50,
	}
}

// startCache wires a fake source + fake clock and runs Start. Returns the
// cache plus a cleanup func that stops the loop and waits for shutdown.
//
// Tests should call cleanup via t.Cleanup so a Fatalf still releases the
// goroutine.
func startCache(t *testing.T, src *fakeSource, clk *fakeClock, cfg StatsCacheConfig) (*StatsCache, func()) {
	t.Helper()
	c := NewStatsCache(src, clk, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)
	return c, func() {
		cancel()
		c.Stop()
	}
}

func TestCache_StatusInitializingBeforeFirstRefresh(t *testing.T) {
	src := &fakeSource{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	// Don't queue anything; cache will run an initial refresh that returns
	// the zero-value AggregatedStatsResult — configuredNodes=0 → no_nodes.
	// To exercise the *initializing* branch we have to inspect Meta
	// BEFORE the cache has a chance to run its initial refresh. The
	// simplest way is to construct the cache without starting it.
	c := NewStatsCache(src, clk, defaultCfg())
	meta := c.Meta()
	if meta.Status != CacheStatusInitializing {
		t.Fatalf("expected initializing, got %v", meta.Status)
	}
	if meta.LastRefreshStatus != CacheStatusInitializing {
		t.Fatalf("expected last_refresh_status=initializing, got %v", meta.LastRefreshStatus)
	}
	if meta.FreshnessMs != nil {
		t.Fatalf("expected nil freshness, got %v", *meta.FreshnessMs)
	}
}

func TestCache_StatusOKAfterFirstSuccess(t *testing.T) {
	src := &fakeSource{}
	src.push(resultOK(map[string]*AggregatedRuleStats{
		"r1": {MatchCount: 10, DropCount: 5, DropPPS: 1.0},
	}))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()

	// Wait for the eager initial refresh to land.
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "status=ok")

	meta := c.Meta()
	if meta.LastRefreshStatus != CacheStatusOK {
		t.Fatalf("base outcome should be ok, got %v", meta.LastRefreshStatus)
	}
	if meta.LastSnapshotAt.IsZero() {
		t.Fatalf("lastSnapshotAt should be set after success")
	}
	if meta.LastFullSuccessAt.IsZero() {
		t.Fatalf("lastFullSuccessAt should be set after full success")
	}
}

func TestCache_StatusStaleAfterThreshold(t *testing.T) {
	src := &fakeSource{}
	src.push(resultOK(map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}}))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	cfg := defaultCfg()
	cfg.StaleThreshold = 1 * time.Second
	c, cleanup := startCache(t, src, clk, cfg)
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "status=ok")

	// Push virtual time past the stale threshold without firing any new
	// refresh. Meta() must derive stale on its own.
	clk.Advance(2 * time.Second)
	meta := c.Meta()
	if meta.Status != CacheStatusStale {
		t.Fatalf("expected stale, got %v", meta.Status)
	}
	if meta.LastRefreshStatus != CacheStatusOK {
		t.Fatalf("base outcome should still be ok, got %v", meta.LastRefreshStatus)
	}
}

// TestCache_StatusPartialStaleCombo verifies the rev10 spec: partial_stale
// only appears when refresh has stalled. We push a partial result, then
// advance virtual time without ticking, and expect the cache to derive
// partial_stale on its own.
func TestCache_StatusPartialStaleCombo(t *testing.T) {
	src := &fakeSource{}
	src.push(AggregatedStatsResult{
		Stats:               map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}},
		ConfiguredNodes:     2,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedOfflineNodes: 1,
		OfflineNodeNames:    []string{"node-down"},
		NodeErrors:          map[string]error{},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	cfg := defaultCfg()
	cfg.StaleThreshold = 1 * time.Second
	c, cleanup := startCache(t, src, clk, cfg)
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusPartial }, "status=partial")

	// Freeze refresh: stop driving ticks. Advance virtual time past the
	// stale threshold. Meta() should now return partial_stale, while the
	// base outcome remains partial.
	clk.Advance(2 * time.Second)
	meta := c.Meta()
	if meta.Status != CacheStatusPartialStale {
		t.Fatalf("expected partial_stale, got %v", meta.Status)
	}
	if meta.LastRefreshStatus != CacheStatusPartial {
		t.Fatalf("base outcome should remain partial, got %v", meta.LastRefreshStatus)
	}
}

func TestCache_StatusPartialOnSomeNodeFail(t *testing.T) {
	// Online attempted request failure — the only flavor of partial that
	// produces a non-empty NodeErrors map. Other partial paths
	// (Offline/Unknown/Syncing) populate the *NodeNames slices instead.
	src := &fakeSource{}
	src.push(AggregatedStatsResult{
		Stats:           map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}},
		ConfiguredNodes: 3,
		AttemptedNodes:  3,
		SucceededNodes:  2,
		FailedNodes:     1,
		NodeErrors:      map[string]error{"node-c": errors.New("connection refused")},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusPartial }, "partial")

	meta := c.Meta()
	if _, ok := meta.NodeErrors["node-c"]; !ok {
		t.Fatalf("expected nodeErrors to contain attempted-fail node, got %v", meta.NodeErrors)
	}
	if len(meta.OfflineNodeNames) != 0 || len(meta.UnknownNodeNames) != 0 || len(meta.SyncingNodeNames) != 0 {
		t.Fatalf("skipped slices should be empty for attempted-fail-only partial: %+v", meta)
	}
}

func TestCache_StatusPartialOnOfflineNode(t *testing.T) {
	src := &fakeSource{}
	src.push(AggregatedStatsResult{
		Stats:               map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}},
		ConfiguredNodes:     2,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedOfflineNodes: 1,
		OfflineNodeNames:    []string{"down"},
		NodeErrors:          map[string]error{},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusPartial }, "partial")

	meta := c.Meta()
	if len(meta.OfflineNodeNames) != 1 || meta.OfflineNodeNames[0] != "down" {
		t.Fatalf("expected offline_node_names=[down], got %v", meta.OfflineNodeNames)
	}
	if len(meta.NodeErrors) != 0 {
		t.Fatalf("offline-only partial must NOT produce NodeErrors, got %v", meta.NodeErrors)
	}
}

func TestCache_StatusPartialOnSomeUnknownNode(t *testing.T) {
	src := &fakeSource{}
	src.push(AggregatedStatsResult{
		Stats:               map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}},
		ConfiguredNodes:     2,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedUnknownNodes: 1,
		UnknownNodeNames:    []string{"warming"},
		NodeErrors:          map[string]error{},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusPartial }, "partial")

	meta := c.Meta()
	if meta.Status == CacheStatusOK {
		t.Fatalf("warming node must NOT be classified ok")
	}
	if len(meta.UnknownNodeNames) != 1 {
		t.Fatalf("expected one unknown node name, got %v", meta.UnknownNodeNames)
	}
}

func TestCache_StatusOKOnlyWhenAllConfiguredSucceed(t *testing.T) {
	src := &fakeSource{}
	src.push(resultOK(map[string]*AggregatedRuleStats{}))
	src.lastRes = resultOK(nil)
	src.queue = nil
	src.push(resultOK(nil))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "first ok")

	// Queue a partial result; tick to install it; verify status flips off ok.
	src.push(AggregatedStatsResult{
		Stats:               map[string]*AggregatedRuleStats{},
		ConfiguredNodes:     2,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedOfflineNodes: 1,
		OfflineNodeNames:    []string{"x"},
		NodeErrors:          map[string]error{},
	})
	clk.Tick()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusPartial }, "switched to partial")
}

func TestCache_StatusNoNodesWhenZeroConfigured(t *testing.T) {
	src := &fakeSource{}
	// All-zeros result == no configured nodes
	src.push(AggregatedStatsResult{NodeErrors: map[string]error{}})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusNoNodes }, "no_nodes")

	meta := c.Meta()
	if meta.LastRefreshStatus != CacheStatusNoNodes {
		t.Fatalf("base outcome should be no_nodes, got %v", meta.LastRefreshStatus)
	}
	if meta.FreshnessMs != nil {
		t.Fatalf("freshness_ms should be nil for no_nodes")
	}
}

func TestCache_StatusFailedNoSnapshot(t *testing.T) {
	src := &fakeSource{}
	src.push(AggregatedStatsResult{
		ConfiguredNodes: 1,
		AttemptedNodes:  1,
		FailedNodes:     1,
		NodeErrors:      map[string]error{"n": errors.New("boom")},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusFailedNoSnapshot }, "failed_no_snapshot")
}

func TestCache_StatusFailedKeepsLastValue(t *testing.T) {
	src := &fakeSource{}
	src.push(resultOK(map[string]*AggregatedRuleStats{"r1": {MatchCount: 100, DropPPS: 7}}))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "first ok")

	// Now everything fails. We should keep last snapshot but flip status to failed.
	src.push(AggregatedStatsResult{
		ConfiguredNodes: 1,
		AttemptedNodes:  1,
		FailedNodes:     1,
		NodeErrors:      map[string]error{"n": errors.New("boom")},
	})
	clk.Tick()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusFailed }, "failed")

	got := c.LookupMany([]string{"r1"})
	if got["r1"].MatchCount != 100 {
		t.Fatalf("failed status must preserve last snapshot, got %+v", got)
	}
}

func TestCache_DisabledFlagSetsStatus(t *testing.T) {
	cfg := defaultCfg()
	cfg.Disabled = true
	src := &fakeSource{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, cfg)
	defer cleanup()

	// Disabled: cache should return status=disabled WITHOUT having called source.
	meta := c.Meta()
	if meta.Status != CacheStatusDisabled {
		t.Fatalf("expected disabled, got %v", meta.Status)
	}
	if got := src.getCalls(); got != 0 {
		t.Fatalf("disabled cache must not call source, got %d calls", got)
	}
}

func TestCache_LookupManyOnlyReturnsRequested(t *testing.T) {
	src := &fakeSource{}
	stats := map[string]*AggregatedRuleStats{}
	for i := 0; i < 100; i++ {
		stats[itoa(i)] = &AggregatedRuleStats{MatchCount: uint64(i)}
	}
	src.push(resultOK(stats))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "ok")

	got := c.LookupMany([]string{"3", "17", "99"})
	if len(got) != 3 {
		t.Fatalf("LookupMany should return only requested ids, got %d entries: %v", len(got), got)
	}
	if got["3"].MatchCount != 3 || got["99"].MatchCount != 99 {
		t.Fatalf("LookupMany values wrong: %v", got)
	}
}

func TestCache_TopByDropPPSStableSort(t *testing.T) {
	// Two rules with identical DropPPS; tie-breaker by RuleID asc means
	// "a" must always come before "b" regardless of map iteration order.
	src := &fakeSource{}
	stats := map[string]*AggregatedRuleStats{
		"b": {DropPPS: 5, DropCount: 100},
		"a": {DropPPS: 5, DropCount: 100},
		"c": {DropPPS: 10},
	}
	src.push(resultOK(stats))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "ok")

	for trial := 0; trial < 5; trial++ {
		top := c.TopByDropPPS(3)
		if len(top) != 3 {
			t.Fatalf("expected 3 entries, got %d", len(top))
		}
		if top[0].RuleID != "c" {
			t.Fatalf("expected highest PPS first (c), got %s", top[0].RuleID)
		}
		if top[1].RuleID != "a" || top[2].RuleID != "b" {
			t.Fatalf("expected tie-break a,b in that order, got %s,%s", top[1].RuleID, top[2].RuleID)
		}
	}
}

func TestCache_SnapshotIsolation(t *testing.T) {
	src := &fakeSource{}
	src.push(resultOK(map[string]*AggregatedRuleStats{"r1": {MatchCount: 7}}))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "ok")

	snap, _ := c.Snapshot()
	stats := snap.Stats["r1"]
	stats.MatchCount = 999
	snap.Stats["r1"] = stats

	// Re-fetch — the original cache state must be intact.
	snap2, _ := c.Snapshot()
	if snap2.Stats["r1"].MatchCount != 7 {
		t.Fatalf("snapshot mutation leaked back to cache: %v", snap2.Stats["r1"])
	}
}

// TestCache_StatusWaitingForHealth — covers the GPT round-3 P3-1 fix:
// when the controller boots and HealthChecker hasn't run its first round
// yet, every node is in Unknown status. The cache must NOT return
// failed_no_snapshot here (that would be a misleading "give up" signal);
// it should return waiting_for_health so the front-end shows a "loading"
// message instead of "stats unavailable".
func TestCache_StatusWaitingForHealth(t *testing.T) {
	src := &fakeSource{}
	src.push(AggregatedStatsResult{
		ConfiguredNodes:     2,
		SkippedUnknownNodes: 2,
		UnknownNodeNames:    []string{"a", "b"},
		NodeErrors:          map[string]error{},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusWaitingForHealth }, "waiting_for_health")

	meta := c.Meta()
	if meta.LastRefreshStatus != CacheStatusWaitingForHealth {
		t.Fatalf("base outcome should be waiting_for_health, got %v", meta.LastRefreshStatus)
	}
	if meta.FreshnessMs != nil {
		t.Fatalf("freshness must be nil when no snapshot exists yet")
	}
	if len(meta.UnknownNodeNames) != 2 {
		t.Fatalf("expected 2 unknown_node_names, got %v", meta.UnknownNodeNames)
	}
}

// TestCache_StatusPartialOnSomeSyncingNode is the Syncing twin of the
// Unknown test (round-4 P2-1). A node mid-sync must NOT be silently
// excluded — it counts as "absent" so the cluster status drops to partial.
func TestCache_StatusPartialOnSomeSyncingNode(t *testing.T) {
	src := &fakeSource{}
	src.push(AggregatedStatsResult{
		Stats:               map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}},
		ConfiguredNodes:     2,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedSyncingNodes: 1,
		SyncingNodeNames:    []string{"sync-1"},
		NodeErrors:          map[string]error{},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusPartial }, "partial")

	meta := c.Meta()
	if meta.Status == CacheStatusOK {
		t.Fatalf("syncing node must NOT be classified ok")
	}
	if len(meta.SyncingNodeNames) != 1 || meta.SyncingNodeNames[0] != "sync-1" {
		t.Fatalf("expected syncing_node_names=[sync-1], got %v", meta.SyncingNodeNames)
	}
	if len(meta.NodeErrors) != 0 {
		t.Fatalf("syncing-only partial must NOT produce NodeErrors")
	}
}

// TestCache_OfflineUnknownSyncingSeparated drives all three skip kinds at
// once and asserts they land in the right buckets. A regression where
// Unknown leaks into SkippedOfflineNodes (round-3 P3-2) would fail here.
func TestCache_OfflineUnknownSyncingSeparated(t *testing.T) {
	src := &fakeSource{}
	src.push(AggregatedStatsResult{
		Stats:               map[string]*AggregatedRuleStats{},
		ConfiguredNodes:     4,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedOfflineNodes: 1,
		SkippedUnknownNodes: 1,
		SkippedSyncingNodes: 1,
		OfflineNodeNames:    []string{"off"},
		UnknownNodeNames:    []string{"unk"},
		SyncingNodeNames:    []string{"syn"},
		NodeErrors:          map[string]error{},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusPartial }, "partial")

	meta := c.Meta()
	if meta.SkippedOfflineNodes != 1 || meta.SkippedUnknownNodes != 1 || meta.SkippedSyncingNodes != 1 {
		t.Fatalf("skip groups should be 1/1/1, got %d/%d/%d",
			meta.SkippedOfflineNodes, meta.SkippedUnknownNodes, meta.SkippedSyncingNodes)
	}
	// Each name must be in EXACTLY ONE list. The most common regression
	// would be "Unknown bleeds into Offline because the helper grouped them
	// the same way the legacy GetAggregatedRuleStats did."
	if !contains(meta.OfflineNodeNames, "off") || contains(meta.OfflineNodeNames, "unk") || contains(meta.OfflineNodeNames, "syn") {
		t.Fatalf("offline list contaminated: %v", meta.OfflineNodeNames)
	}
	if !contains(meta.UnknownNodeNames, "unk") || contains(meta.UnknownNodeNames, "off") || contains(meta.UnknownNodeNames, "syn") {
		t.Fatalf("unknown list contaminated: %v", meta.UnknownNodeNames)
	}
	if !contains(meta.SyncingNodeNames, "syn") || contains(meta.SyncingNodeNames, "off") || contains(meta.SyncingNodeNames, "unk") {
		t.Fatalf("syncing list contaminated: %v", meta.SyncingNodeNames)
	}
}

// TestCache_RecoveryFromFailed verifies the cache transitions cleanly when
// a previously-failed cluster recovers. The status flip must reset
// consecutive_all_fail and update both lastSnapshotAt and lastFullSuccessAt.
//
// Note: BackoffOnAllFail is set to 1ms here. The runLoop's backoff uses
// wall-clock time.After (FakeClock can't drive it), so a 30s default would
// stall the test for half a minute on its way to the recovery tick.
// Changing this to <1ms keeps the test fast and still exercises the
// backoff path. The actual backoff DURATION is not what we're verifying
// here — that would require extending the Clock interface with NewTimer
// (deferred to v2.6.4 per the rev10 audit notes).
func TestCache_RecoveryFromFailed(t *testing.T) {
	src := &fakeSource{}
	// First refresh: total failure
	src.push(AggregatedStatsResult{
		ConfiguredNodes: 1, AttemptedNodes: 1, FailedNodes: 1,
		NodeErrors: map[string]error{"n": errors.New("boom")},
	})
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	cfg := defaultCfg()
	cfg.BackoffOnAllFail = time.Millisecond // see comment above
	c, cleanup := startCache(t, src, clk, cfg)
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusFailedNoSnapshot }, "failed_no_snapshot")

	// Now the node comes back. Tick to install the success.
	src.push(resultOK(map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}}))
	clk.Tick()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "recovered to ok")

	meta := c.Meta()
	if meta.LastSnapshotAt.IsZero() {
		t.Fatalf("recovery must populate lastSnapshotAt")
	}
	if meta.LastFullSuccessAt.IsZero() {
		t.Fatalf("recovery must populate lastFullSuccessAt")
	}
	if meta.ConsecutiveAllFail != 0 {
		t.Fatalf("recovery must reset consecutiveAllFail, got %d", meta.ConsecutiveAllFail)
	}
}

// TestCache_TopByDropPPSPrecomputed verifies the top slice is computed at
// REFRESH time, not at request time. We ask for top-N right after a refresh
// without giving the cache a chance to do extra work, and the slice must
// already contain the right entries in the right order.
func TestCache_TopByDropPPSPrecomputed(t *testing.T) {
	src := &fakeSource{}
	src.push(resultOK(map[string]*AggregatedRuleStats{
		"a": {DropPPS: 1},
		"b": {DropPPS: 5},
		"c": {DropPPS: 3},
	}))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "ok")

	top := c.TopByDropPPS(3)
	if len(top) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(top))
	}
	// Pre-sorted at refresh time → b > c > a regardless of map order
	if top[0].RuleID != "b" || top[1].RuleID != "c" || top[2].RuleID != "a" {
		t.Fatalf("expected b,c,a (precomputed sort), got %s,%s,%s",
			top[0].RuleID, top[1].RuleID, top[2].RuleID)
	}
}

// TestCache_PartialDoesNotResetLastFullSuccess pins down the lastSnapshotAt
// vs lastFullSuccessAt distinction. partial refreshes advance the snapshot
// clock (so freshness updates) but MUST NOT advance the full-success clock
// (used only as a cache_health diagnostic).
func TestCache_PartialDoesNotResetLastFullSuccess(t *testing.T) {
	src := &fakeSource{}
	// First: full success → both clocks updated to T0
	src.push(resultOK(map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}}))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "first ok")
	t0Snapshot := c.Meta().LastSnapshotAt
	t0FullSuccess := c.Meta().LastFullSuccessAt

	// Advance clock and queue a partial result
	clk.Advance(2 * time.Second)
	src.push(AggregatedStatsResult{
		Stats:               map[string]*AggregatedRuleStats{"r1": {DropPPS: 1}},
		ConfiguredNodes:     2,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedOfflineNodes: 1,
		OfflineNodeNames:    []string{"off"},
		NodeErrors:          map[string]error{},
	})
	clk.Tick()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusPartial }, "partial")

	meta := c.Meta()
	if !meta.LastSnapshotAt.After(t0Snapshot) {
		t.Fatalf("partial refresh must advance lastSnapshotAt: %v -> %v", t0Snapshot, meta.LastSnapshotAt)
	}
	if !meta.LastFullSuccessAt.Equal(t0FullSuccess) {
		t.Fatalf("partial refresh must NOT advance lastFullSuccessAt: %v -> %v", t0FullSuccess, meta.LastFullSuccessAt)
	}
}

// TestCache_ConcurrentReadDuringSwap is the goroutine-safety bedrock test.
// One writer loop drives refresh ticks; many concurrent readers bang on
// every read API. With -race this catches any missing lock or unsafe map
// alias. Without -race it at least confirms nothing panics.
func TestCache_ConcurrentReadDuringSwap(t *testing.T) {
	src := &fakeSource{}
	stats := map[string]*AggregatedRuleStats{}
	for i := 0; i < 50; i++ {
		stats[itoa(i)] = &AggregatedRuleStats{MatchCount: uint64(i)}
	}
	// Pre-load enough refresh results so the loop never runs out
	for i := 0; i < 100; i++ {
		src.push(resultOK(stats))
	}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "first ok")

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer: keep ticking
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				clk.Tick()
			}
		}
	}()

	// 100 readers banging on Meta / LookupMany / TopByDropPPS / Snapshot
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids := []string{"1", "5", "10", "25"}
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = c.Meta()
				_ = c.LookupMany(ids)
				_ = c.TopByDropPPS(10)
				_, _ = c.Snapshot()
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestCache_FakeClockTickRespectsInterval confirms the cache only refreshes
// when the (fake) ticker fires. With wall-clock time stopped, no extra
// refreshes should happen on their own — the cache should be entirely
// driven by ticks the test produces.
func TestCache_FakeClockTickRespectsInterval(t *testing.T) {
	src := &fakeSource{}
	// Pre-load 5 distinct results so we can count how many landed
	for i := 0; i < 5; i++ {
		src.push(resultOK(map[string]*AggregatedRuleStats{"r": {MatchCount: uint64(i)}}))
	}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c, cleanup := startCache(t, src, clk, defaultCfg())
	defer cleanup()
	// Initial refresh (eager, runs on Start) consumes one queued result
	waitFor(t, func() bool { return c.Meta().Status == CacheStatusOK }, "first ok")

	beforeTicks := src.getCalls()

	// Three explicit ticks → three refreshes
	clk.Tick()
	clk.Tick()
	clk.Tick()
	// Give the ticker channel a moment to drain before reading the count
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if src.getCalls()-beforeTicks >= 3 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	got := src.getCalls() - beforeTicks
	if got != 3 {
		t.Fatalf("expected exactly 3 additional refreshes for 3 ticks, got %d", got)
	}
}

// TestCache_StopBeforeStartReturns is the round-9 P3-3 guard: a cache that
// was constructed but never had Start() called must NOT block in Stop().
//
// The realistic call site for this is constructor-level wiring failure:
// `cache := NewStatsCache(...); defer cache.Stop()` followed by an early
// return for some other config error before Start is reached. Without the
// `started` flag the deferred Stop would wait on doneCh forever, since
// doneCh is only closed by Start's disabled branch or runLoop's defer.
func TestCache_StopBeforeStartReturns(t *testing.T) {
	src := &fakeSource{}
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c := NewStatsCache(src, clk, defaultCfg())

	// No Start. Stop must return promptly instead of waiting forever.
	stopped := make(chan struct{})
	go func() {
		c.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		// good — Stop returned without Start ever happening
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("Stop blocked when Start was never called")
	}
}

func TestCache_StopHonorsCtxCancel(t *testing.T) {
	src := &fakeSource{}
	src.push(resultOK(nil))
	clk := newFakeClock(time.Unix(1_700_000_000, 0))
	c := NewStatsCache(src, clk, defaultCfg())
	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)
	cancel()

	stopped := make(chan struct{})
	go func() {
		c.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Stop did not return within 500ms after ctx cancel")
	}
}

// waitFor polls cond every 5ms up to ~500ms so test setup with the eager
// initial refresh has time to land. Using polling instead of a channel
// avoids re-plumbing the cache to expose internal events for tests.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waitFor timeout: %s", what)
}

func itoa(i int) string {
	// avoid importing strconv just for this — keep test deps tight
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
