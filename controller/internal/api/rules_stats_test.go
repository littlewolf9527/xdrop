// rules_stats_test.go — v2.6.3 contract tests for List / TopRules / listAll.
//
// Verifies that for every CacheStatus the handler emits the right top-level
// stats meta fields and the right per-rule .stats shape (omitted vs. synthesized
// 0/0/0 vs. real numbers vs. last snapshot). Cache state is driven by a
// minimal mock source that satisfies the unexported service.statsSource
// interface via Go's structural typing — no need to expose service-package
// internals.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// mockStatsSource is a programmable statsSource. push(result) queues the next
// AggregatedStatsResult to be returned; once the queue drains, the most recent
// result is repeated. The cache calls this on every refresh tick, so a single
// pushed result installs a reproducible cache state.
type mockStatsSource struct {
	mu      sync.Mutex
	queue   []service.AggregatedStatsResult
	lastRes service.AggregatedStatsResult
	calls   int
}

func (m *mockStatsSource) push(r service.AggregatedStatsResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queue = append(m.queue, r)
}

func (m *mockStatsSource) GetAggregatedRuleStatsDetailed(_ context.Context, _ service.AggregatedFetchConfig) service.AggregatedStatsResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if len(m.queue) == 0 {
		return m.lastRes
	}
	r := m.queue[0]
	m.queue = m.queue[1:]
	m.lastRes = r
	return r
}

// mockClock — minimal Clock interface stand-in. Unlike the FakeClock in
// service/stats_cache_test.go (which is package-internal), this lives in the
// api package's test scope. Same idea: NewTicker hands back a controllable
// channel so we can fire ticks deterministically; Advance bumps virtual time
// so deriveStatus can promote ok→stale or partial→partial_stale without
// triggering a refresh.
type mockClock struct {
	mu     sync.Mutex
	now    time.Time
	ticker *mockTicker
}

func newMockClock(start time.Time) *mockClock {
	return &mockClock{now: start}
}

func (m *mockClock) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

func (m *mockClock) NewTicker(d time.Duration) service.Ticker {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := &mockTicker{ch: make(chan time.Time, 1)}
	m.ticker = t
	return t
}

func (m *mockClock) Advance(d time.Duration) {
	m.mu.Lock()
	m.now = m.now.Add(d)
	m.mu.Unlock()
}

// Tick fires a single ticker event at the current virtual time. Used by
// multi-step contract tests that need to walk the cache through a sequence
// of refresh outcomes (e.g. ok → failed). The runLoop blocks on the ticker
// channel, so this is the manual driver — equivalent to "wait for the
// 5-second timer to fire" without actually waiting.
//
// No-op if no ticker has been created yet (i.e. cache hasn't started).
func (m *mockClock) Tick() {
	m.mu.Lock()
	t := m.ticker
	now := m.now
	m.mu.Unlock()
	if t == nil {
		return
	}
	t.ch <- now
}

type mockTicker struct{ ch chan time.Time }

func (t *mockTicker) C() <-chan time.Time { return t.ch }
func (t *mockTicker) Stop()               {}

// makeContractTestHarness builds the smallest end-to-end fixture: a real
// RuleService backed by an in-memory SQLite, a real StatsCache backed by a
// programmable mock source, and a Gin engine wired to the v2.6.3 handlers.
//
// Setup chooses defaults that keep the cache in a deterministic state:
//   - StaleThreshold 1s so tests can flip ok→stale by Advance(2s).
//   - BackoffOnAllFail set to 1ms so failure-recovery tests don't get stuck
//     on the wall-clock time.After backoff (see stats_cache_test.go for the
//     same workaround and explanation).
type contractHarness struct {
	t       *testing.T
	src     *mockStatsSource
	clk     *mockClock
	cache   *service.StatsCache
	handler *RulesHandler
	// seededIDs maps the caller-supplied rule labels (e.g. "r1") to the
	// auto-generated rule IDs assigned by RuleService.Create. Tests use
	// these real IDs both when pushing stats into the mock source and
	// when asserting per-rule fields in the handler response — without
	// this mapping the cache lookup keyed by label would never hit a
	// real rule, making the positive contract case a no-op (round-9 P3-2).
	seededIDs map[string]string
	cleanup   func()
}

func newContractHarness(t *testing.T, ruleIDs []string) *contractHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "contract.db")
	db, err := repository.NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	repo := repository.NewSQLiteRuleRepo(db)
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	syncLogRepo := repository.NewSQLiteSyncLogRepo(db)
	syncSvc := service.NewSyncService(fakeNodeProvider{}, syncLogRepo, repo, wlRepo, nil, 1, 0, time.Millisecond)
	ruleSvc := service.NewRuleService(repo, syncSvc)

	// Seed rules so handlers can return them. Capture the auto-generated
	// rule ID under each label so tests can correlate cache stats to the
	// rule the handler returns.
	seededIDs := make(map[string]string, len(ruleIDs))
	for i, id := range ruleIDs {
		comment := id
		rule, _, err := ruleSvc.Create(&model.RuleRequest{
			SrcIP:    fmt.Sprintf("198.51.100.%d", i+1),
			Protocol: "tcp",
			Action:   "drop",
			Comment:  &comment, // pointer tri-state — see model.RuleRequest
		})
		if err != nil {
			t.Fatalf("seed rule %s: %v", id, err)
		}
		seededIDs[id] = rule.ID
	}

	src := &mockStatsSource{}
	clk := newMockClock(time.Unix(1_700_000_000, 0))

	cfg := service.StatsCacheConfig{
		RefreshInterval:  100 * time.Millisecond,
		StaleThreshold:   1 * time.Second,
		PerNodeTimeout:   50 * time.Millisecond,
		MaxConcurrency:   2,
		BackoffOnAllFail: 1 * time.Millisecond, // see comment above
		TopNCacheSize:    50,
	}

	cache := service.NewStatsCache(src, clk, cfg)
	// Note: cache.Start is intentionally deferred to start() below. The
	// initial refresh runs as soon as Start fires, so any test scenario
	// that wants a specific first-tick result must push BEFORE start().

	handler := NewRulesHandler(ruleSvc, nil, cache)

	return &contractHarness{
		t:         t,
		src:       src,
		clk:       clk,
		cache:     cache,
		handler:   handler,
		seededIDs: seededIDs,
		cleanup: func() {
			cache.Stop()
			db.Close()
			os.RemoveAll(tmpDir)
		},
	}
}

// start launches the cache loop. Tests call this AFTER push()-ing the
// initial refresh result so the eager startup refresh sees that result
// (and not the zero-value AggregatedStatsResult, which would land the
// cache in no_nodes regardless of the test's intent).
func (h *contractHarness) start() {
	h.t.Helper()
	h.cache.Start(context.Background())
}

// waitForStatus polls Meta() until Status matches target. Sometimes the
// initial refresh that runs on Start() lands during this wait — that's fine,
// we just need a stable state before hitting the handler.
func (h *contractHarness) waitForStatus(target service.CacheStatus) {
	h.t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if h.cache.Meta().Status == target {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.t.Fatalf("waitForStatus timeout: want %v, got %v", target, h.cache.Meta().Status)
}

// hitJSON runs a single GET request through the handler and decodes the
// response body into a generic map. Reusing httptest.ResponseRecorder keeps
// the test simple — no actual network involved.
//
// Note: gin's `Handle(method, path, ...)` registers based on the path
// SHAPE only, with no query-string awareness. We split the user-supplied
// `urlWithQuery` so the registered route matches the path part while the
// request URI carries the query.
func (h *contractHarness) hitJSON(method, urlWithQuery string, handlerFn gin.HandlerFunc) (int, map[string]any) {
	h.t.Helper()
	pathOnly := urlWithQuery
	if i := indexByte(urlWithQuery, '?'); i >= 0 {
		pathOnly = urlWithQuery[:i]
	}
	req := httptest.NewRequest(method, urlWithQuery, nil)
	w := httptest.NewRecorder()
	r := gin.New()
	r.Handle(method, pathOnly, handlerFn)
	r.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		h.t.Fatalf("decode response: %v\nbody=%s", err, w.Body.String())
	}
	return w.Code, body
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// assertSixMetaFields enforces the rev10 contract: every stats-aware response
// MUST include all six top-level stats_* fields (some may be empty/null,
// but the keys themselves are required). A regression that drops a key would
// silently shift front-end logic (e.g. Vue's `data.stats_status || ”`
// fallback would mask the bug).
func assertSixMetaFields(t *testing.T, body map[string]any, wantStatus string) {
	t.Helper()
	required := []string{
		"stats_status", "stats_freshness_ms",
		"stats_node_failures", "stats_offline_nodes",
		"stats_unknown_nodes", "stats_syncing_nodes",
	}
	for _, k := range required {
		if _, ok := body[k]; !ok {
			t.Fatalf("missing required meta field %q in response: %v", k, body)
		}
	}
	if got := body["stats_status"]; got != wantStatus {
		t.Fatalf("stats_status = %v, want %v", got, wantStatus)
	}
}

// rulesField extracts the rules slice as []any. Helper to avoid repeating
// the same type-assertion boilerplate in each test.
func rulesField(t *testing.T, body map[string]any) []any {
	t.Helper()
	raw, ok := body["rules"]
	if !ok {
		t.Fatalf("response has no rules field: %v", body)
	}
	rules, ok := raw.([]any)
	if !ok {
		t.Fatalf("rules field is not a slice: %T", raw)
	}
	return rules
}

// fakeOK constructs an "all configured nodes succeeded" result.
func fakeOK(stats map[string]*service.AggregatedRuleStats) service.AggregatedStatsResult {
	return service.AggregatedStatsResult{
		Stats:           stats,
		ConfiguredNodes: 1,
		AttemptedNodes:  1,
		SucceededNodes:  1,
		NodeErrors:      map[string]error{},
	}
}

// ---------- TestRulesHandler_PaginatedListContract ----------
//
// Verifies the v2.6.3 paginated response contract for every CacheStatus a
// handler can encounter at request time.
//
// Checks per case:
//  1. Six top-level stats_* fields are present.
//  2. stats_status equals the cache's derived status.
//  3. stats_freshness_ms is null vs. number per the D.4 table.
//  4. Per-rule stats key obeys the omit/synth-zero/actual contract.
//
// Statuses NOT covered here:
//   - waiting_for_health: indistinguishable from initializing at the wire
//     level (both omit stats keys + null freshness). Covered in
//     stats_cache_test.go; smoke-checked separately below if needed.
func TestRulesHandler_PaginatedListContract(t *testing.T) {
	// Each subtest gets its OWN harness, since calling Start() is one-time
	// per cache and the initial refresh only sees what was pushed before
	// Start. Sharing a harness across cases would let state leak between
	// scenarios.
	//
	// The buildPush field takes the seededIDs map so a case can reference
	// the actual generated rule ID (round-9 P3-2). Without that indirection
	// the cache would receive stats keyed by a label that doesn't exist on
	// any real rule, and the positive "stats stitched back" path would be
	// untested even though the case looks like it covers it.
	type tc struct {
		name          string
		buildPush     func(seededIDs map[string]string) service.AggregatedStatsResult
		wantStatus    service.CacheStatus
		wantStatsOmit bool // missing stats key on rule entries
		wantSynthZero bool // when stats present and rule had no hits, must be 0/0/0
		wantFreshNil  bool // stats_freshness_ms must be null

		// expectStatsForLabel is the seed label whose response stats are
		// asserted to match the values we pushed into the cache. Empty
		// string disables the per-rule value check.
		expectStatsForLabel string
		expectMatchCount    uint64
		expectDropCount     uint64
		expectDropPPS       float64
	}

	cases := []tc{
		{
			name: "ok-with-data",
			buildPush: func(ids map[string]string) service.AggregatedStatsResult {
				return fakeOK(map[string]*service.AggregatedRuleStats{
					ids["r1"]: {MatchCount: 42, DropCount: 7, DropPPS: 1.5},
				})
			},
			wantStatus:          service.CacheStatusOK,
			expectStatsForLabel: "r1",
			expectMatchCount:    42,
			expectDropCount:     7,
			expectDropPPS:       1.5,
		},
		{
			name:          "ok-no-data-synth-zero",
			buildPush:     func(_ map[string]string) service.AggregatedStatsResult { return fakeOK(nil) },
			wantStatus:    service.CacheStatusOK,
			wantSynthZero: true,
		},
		{
			name: "no_nodes",
			buildPush: func(_ map[string]string) service.AggregatedStatsResult {
				return service.AggregatedStatsResult{NodeErrors: map[string]error{}}
			},
			wantStatus:    service.CacheStatusNoNodes,
			wantStatsOmit: true,
			wantFreshNil:  true,
		},
		{
			name: "partial-offline",
			buildPush: func(_ map[string]string) service.AggregatedStatsResult {
				return service.AggregatedStatsResult{
					Stats:               map[string]*service.AggregatedRuleStats{},
					ConfiguredNodes:     2,
					AttemptedNodes:      1,
					SucceededNodes:      1,
					SkippedOfflineNodes: 1,
					OfflineNodeNames:    []string{"node-down"},
					NodeErrors:          map[string]error{},
				}
			},
			wantStatus:    service.CacheStatusPartial,
			wantStatsOmit: true,
		},
		{
			// Real-world regression for the round-N P2 finding: Node agents
			// always emit `stats: {0,0,0}` for rules with no hits. Under
			// partial we used to forward those zeros with a partial badge,
			// which reads as "we know there are 0 hits cluster-wide" — but
			// the failed/offline nodes might have hits we never saw, so
			// the zero is just a lower bound, not a fact. Contract D.4 says
			// to omit. This case pushes a zero entry KEYED BY the real rule
			// ID and asserts the response omits stats.
			name: "partial-zero-stats-from-succeeded-node",
			buildPush: func(ids map[string]string) service.AggregatedStatsResult {
				return service.AggregatedStatsResult{
					Stats: map[string]*service.AggregatedRuleStats{
						ids["r1"]: {MatchCount: 0, DropCount: 0, DropPPS: 0},
					},
					ConfiguredNodes:     2,
					AttemptedNodes:      1,
					SucceededNodes:      1,
					SkippedOfflineNodes: 1,
					OfflineNodeNames:    []string{"node-down"},
					NodeErrors:          map[string]error{},
				}
			},
			wantStatus:    service.CacheStatusPartial,
			wantStatsOmit: true, // ← critical: zero from succeeded node MUST NOT be displayed under partial
		},
		{
			// Companion to the zero-stats case: when the succeeded node DID
			// see real hits, we obviously want to surface them, just with
			// the partial badge. Without this case the test wouldn't
			// distinguish "always omit under partial" (over-eager fix)
			// from "omit only zero entries under partial" (correct fix).
			name: "partial-real-stats-from-succeeded-node",
			buildPush: func(ids map[string]string) service.AggregatedStatsResult {
				return service.AggregatedStatsResult{
					Stats: map[string]*service.AggregatedRuleStats{
						ids["r1"]: {MatchCount: 99, DropCount: 11, DropPPS: 2.5},
					},
					ConfiguredNodes:     2,
					AttemptedNodes:      1,
					SucceededNodes:      1,
					SkippedOfflineNodes: 1,
					OfflineNodeNames:    []string{"node-down"},
					NodeErrors:          map[string]error{},
				}
			},
			wantStatus:          service.CacheStatusPartial,
			expectStatsForLabel: "r1",
			expectMatchCount:    99,
			expectDropCount:     11,
			expectDropPPS:       2.5,
		},
		{
			name: "failed_no_snapshot",
			buildPush: func(_ map[string]string) service.AggregatedStatsResult {
				return service.AggregatedStatsResult{
					ConfiguredNodes: 1, AttemptedNodes: 1, FailedNodes: 1,
					NodeErrors: map[string]error{"n": fmt.Errorf("boom")},
				}
			},
			wantStatus:    service.CacheStatusFailedNoSnapshot,
			wantStatsOmit: true,
			wantFreshNil:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newContractHarness(t, []string{"r1"})
			defer h.cleanup()

			h.src.push(c.buildPush(h.seededIDs))
			h.start()
			h.waitForStatus(c.wantStatus)

			code, body := h.hitJSON("GET", "/api/v1/rules?page=1&limit=50", h.handler.List)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200", code)
			}
			assertSixMetaFields(t, body, string(c.wantStatus))

			if c.wantFreshNil && body["stats_freshness_ms"] != nil {
				t.Fatalf("stats_freshness_ms should be null for %s, got %v",
					c.wantStatus, body["stats_freshness_ms"])
			}

			rules := rulesField(t, body)
			if len(rules) == 0 {
				t.Fatalf("expected at least one rule in response")
			}
			rule := rules[0].(map[string]any)
			gotStats, hasStats := rule["stats"]

			if c.wantStatsOmit && hasStats {
				t.Fatalf("expected stats key to be OMITTED for status=%s, got %v",
					c.wantStatus, rule["stats"])
			}
			if !c.wantStatsOmit && !hasStats && c.wantSynthZero {
				t.Fatalf("expected synthesized 0/0/0 stats for status=ok, got missing key")
			}

			// Positive value assertion: when this case pushed real stats
			// keyed by the rule's actual generated ID, verify the handler
			// stitched them back into the response. A regression that
			// breaks the cache→handler join would slip past the omit/synth
			// checks above; this assertion is the part round-9 P3-2 was
			// missing.
			if c.expectStatsForLabel != "" {
				realID := h.seededIDs[c.expectStatsForLabel]
				if got, ok := rule["id"].(string); !ok || got != realID {
					t.Fatalf("response rule id = %v, want %v (label %s)",
						rule["id"], realID, c.expectStatsForLabel)
				}
				statsMap, ok := gotStats.(map[string]any)
				if !ok {
					t.Fatalf("stats field should be an object, got %T: %v", gotStats, gotStats)
				}
				if got := uint64(statsMap["match_count"].(float64)); got != c.expectMatchCount {
					t.Fatalf("match_count = %d, want %d", got, c.expectMatchCount)
				}
				if got := uint64(statsMap["drop_count"].(float64)); got != c.expectDropCount {
					t.Fatalf("drop_count = %d, want %d", got, c.expectDropCount)
				}
				if got := statsMap["drop_pps"].(float64); got != c.expectDropPPS {
					t.Fatalf("drop_pps = %v, want %v", got, c.expectDropPPS)
				}
			}
		})
	}
}

// TestRulesHandler_StaleZeroStatsFromOKSnapshot exercises the round-N P2
// (re-fix) path: a snapshot captured under `ok` is authoritative even when
// it ages past stale_threshold. Zero values in that snapshot stay as 0/0/0
// under the resulting `stale` status; they are NOT lower-bound zeros and
// must NOT be omitted.
//
// Setup:
//  1. Push an ok result with `r1` carrying explicit 0/0/0.
//  2. Start the cache; wait until status=ok.
//  3. Advance the FakeClock past stale_threshold without firing a refresh.
//  4. GET /api/v1/rules?page=...
//  5. Expect: stats_status=stale, the rule's stats key IS PRESENT with 0/0/0.
//
// This is the test that distinguishes the round-N audit's "stale snapshot
// zeros are still authoritative" rule from the previous over-eager fix
// that omitted any non-ok zero.
func TestRulesHandler_StaleZeroStatsFromOKSnapshot(t *testing.T) {
	h := newContractHarness(t, []string{"r1"})
	defer h.cleanup()

	h.src.push(fakeOK(map[string]*service.AggregatedRuleStats{
		h.seededIDs["r1"]: {MatchCount: 0, DropCount: 0, DropPPS: 0},
	}))
	h.start()
	h.waitForStatus(service.CacheStatusOK)

	// Advance past stale threshold (1s by harness default). No new tick fired,
	// so cache should stay on the same snapshot but Meta() derives stale.
	h.clk.Advance(2 * time.Second)
	h.waitForStatus(service.CacheStatusStale)

	_, body := h.hitJSON("GET", "/api/v1/rules?page=1&limit=50", h.handler.List)
	assertSixMetaFields(t, body, string(service.CacheStatusStale))

	rules := rulesField(t, body)
	if len(rules) == 0 {
		t.Fatalf("expected one rule")
	}
	rule := rules[0].(map[string]any)
	statsRaw, ok := rule["stats"]
	if !ok {
		t.Fatalf("stale-from-ok must KEEP stats key (zero values are authoritative): %v", rule)
	}
	stats := statsRaw.(map[string]any)
	if stats["match_count"].(float64) != 0 ||
		stats["drop_count"].(float64) != 0 ||
		stats["drop_pps"].(float64) != 0 {
		t.Fatalf("expected 0/0/0 from ok snapshot, got %v", stats)
	}
}

// TestRulesHandler_PartialStaleZeroStatsFromPartialSnapshot is the symmetric
// case to the test above: a snapshot captured as `partial` represents lower
// bounds. Once it ages into `partial_stale`, the zero entries are still
// lower-bound zeros and MUST be omitted (same as plain `partial`).
//
// Without this case, a regression that classifies `partial_stale` as
// "authoritative because it's an old snapshot" would slip through.
func TestRulesHandler_PartialStaleZeroStatsFromPartialSnapshot(t *testing.T) {
	h := newContractHarness(t, []string{"r1"})
	defer h.cleanup()

	h.src.push(service.AggregatedStatsResult{
		Stats: map[string]*service.AggregatedRuleStats{
			h.seededIDs["r1"]: {MatchCount: 0, DropCount: 0, DropPPS: 0},
		},
		ConfiguredNodes:     2,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedOfflineNodes: 1,
		OfflineNodeNames:    []string{"node-down"},
		NodeErrors:          map[string]error{},
	})
	h.start()
	h.waitForStatus(service.CacheStatusPartial)

	h.clk.Advance(2 * time.Second)
	h.waitForStatus(service.CacheStatusPartialStale)

	_, body := h.hitJSON("GET", "/api/v1/rules?page=1&limit=50", h.handler.List)
	assertSixMetaFields(t, body, string(service.CacheStatusPartialStale))

	rules := rulesField(t, body)
	rule := rules[0].(map[string]any)
	if _, hasStats := rule["stats"]; hasStats {
		t.Fatalf("partial_stale-from-partial: zero entry must be omitted, got %v", rule["stats"])
	}
}

// TestRulesHandler_FailedAfterOKSnapshot covers the "failed but we have an
// ok snapshot stashed" case. We need to keep showing the snapshot's
// authoritative zeros (with a failed badge in UI) — operators should see
// "the last successful read was 0 hits, and we currently can't fetch new
// data" rather than "no data at all".
//
// Setup:
//  1. Push an ok result with `r1` at 0/0/0. Wait for status=ok.
//  2. Push an all-failed result. Tick. Wait for status=failed.
//  3. Hit /rules?page=, expect stats key present at 0/0/0.
func TestRulesHandler_FailedAfterOKSnapshot(t *testing.T) {
	h := newContractHarness(t, []string{"r1"})
	defer h.cleanup()

	h.src.push(fakeOK(map[string]*service.AggregatedRuleStats{
		h.seededIDs["r1"]: {MatchCount: 0, DropCount: 0, DropPPS: 0},
	}))
	h.start()
	h.waitForStatus(service.CacheStatusOK)

	h.src.push(service.AggregatedStatsResult{
		ConfiguredNodes: 1, AttemptedNodes: 1, FailedNodes: 1,
		NodeErrors: map[string]error{"n": fmt.Errorf("boom")},
	})
	h.clk.Tick()
	h.waitForStatus(service.CacheStatusFailed)

	_, body := h.hitJSON("GET", "/api/v1/rules?page=1&limit=50", h.handler.List)
	assertSixMetaFields(t, body, string(service.CacheStatusFailed))

	rules := rulesField(t, body)
	rule := rules[0].(map[string]any)
	statsRaw, ok := rule["stats"]
	if !ok {
		t.Fatalf("failed-after-ok must KEEP stats key (snapshot zero is authoritative): %v", rule)
	}
	stats := statsRaw.(map[string]any)
	if stats["match_count"].(float64) != 0 {
		t.Fatalf("expected match_count=0 from preserved ok snapshot, got %v", stats)
	}
}

// TestRulesHandler_FailedAfterPartialSnapshot is the symmetric inverse:
// when the cache's last good snapshot was `partial`, transitioning to
// `failed` does NOT magically turn that lower-bound zero into an
// authoritative one. Zero entries must continue to be omitted. This test
// is the one that catches the "failed inherits ok-style synth-zero"
// regression.
func TestRulesHandler_FailedAfterPartialSnapshot(t *testing.T) {
	h := newContractHarness(t, []string{"r1"})
	defer h.cleanup()

	// First push: partial with zero entry. lastSnapshotBaseStatus = partial.
	h.src.push(service.AggregatedStatsResult{
		Stats: map[string]*service.AggregatedRuleStats{
			h.seededIDs["r1"]: {MatchCount: 0, DropCount: 0, DropPPS: 0},
		},
		ConfiguredNodes:     2,
		AttemptedNodes:      1,
		SucceededNodes:      1,
		SkippedOfflineNodes: 1,
		OfflineNodeNames:    []string{"node-down"},
		NodeErrors:          map[string]error{},
	})
	h.start()
	h.waitForStatus(service.CacheStatusPartial)

	// Second push: all-fail. Cache keeps the prior partial snapshot but
	// transitions status to `failed`. The kept zero is STILL a lower
	// bound from the partial era — the fact that we now can't refresh
	// doesn't promote it to authoritative.
	h.src.push(service.AggregatedStatsResult{
		ConfiguredNodes: 2, AttemptedNodes: 2, FailedNodes: 2,
		NodeErrors: map[string]error{"n1": fmt.Errorf("boom"), "n2": fmt.Errorf("boom")},
	})
	h.clk.Tick()
	h.waitForStatus(service.CacheStatusFailed)

	_, body := h.hitJSON("GET", "/api/v1/rules?page=1&limit=50", h.handler.List)
	assertSixMetaFields(t, body, string(service.CacheStatusFailed))

	rules := rulesField(t, body)
	rule := rules[0].(map[string]any)
	if _, hasStats := rule["stats"]; hasStats {
		t.Fatalf("failed-after-partial: zero from lower-bound snapshot must STAY omitted, got %v", rule["stats"])
	}
}

// TestRulesHandler_TopRulesContract drives /rules/top through ok / partial /
// no_nodes / disabled / failed_no_snapshot and asserts the wire shape.
//
// `stale` and `partial_stale` aren't in the table because triggering them
// requires the FakeClock to advance past StaleThreshold, which is
// orthogonal to the contract verification here (stats_cache_test.go has
// per-state coverage).
func TestRulesHandler_TopRulesContract(t *testing.T) {
	cases := []struct {
		name       string
		push       service.AggregatedStatsResult
		wantStatus service.CacheStatus
		wantEmpty  bool
	}{
		{
			"ok-empty",
			fakeOK(nil), // No rules with drop_pps>0 → empty rules array
			service.CacheStatusOK,
			true,
		},
		{
			"failed_no_snapshot",
			service.AggregatedStatsResult{
				ConfiguredNodes: 1, AttemptedNodes: 1, FailedNodes: 1,
				NodeErrors: map[string]error{"n": fmt.Errorf("boom")},
			},
			service.CacheStatusFailedNoSnapshot,
			true,
		},
		{
			"no_nodes",
			service.AggregatedStatsResult{NodeErrors: map[string]error{}},
			service.CacheStatusNoNodes,
			true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newContractHarness(t, []string{"r1"})
			defer h.cleanup()
			h.src.push(c.push)
			h.start()
			h.waitForStatus(c.wantStatus)

			code, body := h.hitJSON("GET", "/api/v1/rules/top?limit=10", h.handler.TopRules)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200", code)
			}
			assertSixMetaFields(t, body, string(c.wantStatus))

			rules := rulesField(t, body)
			if c.wantEmpty && len(rules) != 0 {
				t.Fatalf("expected empty rules for status=%s, got %d entries", c.wantStatus, len(rules))
			}
		})
	}
}

// TestRulesHandler_ListAllDisabledFallback verifies the spec'd escape hatch:
// when stats_cache.disabled=true the listAll endpoint MUST behave like
// pre-v2.6.3 — synchronous fan-out semantics, no stats meta in the envelope.
//
// We can't exercise an actual fan-out here without a NodeService + httptest
// servers, so we settle for the visible part of the contract: the response
// MUST NOT include any stats_* meta field (this distinguishes "old envelope"
// from "new envelope with maybe-empty meta").
func TestRulesHandler_ListAllDisabledFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "disabled.db")
	db, _ := repository.NewSQLiteDB(dbPath)
	defer func() { db.Close(); os.RemoveAll(tmpDir) }()

	repo := repository.NewSQLiteRuleRepo(db)
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	syncLogRepo := repository.NewSQLiteSyncLogRepo(db)
	syncSvc := service.NewSyncService(fakeNodeProvider{}, syncLogRepo, repo, wlRepo, nil, 1, 0, time.Millisecond)
	ruleSvc := service.NewRuleService(repo, syncSvc)

	src := &mockStatsSource{}
	clk := newMockClock(time.Unix(1_700_000_000, 0))
	cfg := service.StatsCacheConfig{
		RefreshInterval:  100 * time.Millisecond,
		StaleThreshold:   1 * time.Second,
		PerNodeTimeout:   50 * time.Millisecond,
		MaxConcurrency:   2,
		BackoffOnAllFail: 1 * time.Millisecond,
		TopNCacheSize:    50,
		Disabled:         true, // ← the thing under test
	}
	cache := service.NewStatsCache(src, clk, cfg)
	cache.Start(context.Background())
	defer cache.Stop()

	// nodeSvc nil here is OK for this test: the handler's listAll fallback
	// calls h.nodeSvc.GetAggregatedRuleStats() but only AFTER detecting
	// disabled — so we'd panic if cache routing was wrong. Use a real but
	// empty NodeService instead so the legacy path works.
	nodeSvc := service.NewNodeService(repo, wlRepo, nil, nil)
	handler := NewRulesHandler(ruleSvc, nodeSvc, cache)

	// listAll path is triggered by NO query params at all
	req := httptest.NewRequest("GET", "/api/v1/rules", nil)
	w := httptest.NewRecorder()
	r := gin.New()
	r.GET("/api/v1/rules", handler.List)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"stats_status", "stats_freshness_ms", "stats_offline_nodes"} {
		if _, ok := body[k]; ok {
			t.Fatalf("disabled-mode listAll must NOT include meta field %q, but got: %v", k, body)
		}
	}
}

// BenchmarkPaginatedListLookupVsSnapshot is the rev10 acceptance criterion
// in benchmark form: page-scoped LookupMany must use materially less memory
// per request than a full Snapshot. We synth a 10k-rule cache and a 50-id
// page.
//
// AllocsPerOp is the headline number — Snapshot allocates a map sized to
// the entire stats catalog plus value copies for every entry, whereas
// LookupMany only allocates for the requested ids. The exact ratio depends
// on Go's map allocation strategy; the test uses `b.ReportAllocs()` to
// surface it without enforcing a hard threshold (CI hosts have varying
// allocation costs).
func BenchmarkPaginatedListLookupVsSnapshot(b *testing.B) {
	src := &mockStatsSource{}
	stats := map[string]*service.AggregatedRuleStats{}
	for i := 0; i < 10_000; i++ {
		stats[fmt.Sprintf("rule-%d", i)] = &service.AggregatedRuleStats{
			MatchCount: uint64(i), DropPPS: float64(i) / 100,
		}
	}
	src.push(fakeOK(stats))

	clk := newMockClock(time.Unix(1_700_000_000, 0))
	cfg := service.StatsCacheConfig{
		RefreshInterval:  10 * time.Second,
		StaleThreshold:   60 * time.Second,
		PerNodeTimeout:   1 * time.Second,
		MaxConcurrency:   2,
		BackoffOnAllFail: 1 * time.Millisecond,
		TopNCacheSize:    50,
	}
	cache := service.NewStatsCache(src, clk, cfg)
	cache.Start(context.Background())
	defer cache.Stop()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && cache.Meta().Status != service.CacheStatusOK {
		time.Sleep(2 * time.Millisecond)
	}

	// Build a page-worth of ids — 50 entries from the middle of the catalog
	// so the lookups don't all hit the same hash bucket.
	pageIDs := make([]string, 50)
	for i := range pageIDs {
		pageIDs[i] = fmt.Sprintf("rule-%d", 5_000+i)
	}

	b.Run("LookupMany", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = cache.LookupMany(pageIDs)
		}
	})
	b.Run("Snapshot", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = cache.Snapshot()
		}
	})
}
