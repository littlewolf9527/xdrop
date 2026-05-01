package service

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// CacheStatus is the union of base outcomes (written by refresh) and derived
// statuses (computed at Meta() read time).
//
//	base outcomes  : initializing, waiting_for_health, no_nodes,
//	                 ok, partial, failed, failed_no_snapshot, disabled
//	derived only   : stale (← ok), partial_stale (← partial)
//
// The base/derived split matters because partial_stale is reachable only if
// the refresh ticker has stalled — see deriveStatus. Storing a derived value
// in cacheState.status would mask the underlying refresh outcome and break
// cache_health's last_refresh_status diagnostic.
type CacheStatus string

const (
	CacheStatusInitializing     CacheStatus = "initializing"
	CacheStatusWaitingForHealth CacheStatus = "waiting_for_health"
	CacheStatusNoNodes          CacheStatus = "no_nodes"
	CacheStatusOK               CacheStatus = "ok"
	CacheStatusStale            CacheStatus = "stale"
	CacheStatusPartial          CacheStatus = "partial"
	CacheStatusPartialStale     CacheStatus = "partial_stale"
	CacheStatusFailed           CacheStatus = "failed"
	CacheStatusFailedNoSnapshot CacheStatus = "failed_no_snapshot"
	CacheStatusDisabled         CacheStatus = "disabled"
)

// StatsCacheConfig is the runtime form of the user-facing
// config.StatsCacheRawConfig (which uses int seconds). The wiring layer
// converts seconds to time.Duration so this struct can be consumed by the
// service package without an import cycle back into config.
type StatsCacheConfig struct {
	RefreshInterval  time.Duration
	StaleThreshold   time.Duration
	PerNodeTimeout   time.Duration
	MaxConcurrency   int
	BackoffOnAllFail time.Duration
	TopNCacheSize    int
	Disabled         bool
}

// TopRuleEntry is one row in the pre-computed top-N slice produced at refresh
// time. We keep a value copy of Stats so handler code can return references
// without worrying about the cache mutating the same struct on the next
// refresh.
type TopRuleEntry struct {
	RuleID  string
	DropPPS float64
	Stats   AggregatedRuleStats
}

// cacheState is the immutable per-refresh snapshot. The cache holds a
// pointer to one of these and atomically swaps the pointer at the end of
// every refresh. Readers grab the pointer under RLock and then operate on
// the (now read-only) state without holding the lock for any non-trivial
// work.
type cacheState struct {
	aggregated map[string]*AggregatedRuleStats
	topRules   []TopRuleEntry

	// status is the BASE outcome of the most recent refresh — disabled,
	// no_nodes, initializing, waiting_for_health, failed_no_snapshot,
	// failed, partial, ok.
	//
	// stale and partial_stale are NEVER stored here; they are derived in
	// Meta() based on now() vs lastSnapshotAt. cache_health surfaces this
	// raw value as last_refresh_status for diagnosing stuck tickers.
	status CacheStatus

	lastAttempt       time.Time
	lastSnapshotAt    time.Time // updated whenever any node succeeds (drives stale + freshness)
	lastFullSuccessAt time.Time // updated only when ALL configured nodes succeed (diagnostic only)

	configuredNodes     int
	attemptedNodes      int
	succeededNodes      int
	failedNodes         int
	skippedOfflineNodes int
	skippedUnknownNodes int
	skippedSyncingNodes int
	offlineNodeNames    []string
	unknownNodeNames    []string
	syncingNodeNames    []string

	// nodeErrors holds attempted Online failures only — no skipped-node
	// placeholders. The contract is enforced upstream in
	// GetAggregatedRuleStatsDetailed and downstream in CacheMeta.NodeErrors.
	nodeErrors map[string]string

	consecutiveAllFailRounds int
	lastRefreshDuration      time.Duration

	// lastSnapshotBaseStatus is the base outcome (ok / partial) at the
	// moment this snapshot was produced. It's how the handler decides
	// whether a zero-value stats entry in `aggregated` is authoritative
	// ("definitely no hits across all nodes when we sampled") or just a
	// lower bound ("succeeded nodes had no hits, but failed/skipped
	// nodes may have").
	//
	// Critically, this field is what the rule-stats decision uses, NOT
	// the current derived status. `stale` is just `ok` past the freshness
	// threshold — its zero values were authoritative when captured and
	// still are; `failed` may be sitting on either an ok or a partial
	// last snapshot, so we have to remember which.
	//
	// Empty CacheStatus means "no snapshot has ever been produced yet"
	// (initial state, waiting_for_health, failed_no_snapshot).
	lastSnapshotBaseStatus CacheStatus
}

// CacheMeta is the public read-side view of the cache state, returned by
// Meta() and bundled into Snapshot(). Status / FreshnessMs are derived at
// each call from clock.Now() so a stuck ticker eventually surfaces as
// stale or partial_stale even without a fresh refresh.
type CacheMeta struct {
	Status              CacheStatus
	LastRefreshStatus   CacheStatus
	FreshnessMs         *int64
	LastAttemptAt       time.Time
	LastSnapshotAt      time.Time
	LastFullSuccessAt   time.Time
	ConfiguredNodes     int
	AttemptedNodes      int
	SucceededNodes      int
	FailedNodes         int
	SkippedOfflineNodes int
	SkippedUnknownNodes int
	SkippedSyncingNodes int
	OfflineNodeNames    []string
	UnknownNodeNames    []string
	SyncingNodeNames    []string
	NodeErrors          map[string]string
	LastRefreshDuration time.Duration
	ConsecutiveAllFail  int
	RuleCount           int
	TopNCacheSize       int
	TopRulesCached      int

	// LastSnapshotBaseStatus is the base outcome (`ok` or `partial`) at
	// the moment the currently-displayed snapshot was produced. Empty
	// when no snapshot exists yet.
	//
	// This is the field the per-rule stats handler uses to decide
	// whether a 0/0/0 entry is authoritative. See resolveRuleStats in
	// internal/api for the decision tree.
	LastSnapshotBaseStatus CacheStatus
}

// StatsSnapshot is the legacy full-stats deep-copy view used by the
// listAll-from-cache code path. Paginated handlers use LookupMany instead so
// they don't pay the O(total rules) copy cost on every page load.
type StatsSnapshot struct {
	Stats map[string]AggregatedRuleStats
}

// statsSource is the minimal cache→detailed-fetch contract. Production wires
// *NodeService here; tests inject mocks that hand-build AggregatedStatsResult
// values without spinning real httptest servers.
type statsSource interface {
	GetAggregatedRuleStatsDetailed(ctx context.Context, cfg AggregatedFetchConfig) AggregatedStatsResult
}

// StatsCache is the long-lived in-memory aggregated stats cache. One instance
// is created at controller startup, ticks in the background, and is shared
// between all HTTP handlers.
type StatsCache struct {
	mu     sync.RWMutex
	state  *cacheState
	source statsSource
	clock  Clock
	cfg    StatsCacheConfig

	stopCh chan struct{}
	doneCh chan struct{}
	once   sync.Once

	// started flips to true the moment Start() begins running its sync.Once.
	// Used by Stop() to safely no-op when called before Start, e.g. when
	// constructor-level error handling routes through a defer-cleanup before
	// the cache had a chance to launch (round-9 P3-3). Without this guard
	// the unconditional <-c.doneCh in Stop would block forever, since
	// doneCh is only closed by runLoop or the disabled branch of Start.
	started atomic.Bool
}

// NewStatsCache constructs a fresh cache. Start(ctx) must be called for the
// background refresh loop to begin.
func NewStatsCache(source statsSource, clock Clock, cfg StatsCacheConfig) *StatsCache {
	if clock == nil {
		clock = RealClock{}
	}
	initial := &cacheState{
		aggregated: map[string]*AggregatedRuleStats{},
		nodeErrors: map[string]string{},
	}
	if cfg.Disabled {
		initial.status = CacheStatusDisabled
	} else {
		initial.status = CacheStatusInitializing
	}
	return &StatsCache{
		state:  initial,
		source: source,
		clock:  clock,
		cfg:    cfg,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Start launches the refresh loop. Safe to call only once; subsequent calls
// are no-ops. When cfg.Disabled is true Start returns immediately and
// Meta() perpetually reports status=disabled.
//
// `started` flips to true even in the disabled branch because doneCh is
// closed there too — Stop() needs to know it can safely wait on doneCh.
func (c *StatsCache) Start(ctx context.Context) {
	c.once.Do(func() {
		c.started.Store(true)
		if c.cfg.Disabled {
			close(c.doneCh)
			return
		}
		go c.runLoop(ctx)
	})
}

// Stop signals the refresh loop to exit and waits for it to finish.
// Idempotent: a second Stop after the loop has already exited returns
// immediately. The doneCh wait keeps tests from racing on goroutine cleanup.
//
// Stop-before-Start is a no-op (round-9 P3-3): if a constructor-level
// failure routes the caller through a defer-cleanup before Start was ever
// reached, blocking on doneCh would hang forever because nothing closed
// it. Returning silently here matches the standard "drain it but don't
// crash" cleanup pattern.
func (c *StatsCache) Stop() {
	if !c.started.Load() {
		return
	}
	select {
	case <-c.stopCh:
		// already stopped
	default:
		close(c.stopCh)
	}
	<-c.doneCh
}

func (c *StatsCache) runLoop(ctx context.Context) {
	defer close(c.doneCh)

	// Run an immediate refresh on startup so the first few requests don't
	// uniformly see status=initializing for one whole interval.
	c.refresh(ctx)

	ticker := c.clock.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		// Backoff: when the previous round failed across every node, delay
		// the next refresh by BackoffOnAllFail to avoid hammering a node
		// that's already in distress. We re-arm a fresh wait each iteration
		// so the backoff always reflects the most recent state.
		c.mu.RLock()
		consecutiveFail := c.state.consecutiveAllFailRounds
		c.mu.RUnlock()
		if consecutiveFail > 0 {
			select {
			case <-time.After(c.cfg.BackoffOnAllFail):
			case <-c.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}

		select {
		case <-ticker.C():
			c.refresh(ctx)
		case <-c.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// refresh executes one fan-out round and atomically swaps the cache state.
// It NEVER stores a derived status (stale / partial_stale) — those live in
// Meta() only.
func (c *StatsCache) refresh(ctx context.Context) {
	now := c.clock.Now()
	res := c.source.GetAggregatedRuleStatsDetailed(ctx, AggregatedFetchConfig{
		PerNodeTimeout: c.cfg.PerNodeTimeout,
		MaxConcurrency: c.cfg.MaxConcurrency,
	})

	c.mu.Lock()
	prev := c.state

	// Compute next state. Start from the new fan-out result and overlay
	// derived/diagnostic fields. lastSnapshotAt advances only when at least
	// one node succeeded — this is what Meta() bases its stale derivation
	// on. lastFullSuccessAt is the strict "every configured node was
	// successful" timestamp; it never participates in status decisions but
	// is exposed in cache_health for ops.
	next := &cacheState{
		aggregated: res.Stats,
		// topRules computed below
		lastAttempt:              now,
		lastSnapshotAt:           prev.lastSnapshotAt,
		lastFullSuccessAt:        prev.lastFullSuccessAt,
		configuredNodes:          res.ConfiguredNodes,
		attemptedNodes:           res.AttemptedNodes,
		succeededNodes:           res.SucceededNodes,
		failedNodes:              res.FailedNodes,
		skippedOfflineNodes:      res.SkippedOfflineNodes,
		skippedUnknownNodes:      res.SkippedUnknownNodes,
		skippedSyncingNodes:      res.SkippedSyncingNodes,
		offlineNodeNames:         res.OfflineNodeNames,
		unknownNodeNames:         res.UnknownNodeNames,
		syncingNodeNames:         res.SyncingNodeNames,
		nodeErrors:               errorMapToString(res.NodeErrors),
		consecutiveAllFailRounds: prev.consecutiveAllFailRounds,
		lastRefreshDuration:      res.Duration,
		// Carry forward the snapshot's authority tag — only updated when a
		// new snapshot replaces the existing one (see below).
		lastSnapshotBaseStatus: prev.lastSnapshotBaseStatus,
	}

	// Has any node succeeded this round? If yes, we have a fresh
	// displayable snapshot; advance lastSnapshotAt and re-tag the snapshot
	// with whether THIS round was full success or partial.
	if res.SucceededNodes > 0 {
		next.lastSnapshotAt = now
		// Snapshot base outcome: full success means every configured node
		// contributed (no failures, no skips). Anything else means the
		// new snapshot is a lower bound, even if we got most of the
		// nodes' data — a future read in `failed` state needs to know
		// not to trust 0/0/0 entries from this snapshot as authoritative.
		fullSuccess := res.FailedNodes == 0 &&
			res.SkippedOfflineNodes == 0 &&
			res.SkippedUnknownNodes == 0 &&
			res.SkippedSyncingNodes == 0 &&
			res.SucceededNodes == res.ConfiguredNodes
		if fullSuccess {
			next.lastSnapshotBaseStatus = CacheStatusOK
		} else {
			next.lastSnapshotBaseStatus = CacheStatusPartial
		}
	} else {
		// No new data — keep the previous aggregated stats so partial /
		// failed responses can still surface "what we last knew" rather
		// than blanking out. lastSnapshotBaseStatus stays the same too,
		// since we're still serving the same snapshot.
		next.aggregated = prev.aggregated
	}

	// Full-success timestamp is the strict variant: every node attempted
	// AND every attempted node succeeded AND no skips. This is consulted
	// only by cache_health, never by status decisions.
	allConfiguredSucceeded := res.ConfiguredNodes > 0 &&
		res.SucceededNodes == res.ConfiguredNodes &&
		res.FailedNodes == 0 &&
		res.SkippedOfflineNodes == 0 &&
		res.SkippedUnknownNodes == 0 &&
		res.SkippedSyncingNodes == 0
	if allConfiguredSucceeded {
		next.lastFullSuccessAt = now
	}

	// Backoff bookkeeping: count consecutive rounds where every configured
	// node either failed or was skipped (no useful data produced).
	allFailed := res.ConfiguredNodes > 0 && res.SucceededNodes == 0
	if allFailed {
		next.consecutiveAllFailRounds = prev.consecutiveAllFailRounds + 1
	} else {
		next.consecutiveAllFailRounds = 0
	}

	next.status = deriveBaseStatus(c.cfg, next)

	// Pre-compute top-N for the /rules/top fast path. Using the full
	// aggregated map (which may be the previous snapshot when no node
	// succeeded), we sort once and slice — handlers don't have to revisit
	// the whole map on every request.
	next.topRules = computeTopRules(next.aggregated, c.cfg.TopNCacheSize)

	c.state = next
	c.mu.Unlock()

	if allFailed {
		slog.Warn("stats cache refresh: all nodes failed",
			"configured", res.ConfiguredNodes,
			"failed", res.FailedNodes,
			"skipped_offline", res.SkippedOfflineNodes,
			"skipped_unknown", res.SkippedUnknownNodes,
			"skipped_syncing", res.SkippedSyncingNodes,
			"consecutive_all_fail", next.consecutiveAllFailRounds,
		)
	}
}

// deriveBaseStatus implements the refresh-time decision tree. It returns
// only base outcomes — stale and partial_stale belong to deriveStatus.
//
// The order is intentional:
//  1. disabled / no_nodes are configuration-driven, decided up front.
//  2. initializing fires only when we haven't completed a refresh yet
//     (lastAttempt zero).
//  3. waiting_for_health is for the "everything still says Unknown/Syncing
//     and we have no snapshot to fall back on" case — distinguished from
//     failed because the nodes might come up shortly.
//  4. failed_no_snapshot vs failed: same "everything missed" condition,
//     split by whether we ever produced a usable snapshot.
//  5. partial fires whenever ANY configured node didn't successfully
//     contribute (whether failed, offline, unknown, or syncing). This is
//     stricter than just "FailedNodes > 0" because lower-bound stats from
//     a subset must be flagged so consumers don't treat 0 as "definitely
//     no hits".
//  6. Default is ok — strictest case where every configured node succeeded.
func deriveBaseStatus(cfg StatsCacheConfig, s *cacheState) CacheStatus {
	if cfg.Disabled {
		return CacheStatusDisabled
	}
	if s.configuredNodes == 0 {
		return CacheStatusNoNodes
	}
	if s.lastAttempt.IsZero() {
		return CacheStatusInitializing
	}

	warming := s.skippedUnknownNodes + s.skippedSyncingNodes
	absent := s.failedNodes + s.skippedOfflineNodes
	unsuccessful := absent + warming

	if warming == s.configuredNodes && s.lastSnapshotAt.IsZero() {
		return CacheStatusWaitingForHealth
	}
	if unsuccessful == s.configuredNodes {
		if s.lastSnapshotAt.IsZero() {
			return CacheStatusFailedNoSnapshot
		}
		return CacheStatusFailed
	}
	if unsuccessful > 0 {
		return CacheStatusPartial
	}
	return CacheStatusOK
}

// deriveStatus is the read-side complement to deriveBaseStatus. Callers (Meta
// and Snapshot) hand it the most recent base outcome plus the current time
// and stale threshold; partial / ok promote to partial_stale / stale once
// enough time has elapsed without a fresh snapshot.
//
// All other base statuses pass through unchanged — disabled stays disabled,
// failed stays failed even if it's been failing for hours, etc.
func deriveStatus(now time.Time, base CacheStatus, lastSnapshotAt time.Time, staleThreshold time.Duration) CacheStatus {
	switch base {
	case CacheStatusDisabled, CacheStatusNoNodes,
		CacheStatusInitializing, CacheStatusWaitingForHealth,
		CacheStatusFailedNoSnapshot, CacheStatusFailed:
		return base
	}
	isStale := !lastSnapshotAt.IsZero() && now.Sub(lastSnapshotAt) > staleThreshold
	switch base {
	case CacheStatusOK:
		if isStale {
			return CacheStatusStale
		}
	case CacheStatusPartial:
		if isStale {
			return CacheStatusPartialStale
		}
	}
	return base
}

// deriveFreshness returns ms since the last displayable snapshot, or nil if
// freshness is meaningless for the current status (no snapshot yet, disabled,
// etc.). nil pointers serialize as JSON null, matching the API contract.
func deriveFreshness(now time.Time, lastSnapshotAt time.Time, status CacheStatus) *int64 {
	switch status {
	case CacheStatusInitializing, CacheStatusWaitingForHealth,
		CacheStatusNoNodes, CacheStatusFailedNoSnapshot, CacheStatusDisabled:
		return nil
	}
	if lastSnapshotAt.IsZero() {
		return nil
	}
	ms := now.Sub(lastSnapshotAt).Milliseconds()
	return &ms
}

// buildMeta is the single source of truth for translating an internal
// cacheState into the public CacheMeta shape. Both Meta() and Snapshot()
// route through it so a cache state can never disagree with itself across
// the two read APIs.
func buildMeta(now time.Time, s *cacheState, staleThreshold time.Duration) CacheMeta {
	derived := deriveStatus(now, s.status, s.lastSnapshotAt, staleThreshold)
	return CacheMeta{
		Status:                 derived,
		LastRefreshStatus:      s.status,
		FreshnessMs:            deriveFreshness(now, s.lastSnapshotAt, derived),
		LastAttemptAt:          s.lastAttempt,
		LastSnapshotAt:         s.lastSnapshotAt,
		LastFullSuccessAt:      s.lastFullSuccessAt,
		ConfiguredNodes:        s.configuredNodes,
		AttemptedNodes:         s.attemptedNodes,
		SucceededNodes:         s.succeededNodes,
		FailedNodes:            s.failedNodes,
		SkippedOfflineNodes:    s.skippedOfflineNodes,
		SkippedUnknownNodes:    s.skippedUnknownNodes,
		SkippedSyncingNodes:    s.skippedSyncingNodes,
		OfflineNodeNames:       cloneStringSlice(s.offlineNodeNames),
		UnknownNodeNames:       cloneStringSlice(s.unknownNodeNames),
		SyncingNodeNames:       cloneStringSlice(s.syncingNodeNames),
		NodeErrors:             cloneStringMap(s.nodeErrors),
		LastRefreshDuration:    s.lastRefreshDuration,
		ConsecutiveAllFail:     s.consecutiveAllFailRounds,
		RuleCount:              len(s.aggregated),
		TopNCacheSize:          0, // filled in by callers that have access to cfg
		TopRulesCached:         len(s.topRules),
		LastSnapshotBaseStatus: s.lastSnapshotBaseStatus,
	}
}

// Meta returns just the metadata view of the cache. Callers that don't need
// stats (e.g. headers-only health check) avoid the per-rule deep copies.
func (c *StatsCache) Meta() CacheMeta {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	now := c.clock.Now()
	meta := buildMeta(now, state, c.cfg.StaleThreshold)
	meta.TopNCacheSize = c.cfg.TopNCacheSize
	return meta
}

// LookupMany returns deep-copied stats for the requested rule IDs only.
//
// Designed for paginated handlers: caller already knows which rule IDs are
// on the current page from the database query, so we copy O(len(ids)) stats
// instead of the entire aggregated map. Returns a freshly-allocated map;
// callers can mutate freely without affecting cache state.
//
// Missing IDs simply don't appear in the returned map. The caller's contract
// builder uses that absence to decide whether to omit the stats key, synth
// 0/0/0, or fall back to last snapshot, depending on the current cache status.
func (c *StatsCache) LookupMany(ids []string) map[string]AggregatedRuleStats {
	out := make(map[string]AggregatedRuleStats, len(ids))
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, id := range ids {
		if v, ok := c.state.aggregated[id]; ok && v != nil {
			out[id] = *v // value copy; *v is owned by the (now read-only) state
		}
	}
	return out
}

// TopByDropPPS returns up to `limit` pre-sorted top-by-drop_pps entries.
//
// Sorting happens at refresh time, so this is O(min(limit, TopNCacheSize)).
// Each TopRuleEntry already holds a value-copy of its Stats, so the slice we
// return cannot be mutated to corrupt cache state.
//
// If `limit` exceeds TopNCacheSize the result is silently capped at the
// pre-computed slice length — Validate() rejects configs where this happens
// against the actual API max (see config.StatsCacheRawConfig.Validate).
func (c *StatsCache) TopByDropPPS(limit int) []TopRuleEntry {
	if limit <= 0 {
		return nil
	}
	c.mu.RLock()
	src := c.state.topRules
	c.mu.RUnlock()
	if limit > len(src) {
		limit = len(src)
	}
	out := make([]TopRuleEntry, limit)
	copy(out, src[:limit])
	return out
}

// Snapshot returns a full deep copy of stats plus the meta header. Used by
// the listAll fallback (no pagination params) where the handler genuinely
// needs every rule's stats; paginated paths must use LookupMany instead.
func (c *StatsCache) Snapshot() (StatsSnapshot, CacheMeta) {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	now := c.clock.Now()

	stats := make(map[string]AggregatedRuleStats, len(state.aggregated))
	for k, v := range state.aggregated {
		if v != nil {
			stats[k] = *v
		}
	}
	meta := buildMeta(now, state, c.cfg.StaleThreshold)
	meta.TopNCacheSize = c.cfg.TopNCacheSize
	return StatsSnapshot{Stats: stats}, meta
}

// computeTopRules sorts the given map by (DropPPS desc, DropCount desc,
// RuleID asc) and returns the top-N slice. The third tier is the
// determinism tie-breaker — without it Go's map iteration would randomize
// the order of equal-PPS rules across refreshes, making
// TestCache_TopByDropPPSStableSort flaky.
func computeTopRules(stats map[string]*AggregatedRuleStats, limit int) []TopRuleEntry {
	if limit <= 0 || len(stats) == 0 {
		return nil
	}
	all := make([]TopRuleEntry, 0, len(stats))
	for id, s := range stats {
		if s == nil {
			continue
		}
		all = append(all, TopRuleEntry{
			RuleID:  id,
			DropPPS: s.DropPPS,
			Stats:   *s,
		})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].DropPPS != all[j].DropPPS {
			return all[i].DropPPS > all[j].DropPPS
		}
		if all[i].Stats.DropCount != all[j].Stats.DropCount {
			return all[i].Stats.DropCount > all[j].Stats.DropCount
		}
		return all[i].RuleID < all[j].RuleID
	})
	if len(all) > limit {
		all = all[:limit]
	}
	return all
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func errorMapToString(in map[string]error) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = formatNodeError(v)
	}
	return out
}
