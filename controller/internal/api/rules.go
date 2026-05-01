package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// MaxBatchSize caps the number of rules/ids accepted in a single batch
// request to prevent memory pressure and sync-fanout amplification.
const MaxBatchSize = 1000

// RulesHandler handles rule API requests.
type RulesHandler struct {
	svc        *service.RuleService
	nodeSvc    *service.NodeService
	statsCache *service.StatsCache // v2.6.3 — nil-safe; falls back to legacy fan-out when nil
}

// NewRulesHandler creates a new RulesHandler.
//
// statsCache may be nil during tests / setups that don't wire the cache; in
// that case all stats-aware paths degrade to the legacy real-time fan-out
// behavior so existing tests continue to pass without changes.
func NewRulesHandler(svc *service.RuleService, nodeSvc *service.NodeService, statsCache *service.StatsCache) *RulesHandler {
	return &RulesHandler{svc: svc, nodeSvc: nodeSvc, statsCache: statsCache}
}

// RuleWithStats is a rule augmented with aggregated cluster statistics.
type RuleWithStats struct {
	*model.Rule
	Stats *service.AggregatedRuleStats `json:"stats,omitempty"`
}

// statsMetaFields embeds the 6 v2.6.3 contract fields into a response builder.
//
// Keeping the field shape consistent across List / TopRules / listAll is
// important: front-end code reads stats_status as the only authoritative
// indicator and then dispatches to per-rule .stats. Diverging shapes here
// would force the front-end to special-case each endpoint.
//
// stats_freshness_ms intentionally returns nil (→ JSON null) when the cache
// is in a "no displayable snapshot" state (initializing / waiting_for_health
// / no_nodes / failed_no_snapshot / disabled).
func statsMetaFields(meta service.CacheMeta) gin.H {
	out := gin.H{
		"stats_status":        string(meta.Status),
		"stats_freshness_ms":  meta.FreshnessMs,
		"stats_node_failures": meta.NodeErrors,
		"stats_offline_nodes": stringsOrEmpty(meta.OfflineNodeNames),
		"stats_unknown_nodes": stringsOrEmpty(meta.UnknownNodeNames),
		"stats_syncing_nodes": stringsOrEmpty(meta.SyncingNodeNames),
	}
	return out
}

// stringsOrEmpty normalizes a possibly-nil slice to a non-nil empty slice so
// JSON encodes [] instead of null. Front-end array iteration assumes [].
func stringsOrEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// statsKeyOmittedForStatus mirrors the D.4 per-rule stats decision table:
// for these statuses we don't synth 0/0/0 and we don't return last-snapshot
// stats either — the field is omitted so front-end shows "loading" /
// "disabled" / "获取失败" rather than a misleading number.
func statsKeyOmittedForStatus(status service.CacheStatus) bool {
	switch status {
	case service.CacheStatusInitializing,
		service.CacheStatusWaitingForHealth,
		service.CacheStatusNoNodes,
		service.CacheStatusFailedNoSnapshot,
		service.CacheStatusDisabled:
		return true
	}
	return false
}

// resolveRuleStats decides what to put on a single rule's `stats` field
// given the current cache status, the snapshot's *base outcome*, and what
// the cache had for this rule.
//
// Returns nil to mean "omit the stats key entirely". The caller assigns
// the returned pointer to RuleWithStats.Stats; an omitempty json tag on
// Stats turns nil into a missing field on the wire.
//
// Decision tree — pinned here because three call sites have to agree or
// the D.4 contract invariants drift:
//
//   - status == ok: 0/0/0 is authoritative ("definitely no hits across
//     all configured nodes RIGHT NOW"). Cache hit → return it; cache
//     miss → synthesize zero. Stats key always present.
//
//   - snapshotBase == ok (whether status is `ok`, `stale`, or `failed`
//     after an ok snapshot): the snapshot itself was full-cluster
//     success at capture time. Zero values were authoritative THEN;
//     status=stale just means "that snapshot is now old", and
//     status=failed means "we can't fetch new data". The 0 is still
//     a fact about the snapshot moment. Return cached, including 0/0/0.
//
//   - snapshotBase == partial: cache values are a LOWER BOUND (some
//     nodes contributed, others didn't). 0/0/0 might mean the
//     succeeded nodes saw nothing, while a failed/skipped node had
//     real hits. Filter zero entries — they read as "definite zero"
//     to UI even with a partial badge. Non-zero entries pass through
//     as lower bounds.
//
//   - snapshotBase == "" (no snapshot ever produced — initializing,
//     waiting_for_health, failed_no_snapshot, etc.): caller already
//     short-circuited via statsKeyOmittedForStatus earlier; this
//     function isn't called for those statuses. We treat it the same
//     as partial here for safety.
//
// status==ok is checked first because it implies snapshotBase==ok by
// construction; checking it explicitly lets the OK path synth zero on
// cache miss without falling into the partial branch.
func resolveRuleStats(
	status service.CacheStatus,
	snapshotBase service.CacheStatus,
	cached service.AggregatedRuleStats,
	hadCacheEntry bool,
) *service.AggregatedRuleStats {
	if status == service.CacheStatusOK {
		// Cache hit OR miss — synthesize zero is correct under ok.
		out := cached
		return &out
	}

	// Past here we're in stale / partial / partial_stale / failed.
	// Without a cache entry there's nothing to surface, regardless of base.
	if !hadCacheEntry {
		return nil
	}

	// Authoritative-zero snapshots: stale/failed-after-ok still carry the
	// fact that the captured moment had no hits, just outdated.
	if snapshotBase == service.CacheStatusOK {
		out := cached
		return &out
	}

	// Lower-bound snapshots: filter zero entries that would read as
	// "definite zero" with only a partial badge to qualify them.
	if cached.MatchCount == 0 && cached.DropCount == 0 && cached.DropPPS == 0 {
		return nil
	}
	out := cached
	return &out
}

// hasPaginationParams checks if any pagination-related query param is present.
// Uses GetQuery to distinguish "not present" from "present but empty".
func hasPaginationParams(c *gin.Context) bool {
	for _, key := range []string{"page", "limit", "search", "sort", "order", "enabled", "action"} {
		if _, exists := c.GetQuery(key); exists {
			return true
		}
	}
	return false
}

// parseAndValidatePaginationParams parses and validates all pagination parameters.
// Returns 400-style error if any parameter is invalid.
func parseAndValidatePaginationParams(c *gin.Context) (repository.PaginationParams, error) {
	params := repository.PaginationParams{
		Page:  1,
		Limit: 50,
		Sort:  "created_at",
		Order: "desc",
	}

	if v, exists := c.GetQuery("page"); exists {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return params, fmt.Errorf("invalid page: must be positive integer")
		}
		params.Page = n
	}
	if v, exists := c.GetQuery("limit"); exists {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return params, fmt.Errorf("invalid limit: must be 1-1000")
		}
		params.Limit = n
	}
	if v, exists := c.GetQuery("sort"); exists {
		if v != "created_at" && v != "updated_at" {
			return params, fmt.Errorf("invalid sort: allowed values are created_at, updated_at")
		}
		params.Sort = v
	}
	if v, exists := c.GetQuery("order"); exists {
		if v != "asc" && v != "desc" {
			return params, fmt.Errorf("invalid order: allowed values are asc, desc")
		}
		params.Order = v
	}
	if v, exists := c.GetQuery("search"); exists {
		// search accepts any string; empty string means no filter
		params.Search = v
	}
	if v, exists := c.GetQuery("enabled"); exists {
		if v != "true" && v != "false" {
			return params, fmt.Errorf("invalid enabled: allowed values are true, false")
		}
		b := v == "true"
		params.Enabled = &b
	}
	if v, exists := c.GetQuery("action"); exists {
		if v != "drop" && v != "rate_limit" {
			return params, fmt.Errorf("invalid action: allowed values are drop, rate_limit")
		}
		params.Action = v
	}

	return params, nil
}

// List lists rules in paginated or full mode.
//
// v2.6.3: paginated mode now returns per-rule stats (instead of skipping
// aggregation as AUD-001 used to). Stats come from the in-process StatsCache,
// so request latency stays bounded — no Node fan-out happens on this code
// path. Six top-level stats_* fields convey freshness and per-status node
// breakdowns; see statsMetaFields.
//
// When the cache isn't wired (statsCache == nil) the response degrades to the
// pre-v2.6.3 shape with no stats and no meta, preserving compatibility with
// older test setups.
func (h *RulesHandler) List(c *gin.Context) {
	if !hasPaginationParams(c) {
		h.listAll(c)
		return
	}

	params, err := parseAndValidatePaginationParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rules, pagination, err := h.svc.ListPaginated(params)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := gin.H{
		"rules":      rules,
		"count":      pagination.Total,
		"pagination": pagination,
	}

	if h.statsCache == nil {
		c.JSON(http.StatusOK, resp)
		return
	}

	meta := h.statsCache.Meta()
	for k, v := range statsMetaFields(meta) {
		resp[k] = v
	}

	if !statsKeyOmittedForStatus(meta.Status) {
		ids := make([]string, 0, len(rules))
		for _, r := range rules {
			ids = append(ids, r.ID)
		}
		statsByID := h.statsCache.LookupMany(ids)
		ruleResults := make([]RuleWithStats, 0, len(rules))
		for _, rule := range rules {
			rws := RuleWithStats{Rule: rule}
			cached, hit := statsByID[rule.ID]
			rws.Stats = resolveRuleStats(meta.Status, meta.LastSnapshotBaseStatus, cached, hit)
			ruleResults = append(ruleResults, rws)
		}
		resp["rules"] = ruleResults
	}

	c.JSON(http.StatusOK, resp)
}

// listAll returns all rules (backward compatible with old API).
//
// Behavior change in v2.6.3 (must be documented in API.md):
//   - When stats_cache is enabled, listAll reads from the cache — same
//     semantics as paginated, just without pagination metadata. Responses
//     are at most RefreshInterval stale.
//   - When stats_cache.disabled=true, listAll falls back to the legacy
//     synchronous fan-out so diagnostic scripts can opt into real-time
//     numbers via a config-level switch.
//
// In both cases the old response shape is preserved (no stats_status when
// the cache is disabled or unwired), so older callers don't see surprise
// fields.
func (h *RulesHandler) listAll(c *gin.Context) {
	rules, err := h.svc.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// No cache wired → legacy real-time fan-out, no meta.
	if h.statsCache == nil {
		h.listAllLegacy(c, rules)
		return
	}

	meta := h.statsCache.Meta()

	// Disabled-mode escape hatch: keep the old fan-out behavior so
	// operators who flip stats_cache.disabled=true at runtime still see
	// real-time stats on this endpoint.
	if meta.Status == service.CacheStatusDisabled {
		h.listAllLegacy(c, rules)
		return
	}

	resp := gin.H{
		"count": len(rules),
	}
	for k, v := range statsMetaFields(meta) {
		resp[k] = v
	}

	if statsKeyOmittedForStatus(meta.Status) {
		// No usable snapshot — return rules without the stats key, but
		// keep the meta so the front-end can render the loading/error
		// state instead of "no data" / blank columns.
		resp["rules"] = rules
	} else {
		ids := make([]string, 0, len(rules))
		for _, r := range rules {
			ids = append(ids, r.ID)
		}
		statsByID := h.statsCache.LookupMany(ids)
		ruleResults := make([]RuleWithStats, 0, len(rules))
		for _, rule := range rules {
			rws := RuleWithStats{Rule: rule}
			cached, hit := statsByID[rule.ID]
			rws.Stats = resolveRuleStats(meta.Status, meta.LastSnapshotBaseStatus, cached, hit)
			ruleResults = append(ruleResults, rws)
		}
		resp["rules"] = ruleResults
	}

	c.JSON(http.StatusOK, resp)
}

// listAllLegacy preserves the pre-v2.6.3 listAll behavior — synchronous Node
// fan-out, no stats meta. Reused by both the "no cache wired" path (used by
// tests) and the runtime escape hatch when stats_cache.disabled=true.
func (h *RulesHandler) listAllLegacy(c *gin.Context, rules []*model.Rule) {
	aggregatedStats, _ := h.nodeSvc.GetAggregatedRuleStats()
	result := make([]RuleWithStats, 0, len(rules))
	for _, rule := range rules {
		rws := RuleWithStats{Rule: rule}
		if stats, ok := aggregatedStats[rule.ID]; ok {
			rws.Stats = stats
		}
		result = append(result, rws)
	}
	c.JSON(http.StatusOK, gin.H{
		"rules": result,
		"count": len(result),
	})
}

// Get retrieves a single rule by ID.
func (h *RulesHandler) Get(c *gin.Context) {
	id := c.Param("id")
	rule, err := h.svc.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// TopRules returns top-N rules sorted by drop_pps for the Dashboard chart.
//
// v2.6.3: this endpoint reads from the StatsCache's pre-computed top slice
// (sorted at refresh time with a deterministic tie-breaker). No fan-out
// happens at request time — the chart can be polled aggressively without
// putting load on Nodes.
//
// The response now includes the standard six stats_* meta fields plus an
// always-present (possibly empty) rules array. Front-end code dispatches off
// stats_status to distinguish "no drops yet" (ok with empty rules) from
// "still loading" (initializing) from "stuck" (partial_stale / failed).
//
// When statsCache is not wired, falls back to the legacy synchronous
// aggregation path so old test harnesses continue to work.
func (h *RulesHandler) TopRules(c *gin.Context) {
	limit := 10
	if v, exists := c.GetQuery("limit"); exists {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 50 {
			limit = n
		}
	}

	if h.statsCache == nil {
		h.topRulesLegacy(c, limit)
		return
	}

	meta := h.statsCache.Meta()
	resp := gin.H{}
	for k, v := range statsMetaFields(meta) {
		resp[k] = v
	}

	if statsKeyOmittedForStatus(meta.Status) {
		// No displayable snapshot — front-end shows the appropriate empty
		// state based on stats_status, not the empty rules slice.
		resp["rules"] = []RuleWithStats{}
		c.JSON(http.StatusOK, resp)
		return
	}

	entries := h.statsCache.TopByDropPPS(limit)
	result := make([]RuleWithStats, 0, len(entries))
	for _, e := range entries {
		if e.DropPPS <= 0 {
			continue
		}
		rule, err := h.svc.Get(e.RuleID)
		if err != nil {
			continue
		}
		stats := e.Stats // value copy; safe to take address
		result = append(result, RuleWithStats{Rule: rule, Stats: &stats})
	}
	resp["rules"] = result
	c.JSON(http.StatusOK, resp)
}

// topRulesLegacy preserves the pre-v2.6.3 TopRules behavior for environments
// without a wired StatsCache. Identical to the original implementation; the
// only thing that changed is the wiring around it.
func (h *RulesHandler) topRulesLegacy(c *gin.Context, limit int) {
	aggregatedStats, _ := h.nodeSvc.GetAggregatedRuleStats()
	if len(aggregatedStats) == 0 {
		c.JSON(http.StatusOK, gin.H{"rules": []interface{}{}})
		return
	}

	type entry struct {
		ID   string
		Stat *service.AggregatedRuleStats
	}
	var entries []entry
	for id, stat := range aggregatedStats {
		if stat.DropPPS > 0 {
			entries = append(entries, entry{id, stat})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Stat.DropPPS > entries[j].Stat.DropPPS
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}

	result := make([]RuleWithStats, 0, len(entries))
	for _, e := range entries {
		rule, err := h.svc.Get(e.ID)
		if err != nil {
			continue
		}
		result = append(result, RuleWithStats{Rule: rule, Stats: e.Stat})
	}
	c.JSON(http.StatusOK, gin.H{"rules": result})
}

// syncToResponse always includes the sync result so callers can distinguish
// "DB mutation succeeded" from "data-plane sync succeeded". B-2.
func syncToResponse(resp gin.H, sr *service.SyncResult) gin.H {
	if sr != nil {
		resp["sync"] = sr
	}
	return resp
}

// Create adds a new rule.
func (h *RulesHandler) Create(c *gin.Context) {
	var req model.RuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, sr, err := h.svc.Create(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, syncToResponse(gin.H{
		"success": true,
		"rule":    rule,
	}, sr))
}

// Update modifies an existing rule.
func (h *RulesHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req model.RuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule, sr, err := h.svc.Update(id, &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"rule":    rule,
	}, sr))
}

// Delete removes a rule by ID.
func (h *RulesHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	sr, err := h.svc.Delete(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"message": "Rule deleted",
	}, sr))
}

// BatchCreate adds multiple rules in one request.
func (h *RulesHandler) BatchCreate(c *gin.Context) {
	var req struct {
		Rules []model.RuleRequest `json:"rules"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Rules) > MaxBatchSize {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("batch size %d exceeds limit %d", len(req.Rules), MaxBatchSize)})
		return
	}

	rules, added, failed, sr, err := h.svc.BatchCreate(req.Rules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, syncToResponse(gin.H{
		"success": true,
		"added":   added,
		"failed":  failed,
		"rules":   rules,
	}, sr))
}

// BatchDelete removes multiple rules by ID.
func (h *RulesHandler) BatchDelete(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.IDs) > MaxBatchSize {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("batch size %d exceeds limit %d", len(req.IDs), MaxBatchSize)})
		return
	}

	deleted, failed, sr, err := h.svc.BatchDelete(req.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, syncToResponse(gin.H{
		"success": true,
		"deleted": deleted,
		"failed":  failed,
	}, sr))
}
