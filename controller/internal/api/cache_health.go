package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

// CacheHealthHandler exposes the in-process stats cache state at
// /api/v1/stats/cache_health for ops debugging.
//
// Both `status` (current derived state, may be partial_stale even though no
// new refresh happened) and `last_refresh_status` (the raw base outcome at
// last refresh time) are returned. When the two diverge, the cause is
// almost always a stuck refresh ticker — having both fields makes that
// diagnosable from a single GET without going to logs.
//
// Authentication: rides on the existing /api/v1 auth middleware. There is
// no admin/RBAC layer in the controller; this is "any authenticated v1
// caller". If RBAC is added later this handler will need to opt-in.
type CacheHealthHandler struct {
	cache *service.StatsCache
}

// NewCacheHealthHandler — cache may be nil for setups that don't wire the
// stats cache. Setting nil makes the endpoint return 503 to make it
// obvious the feature isn't actually enabled, rather than silently
// returning bogus zero metrics.
func NewCacheHealthHandler(cache *service.StatsCache) *CacheHealthHandler {
	return &CacheHealthHandler{cache: cache}
}

// Get serves the cache_health JSON payload.
func (h *CacheHealthHandler) Get(c *gin.Context) {
	if h.cache == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_configured",
			"error":  "stats cache not wired",
		})
		return
	}

	meta := h.cache.Meta()

	// Translate timestamps to unix-ms — easier to consume from shell
	// (jq + epoch math) than RFC3339 timestamps. Zero times serialize as
	// 0 to keep the JSON shape stable; consumers should ignore 0 values
	// rather than trying to parse them.
	c.JSON(http.StatusOK, gin.H{
		"status":                    string(meta.Status),
		"last_refresh_status":       string(meta.LastRefreshStatus),
		"last_attempt_unix_ms":      unixMs(meta.LastAttemptAt),
		"last_snapshot_unix_ms":     unixMs(meta.LastSnapshotAt),
		"last_full_success_unix_ms": unixMs(meta.LastFullSuccessAt),
		"freshness_ms":              meta.FreshnessMs,
		"configured_nodes":          meta.ConfiguredNodes,
		"attempted_nodes":           meta.AttemptedNodes,
		"succeeded_nodes":           meta.SucceededNodes,
		"failed_nodes":              meta.FailedNodes,
		"skipped_offline_nodes":     meta.SkippedOfflineNodes,
		"skipped_unknown_nodes":     meta.SkippedUnknownNodes,
		"skipped_syncing_nodes":     meta.SkippedSyncingNodes,
		"offline_node_names":        stringsOrEmpty(meta.OfflineNodeNames),
		"unknown_node_names":        stringsOrEmpty(meta.UnknownNodeNames),
		"syncing_node_names":        stringsOrEmpty(meta.SyncingNodeNames),
		"node_errors":               meta.NodeErrors,
		"rule_count":                meta.RuleCount,
		"top_n_cache_size":          meta.TopNCacheSize,
		"top_rules_cached":          meta.TopRulesCached,
		"last_refresh_duration_ms":  meta.LastRefreshDuration.Milliseconds(),
		"consecutive_all_fail":      meta.ConsecutiveAllFail,
	})
}

// unixMs converts a time.Time to unix milliseconds, returning 0 for the
// zero value. The 0 sentinel is used because (a) JSON encoding of a zero
// time.Time would emit "0001-01-01T00:00:00Z" which is awkward to detect
// downstream and (b) consumers can simply skip non-positive timestamps.
func unixMs(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}
