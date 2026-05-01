package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// AggregatedFetchConfig drives a single refresh round of the stats cache.
//
// The cache layer constructs this from its runtime StatsCacheConfig and
// hands it to GetAggregatedRuleStatsDetailed. Keeping it out of the public
// cache API avoids leaking ticker / lifecycle types into the fetch path.
type AggregatedFetchConfig struct {
	PerNodeTimeout time.Duration // hard upper bound per node, enforced via context.WithTimeout
	MaxConcurrency int           // semaphore size for outbound fan-out
}

// NodeFetchResult is the per-node outcome of a single refresh round.
// Only used internally to assemble AggregatedStatsResult; not exported on
// the response contract because the cache layer flattens these into the
// three skipped/failed groups before responding.
type nodeFetchResult struct {
	node       model.Node
	skipKind   string // "" = attempted; otherwise "offline"|"unknown"|"syncing"|"other_skip"
	rules      []client.NodeRule
	requestErr error // only populated for attempted nodes
}

// AggregatedStatsResult is the structured outcome of a refresh fan-out.
//
// Unlike the legacy GetAggregatedRuleStats() which silently skips
// non-Online nodes and returns nil error, this surfaces the full breakdown
// so the cache state machine can compute ok / partial / partial_stale /
// failed / failed_no_snapshot correctly without guessing.
//
// Skipped nodes are split into three reasons so the response contract
// (D.4) can populate stats_offline_nodes / stats_unknown_nodes /
// stats_syncing_nodes separately. NodeErrors carries ONLY actual request
// failures from attempted Online nodes — skipped nodes are not added with
// placeholder errors; downstream code should rely on the *NodeNames
// slices to enumerate them.
type AggregatedStatsResult struct {
	Stats               map[string]*AggregatedRuleStats
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
	NodeErrors          map[string]error // attempted Online node failures only
	Duration            time.Duration
}

// GetAggregatedRuleStatsDetailed fans out per-rule stats fetches across all
// configured nodes (not just Online), bounded by MaxConcurrency, with a
// per-node timeout enforced via context.WithTimeout.
//
// Implementation notes:
//   - Uses SnapshotNodesForStats to copy node values inside the lock, so
//     concurrent HealthChecker.UpdateStatus mutations do NOT race with the
//     fan-out loop's reads of node.Status / node.Endpoint.
//   - Each Online node's HTTP request runs in its own goroutine guarded by a
//     semaphore. The per-node ctx is derived from the caller's ctx with
//     context.WithTimeout(PerNodeTimeout), so the HTTP request honors both
//     the timeout AND the parent cache shutdown.
//   - Aggregation is deterministic-ish: rule_id key collisions from multiple
//     nodes are summed (MatchCount / DropCount additive, DropPPS additive).
//     The legacy GetAggregatedRuleStats does the same.
func (s *NodeService) GetAggregatedRuleStatsDetailed(
	ctx context.Context,
	cfg AggregatedFetchConfig,
) AggregatedStatsResult {
	start := time.Now()

	nodes := s.SnapshotNodesForStats()

	result := AggregatedStatsResult{
		Stats:           make(map[string]*AggregatedRuleStats),
		ConfiguredNodes: len(nodes),
		NodeErrors:      make(map[string]error),
	}

	if len(nodes) == 0 {
		result.Duration = time.Since(start)
		return result
	}

	concurrency := cfg.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
	results := make([]nodeFetchResult, len(nodes))

	for i, n := range nodes {
		switch n.Status {
		case model.NodeStatusOnline:
			// attempted
		case model.NodeStatusOffline:
			results[i] = nodeFetchResult{node: n, skipKind: "offline"}
			continue
		case model.NodeStatusUnknown:
			results[i] = nodeFetchResult{node: n, skipKind: "unknown"}
			continue
		case model.NodeStatusSyncing:
			results[i] = nodeFetchResult{node: n, skipKind: "syncing"}
			continue
		default:
			// Defensive: treat any unknown status as a skipped node tagged unknown
			// so the caller can still surface it in stats_unknown_nodes.
			results[i] = nodeFetchResult{node: n, skipKind: "unknown"}
			continue
		}

		wg.Add(1)
		go func(i int, n model.Node) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = nodeFetchResult{node: n, requestErr: ctx.Err()}
				return
			}

			perNodeCtx, cancel := context.WithTimeout(ctx, cfg.PerNodeTimeout)
			defer cancel()

			resp, err := s.nodeClient.GetRulesWithStatsContext(perNodeCtx, n.Endpoint, n.ApiKey)
			if err != nil {
				results[i] = nodeFetchResult{node: n, requestErr: err}
				return
			}
			results[i] = nodeFetchResult{node: n, rules: resp.Rules}
		}(i, n)
	}
	wg.Wait()

	for _, r := range results {
		switch r.skipKind {
		case "offline":
			result.SkippedOfflineNodes++
			result.OfflineNodeNames = append(result.OfflineNodeNames, r.node.Name)
			continue
		case "unknown":
			result.SkippedUnknownNodes++
			result.UnknownNodeNames = append(result.UnknownNodeNames, r.node.Name)
			continue
		case "syncing":
			result.SkippedSyncingNodes++
			result.SyncingNodeNames = append(result.SyncingNodeNames, r.node.Name)
			continue
		}
		// attempted
		result.AttemptedNodes++
		if r.requestErr != nil {
			result.FailedNodes++
			result.NodeErrors[r.node.Name] = r.requestErr
			continue
		}
		result.SucceededNodes++
		for _, rule := range r.rules {
			if rule.Stats == nil {
				continue
			}
			agg, ok := result.Stats[rule.ID]
			if !ok {
				agg = &AggregatedRuleStats{}
				result.Stats[rule.ID] = agg
			}
			agg.MatchCount += rule.Stats.MatchCount
			agg.DropCount += rule.Stats.DropCount
			agg.DropPPS += rule.Stats.DropPPS
		}
	}

	result.Duration = time.Since(start)
	return result
}

// formatNodeError keeps NodeErrors human-readable across the JSON boundary
// without leaking error wrapping internals. Cache_health serializes this
// when handing the map to JSON.
func formatNodeError(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
