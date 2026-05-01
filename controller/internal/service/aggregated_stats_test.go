package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// makeServer spins up a httptest server whose handler can be parameterized:
//
//	delay  — how long to "process" before responding. Must respect ctx.
//	hits   — counter incremented atomically for every received request.
//	body   — optional override of the JSON response.
//
// The handler uses select { time.After / r.Context().Done() } so an early
// client-side ctx cancel terminates the server-side handler too — without
// this, httptest.Server.Close() would block until the longest sleep elapsed,
// which would mask context-not-wired bugs and bloat test runtime.
func makeServer(delay time.Duration, hits *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rules":[{"id":"r1","stats":{"match_count":1,"drop_count":0,"drop_pps":0}}],"count":1}`))
	}))
}

// makeService builds a NodeService whose nodes point at the supplied
// httptest endpoints. The returned NodeService is enough to drive
// GetAggregatedRuleStatsDetailed; ruleRepo / wlRepo / syncService are not
// touched by the fan-out path.
func makeService(timeout time.Duration, nodes []model.Node) *NodeService {
	svc := &NodeService{
		nodes:      make(map[string]*model.Node, len(nodes)),
		nodeClient: client.NewNodeClient(timeout),
	}
	for i, n := range nodes {
		nn := n
		svc.nodes[nn.ID] = &nn
		_ = i
	}
	return svc
}

func TestFetch_PerNodeTimeoutHonored(t *testing.T) {
	var hits atomic.Int64
	srv := makeServer(5*time.Second, &hits) // simulates a stuck node
	defer srv.Close()

	svc := makeService(10*time.Second, []model.Node{
		{ID: "slow", Name: "slow", Endpoint: srv.URL, Status: model.NodeStatusOnline},
	})

	start := time.Now()
	res := svc.GetAggregatedRuleStatsDetailed(context.Background(), AggregatedFetchConfig{
		PerNodeTimeout: 200 * time.Millisecond,
		MaxConcurrency: 1,
	})
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Fatalf("per-node timeout did not abort: elapsed %v (expected ≤ 1s)", elapsed)
	}
	if res.FailedNodes != 1 {
		t.Fatalf("expected 1 failed node, got %d", res.FailedNodes)
	}
	if _, ok := res.NodeErrors["slow"]; !ok {
		t.Fatalf("expected NodeErrors[slow], got %v", res.NodeErrors)
	}
	if !strings.Contains(res.NodeErrors["slow"].Error(), "context") {
		t.Fatalf("expected context error, got %v", res.NodeErrors["slow"])
	}
}

func TestFetch_OfflineUnknownSyncingSeparated(t *testing.T) {
	// One Online node returns quickly so the fan-out has work to do.
	var hits atomic.Int64
	srv := makeServer(5*time.Millisecond, &hits)
	defer srv.Close()

	svc := makeService(1*time.Second, []model.Node{
		{ID: "on", Name: "online-1", Endpoint: srv.URL, Status: model.NodeStatusOnline},
		{ID: "off", Name: "offline-1", Endpoint: "http://0.0.0.0:1", Status: model.NodeStatusOffline},
		{ID: "unk", Name: "unknown-1", Endpoint: "http://0.0.0.0:1", Status: model.NodeStatusUnknown},
		{ID: "syn", Name: "syncing-1", Endpoint: "http://0.0.0.0:1", Status: model.NodeStatusSyncing},
	})

	res := svc.GetAggregatedRuleStatsDetailed(context.Background(), AggregatedFetchConfig{
		PerNodeTimeout: 500 * time.Millisecond,
		MaxConcurrency: 4,
	})

	if res.ConfiguredNodes != 4 {
		t.Fatalf("ConfiguredNodes=%d, want 4", res.ConfiguredNodes)
	}
	if res.AttemptedNodes != 1 || res.SucceededNodes != 1 {
		t.Fatalf("Attempted/Succeeded should be 1/1, got %d/%d", res.AttemptedNodes, res.SucceededNodes)
	}
	if res.SkippedOfflineNodes != 1 || res.SkippedUnknownNodes != 1 || res.SkippedSyncingNodes != 1 {
		t.Fatalf("skip groups should be 1/1/1, got %d/%d/%d",
			res.SkippedOfflineNodes, res.SkippedUnknownNodes, res.SkippedSyncingNodes)
	}
	if len(res.NodeErrors) != 0 {
		t.Fatalf("NodeErrors should NOT contain skipped nodes, got %v", res.NodeErrors)
	}
	// Names must land in the right slice
	if !contains(res.OfflineNodeNames, "offline-1") {
		t.Fatalf("offline node missing from OfflineNodeNames: %v", res.OfflineNodeNames)
	}
	if !contains(res.UnknownNodeNames, "unknown-1") {
		t.Fatalf("unknown node missing from UnknownNodeNames: %v", res.UnknownNodeNames)
	}
	if !contains(res.SyncingNodeNames, "syncing-1") {
		t.Fatalf("syncing node missing from SyncingNodeNames: %v", res.SyncingNodeNames)
	}
}

func TestFetch_BoundedConcurrency(t *testing.T) {
	// 4 nodes that each take 100ms. With MaxConcurrency=2, the round must
	// take at least 200ms (2 batches of 2 in parallel) — never 100ms (all
	// parallel) and never 400ms (serial).
	var hits atomic.Int64
	srv := makeServer(100*time.Millisecond, &hits)
	defer srv.Close()

	nodes := make([]model.Node, 4)
	for i := range nodes {
		nodes[i] = model.Node{
			ID: "n" + itoa(i), Name: "n" + itoa(i), Endpoint: srv.URL, Status: model.NodeStatusOnline,
		}
	}
	svc := makeService(1*time.Second, nodes)

	start := time.Now()
	res := svc.GetAggregatedRuleStatsDetailed(context.Background(), AggregatedFetchConfig{
		PerNodeTimeout: 500 * time.Millisecond,
		MaxConcurrency: 2,
	})
	elapsed := time.Since(start)

	if res.SucceededNodes != 4 {
		t.Fatalf("expected 4 successes, got %d", res.SucceededNodes)
	}
	// Lower bound: 2 batches of 2 in parallel ≈ 200ms
	if elapsed < 180*time.Millisecond {
		t.Fatalf("concurrency too high: elapsed %v < 180ms", elapsed)
	}
	// Upper bound: should still be << 400ms (full serial)
	if elapsed > 350*time.Millisecond {
		t.Fatalf("concurrency too low: elapsed %v > 350ms", elapsed)
	}
}

// TestFetch_PartialFailureReturnsBoth verifies that when a fan-out hits a
// mix of successful and failed nodes, the result includes BOTH succeeded
// stats AND the failure metadata. The cache layer relies on this — without
// it the resulting cacheState would lose track of whether any node
// actually succeeded (which gates ok vs partial vs failed).
func TestFetch_PartialFailureReturnsBoth(t *testing.T) {
	var hits atomic.Int64
	good := makeServer(5*time.Millisecond, &hits)
	defer good.Close()

	// Two good servers + one URL guaranteed to fail (refused immediately).
	svc := makeService(500*time.Millisecond, []model.Node{
		{ID: "g1", Name: "good-1", Endpoint: good.URL, Status: model.NodeStatusOnline},
		{ID: "g2", Name: "good-2", Endpoint: good.URL, Status: model.NodeStatusOnline},
		{ID: "bad", Name: "bad-1", Endpoint: "http://127.0.0.1:1", Status: model.NodeStatusOnline},
	})

	res := svc.GetAggregatedRuleStatsDetailed(context.Background(), AggregatedFetchConfig{
		PerNodeTimeout: 200 * time.Millisecond,
		MaxConcurrency: 4,
	})

	if res.SucceededNodes != 2 {
		t.Fatalf("expected 2 successes, got %d", res.SucceededNodes)
	}
	if res.FailedNodes != 1 {
		t.Fatalf("expected 1 failure, got %d", res.FailedNodes)
	}
	if _, ok := res.NodeErrors["bad-1"]; !ok {
		t.Fatalf("expected NodeErrors[bad-1], got %v", res.NodeErrors)
	}
	// Stats from succeeded nodes should still be aggregated; the test
	// servers return one rule per call and the helper sums them across
	// all succeeding nodes.
	if v, ok := res.Stats["r1"]; !ok || v.MatchCount != 2 {
		t.Fatalf("expected aggregated stats from 2 nodes (match_count=2), got %v", res.Stats)
	}
}

// TestFetch_AllConfiguredNodesFailReturnsEmptyStats covers the worst case:
// every node is either failing or skipped. The cache state machine uses
// this signal to decide failed vs failed_no_snapshot, so the conservation
// law (failed + skipped_* == configured) MUST hold even when nothing
// succeeds.
func TestFetch_AllConfiguredNodesFailReturnsEmptyStats(t *testing.T) {
	svc := makeService(500*time.Millisecond, []model.Node{
		{ID: "f1", Name: "fail-1", Endpoint: "http://127.0.0.1:1", Status: model.NodeStatusOnline},
		{ID: "f2", Name: "fail-2", Endpoint: "http://127.0.0.1:2", Status: model.NodeStatusOnline},
		{ID: "off", Name: "off-1", Endpoint: "http://127.0.0.1:3", Status: model.NodeStatusOffline},
	})

	res := svc.GetAggregatedRuleStatsDetailed(context.Background(), AggregatedFetchConfig{
		PerNodeTimeout: 200 * time.Millisecond,
		MaxConcurrency: 4,
	})

	if res.SucceededNodes != 0 {
		t.Fatalf("expected 0 successes, got %d", res.SucceededNodes)
	}
	if len(res.Stats) != 0 {
		t.Fatalf("expected empty stats map, got %v", res.Stats)
	}
	// Conservation check: every configured node is accounted for, either
	// in failed or in one of the three skip groups.
	accounted := res.FailedNodes + res.SkippedOfflineNodes + res.SkippedUnknownNodes + res.SkippedSyncingNodes
	if accounted != res.ConfiguredNodes {
		t.Fatalf("conservation broken: failed+skipped(%d) != configured(%d)", accounted, res.ConfiguredNodes)
	}
	if res.FailedNodes != 2 {
		t.Fatalf("expected 2 failed (online but unreachable), got %d", res.FailedNodes)
	}
	if res.SkippedOfflineNodes != 1 {
		t.Fatalf("expected 1 skipped-offline, got %d", res.SkippedOfflineNodes)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
