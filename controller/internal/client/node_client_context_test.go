package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestNodeClient_ContextCancelStopsRequest is the canonical proof that
// per-node ctx-with-timeout actually aborts in-flight HTTP requests.
//
// The handler waits 5 seconds OR the request context being canceled —
// whichever comes first. Crucially, with `select { case <-r.Context().Done() }`
// the server-side handler returns immediately when the client-side context
// is canceled, so httptest.Server.Close() doesn't block on a stale handler
// (per round-6 P3-6).
//
// The client-side test then enforces that the call returns within ~1s,
// not the 10s client-level timeout we configured below.
func TestNodeClient_ContextCancelStopsRequest(t *testing.T) {
	var serverDone atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
			// would have been bad — not enforced because we cancel below
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case <-r.Context().Done():
			serverDone.Store(true)
			return
		}
	}))
	defer srv.Close()

	// Client-level timeout intentionally large (10s). The whole point of
	// passing context.WithTimeout is to override per-call without changing
	// global client behavior.
	c := NewNodeClient(10 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	_, err := c.GetRulesWithStatsContext(ctx, srv.URL, "")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected ctx-deadline error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("per-call ctx did not cancel: elapsed %v (expected ~1s, hard cap 2s)", elapsed)
	}
}

// TestNodeClient_GetRulesWithStatsBackCompat ensures the legacy
// GetRulesWithStats helper still works against a happy-path server. This
// guards against a future refactor that accidentally drops the
// context.Background() delegate.
func TestNodeClient_GetRulesWithStatsBackCompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rules":[{"id":"r1","stats":{"match_count":42,"drop_count":1,"drop_pps":0.5}}],"count":1}`))
	}))
	defer srv.Close()

	c := NewNodeClient(2 * time.Second)
	resp, err := c.GetRulesWithStats(srv.URL, "")
	if err != nil {
		t.Fatalf("legacy call failed: %v", err)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].Stats.MatchCount != 42 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
