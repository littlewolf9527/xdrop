// sync_whitelist_test.go — Phase 8 Controller whitelist sync path unit tests.
//
// Tests syncWhitelistToNode (private method, package-internal access) using
// httptest servers to simulate new and old Node agents. No BPF required.
//
// Coverage:
//   T36  — syncWhitelistToNode calls POST /api/v1/sync/whitelist on new nodes
//   T37a — old node (404 on sync endpoint) → always error, upgrade required
//   T37b — old node (404 on sync endpoint) + new combo entry → fail loudly
package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// syncNode builds a minimal model.Node pointing at the given server URL.
func syncNode(url string) *model.Node {
	return &model.Node{
		ID:       "test-node-1",
		Name:     "test-node",
		Endpoint: url,
		ApiKey:   "",
	}
}

// newSyncServiceWithClient creates a minimal SyncService with the provided NodeClient.
// Only the nodeClient field is needed for syncWhitelistToNode tests.
func newSyncServiceWithClient(c *client.NodeClient) *SyncService {
	return &SyncService{nodeClient: c}
}

// ---- T36: syncWhitelistToNode calls POST /api/v1/sync/whitelist ----

// T36: when the node supports the Phase 8 endpoint, syncWhitelistToNode must
// issue exactly one POST to /api/v1/sync/whitelist with the full whitelist
// entries in the request body. Legacy batch endpoints (GET/DELETE/POST
// /whitelist and /whitelist/batch) must NOT be called.
func TestSyncWhitelistToNode_T36_UsesAtomicEndpoint(t *testing.T) {
	var syncCalls int
	var batchCalls int
	var capturedBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/sync/whitelist":
			syncCalls++
			if r.Method != http.MethodPost {
				t.Errorf("sync endpoint: expected POST, got %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
				t.Errorf("sync endpoint: failed to decode body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"total": 2, "failed": 0})

		case "/api/v1/whitelist",
			"/api/v1/whitelist/batch":
			batchCalls++
			t.Errorf("legacy whitelist endpoint called: %s %s — must not be reached on new node", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	svc := newSyncServiceWithClient(client.NewNodeClient(5 * time.Second))
	node := syncNode(srv.URL)

	entries := []map[string]interface{}{
		{"id": "wl-1", "src_ip": "192.0.2.1"},
		{"id": "wl-2", "dst_ip": "192.0.2.2"},
	}

	if err := svc.syncWhitelistToNode(node, entries); err != nil {
		t.Fatalf("syncWhitelistToNode: %v", err)
	}

	if syncCalls != 1 {
		t.Errorf("sync endpoint called %d times, want 1", syncCalls)
	}
	if batchCalls != 0 {
		t.Errorf("legacy batch endpoint called %d times, want 0", batchCalls)
	}

	// Verify request body contains all entries.
	entriesRaw, ok := capturedBody["entries"].([]interface{})
	if !ok {
		t.Fatalf("sync body.entries missing or wrong type: %v", capturedBody)
	}
	if len(entriesRaw) != 2 {
		t.Errorf("sync body.entries count = %d, want 2", len(entriesRaw))
	}
}

// T36b: syncWhitelistToNode returns error if the sync endpoint returns HTTP 500.
func TestSyncWhitelistToNode_T36b_SyncEndpointServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/sync/whitelist" {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	svc := newSyncServiceWithClient(client.NewNodeClient(5 * time.Second))
	node := syncNode(srv.URL)

	err := svc.syncWhitelistToNode(node, []map[string]interface{}{
		{"id": "wl-1", "src_ip": "192.0.2.1"},
	})
	if err == nil {
		t.Fatal("expected error from HTTP 500, got nil")
	}
}

// ---- T37a: old node + legacy-only combos → fallback to batch ----

// T37a: when the sync endpoint returns 404 (old Node), syncWhitelistToNode must
// return an error mentioning upgrade — no fallback regardless of combo type.
func TestSyncWhitelistToNode_T37a_OldNodeReturnsError(t *testing.T) {
	var syncAttempts int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/sync/whitelist":
			syncAttempts++
			http.NotFound(w, r)
		default:
			// Any other call is unexpected
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	svc := newSyncServiceWithClient(client.NewNodeClient(5 * time.Second))
	node := syncNode(srv.URL)

	// Legacy combos (src_ip-only) — no longer matters, old node must still fail.
	newEntries := []map[string]interface{}{
		{"id": "new-wl-1", "src_ip": "192.0.2.10"},
		{"id": "new-wl-2", "dst_ip": "192.0.2.11"},
	}

	err := svc.syncWhitelistToNode(node, newEntries)
	if err == nil {
		t.Fatal("expected error for old node (404), got nil")
	}
	if !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("error should mention upgrade, got: %v", err)
	}
	if syncAttempts != 1 {
		t.Errorf("sync endpoint attempted %d times, want 1", syncAttempts)
	}
}

// ---- T37b: old node + new combo present → fail loudly ----

// T37b: when the sync endpoint returns 404 (old Node) but one or more entries
// use a new combo (protocol-only, port-based, etc.), syncWhitelistToNode must
// return an error and must NOT fall back to the legacy batch path. The error
// must mention that the node needs an upgrade.
func TestSyncWhitelistToNode_T37b_OldNodeNewComboFailsLoudly(t *testing.T) {
	var addBatchCalls int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/sync/whitelist":
			http.NotFound(w, r) // old node

		case r.URL.Path == "/api/v1/whitelist/batch" && r.Method == http.MethodPost:
			// Should not be reached.
			addBatchCalls++
			http.Error(w, "unexpected call", http.StatusInternalServerError)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	svc := newSyncServiceWithClient(client.NewNodeClient(5 * time.Second))
	node := syncNode(srv.URL)

	// One entry uses a new combo (protocol-only: no IPs, no ports, just protocol).
	newEntries := []map[string]interface{}{
		{"id": "legacy-wl", "src_ip": "192.0.2.10"},                    // legacy OK
		{"id": "new-combo-wl", "protocol": "udp"},                        // new combo: protocol-only
	}

	err := svc.syncWhitelistToNode(node, newEntries)
	if err == nil {
		t.Fatal("expected error for new combo on old node, got nil")
	}
	// Error must mention upgrade.
	if !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("error should mention upgrade, got: %v", err)
	}
	// Legacy batch must NOT have been called.
	if addBatchCalls != 0 {
		t.Errorf("legacy batch called %d times, want 0 (must fail loudly)", addBatchCalls)
	}
}

// T37b-port: port-only combo is also a new combo and must trigger loud failure.
func TestSyncWhitelistToNode_T37b_PortOnlyComboFailsLoudly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/sync/whitelist" {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	svc := newSyncServiceWithClient(client.NewNodeClient(5 * time.Second))
	node := syncNode(srv.URL)

	// dst_port-only combo: not supported by pre-v2.7 BPF.
	newEntries := []map[string]interface{}{
		{"id": "port-only", "dst_port": 80},
	}

	err := svc.syncWhitelistToNode(node, newEntries)
	if err == nil {
		t.Fatal("expected error for port-only combo on old node, got nil")
	}
	if !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("error should mention upgrade, got: %v", err)
	}
}
