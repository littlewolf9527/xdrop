// diffsync_test.go — AUD-007 regression tests for DiffSync dual-failure contract.
package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockNodeForDiff serves minimal Node API endpoints for DiffSync testing.
type mockNodeForDiff struct {
	// ruleIDs to report as existing on node
	existingRuleIDs []string
	// addFailed controls how many items to report as failed in POST /rules/batch
	addFailed int
	// deleteFailed controls how many items to report as failed in DELETE /rules/batch
	deleteFailed int
}

func (m *mockNodeForDiff) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/rules":
		rules := []map[string]interface{}{}
		for _, id := range m.existingRuleIDs {
			rules = append(rules, map[string]interface{}{"id": id, "action": "drop"})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"rules": rules, "count": len(rules)})
	case r.Method == "POST" && r.URL.Path == "/api/v1/rules/batch":
		var body struct {
			Rules []interface{} `json:"rules"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		n := len(body.Rules)
		failed := m.addFailed
		if failed > n {
			failed = n
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"added":   n - failed,
			"failed":  failed,
		})
	case r.Method == "DELETE" && r.URL.Path == "/api/v1/rules/batch":
		var body struct {
			IDs []string `json:"ids"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		n := len(body.IDs)
		failed := m.deleteFailed
		if failed > n {
			failed = n
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"deleted": n - failed,
			"failed":  failed,
		})
	case r.Method == "GET" && r.URL.Path == "/api/v1/whitelist":
		json.NewEncoder(w).Encode(map[string]interface{}{"entries": []interface{}{}, "count": 0})
	case r.Method == "POST" && r.URL.Path == "/api/v1/whitelist/batch":
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "added": 0, "failed": 0})
	case r.Method == "DELETE" && r.URL.Path == "/api/v1/whitelist/batch":
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "deleted": 0, "failed": 0})
	default:
		http.NotFound(w, r)
	}
}

func TestDiffSync_BatchAddFailed_ReturnsError(t *testing.T) {
	mock := &mockNodeForDiff{
		existingRuleIDs: []string{}, // node has no rules
		addFailed:       1,          // but batch add will fail 1 item
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := NewNodeClient(5 * time.Second)
	// target has 1 rule to add
	target := []map[string]interface{}{
		{"id": "rule-abc", "action": "drop", "dst_ip": "0.0.0.0/0"},
	}
	err := c.DiffSync(srv.URL, "test-key", target, nil)
	if err == nil {
		t.Fatal("DiffSync should return error when batch add reports failed > 0")
	}
}

func TestDiffSync_BatchDeleteFailed_ReturnsError(t *testing.T) {
	mock := &mockNodeForDiff{
		existingRuleIDs: []string{"stale-rule"}, // node has a stale rule
		deleteFailed:    1,                       // delete will fail
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := NewNodeClient(5 * time.Second)
	// target is empty — diff should delete stale-rule
	err := c.DiffSync(srv.URL, "test-key", nil, nil)
	if err == nil {
		t.Fatal("DiffSync should return error when batch delete reports failed > 0")
	}
}

// mockNodeWhitelistFail returns failed > 0 for whitelist batch operations.
type mockNodeWhitelistFail struct {
	failAddWhitelist    int
	failDeleteWhitelist int
	existingWlIDs       []string
}

func (m *mockNodeWhitelistFail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/rules":
		json.NewEncoder(w).Encode(map[string]interface{}{"rules": []interface{}{}, "count": 0})
	case r.Method == "GET" && r.URL.Path == "/api/v1/whitelist/ids":
		json.NewEncoder(w).Encode(map[string]interface{}{"ids": m.existingWlIDs})
	case r.Method == "GET" && r.URL.Path == "/api/v1/whitelist":
		entries := []map[string]interface{}{}
		for _, id := range m.existingWlIDs {
			entries = append(entries, map[string]interface{}{"id": id})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"entries": entries, "count": len(entries)})
	case r.Method == "POST" && r.URL.Path == "/api/v1/whitelist/batch":
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "added": 0, "failed": m.failAddWhitelist})
	case r.Method == "DELETE" && r.URL.Path == "/api/v1/whitelist/batch":
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "deleted": 0, "failed": m.failDeleteWhitelist})
	default:
		http.NotFound(w, r)
	}
}

func TestDiffSync_WhitelistAddFailed_ReturnsError(t *testing.T) {
	mock := &mockNodeWhitelistFail{failAddWhitelist: 1}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := NewNodeClient(5 * time.Second)
	wl := []map[string]interface{}{{"id": "wl-1", "src_ip": "1.2.3.4"}}
	err := c.DiffSync(srv.URL, "test-key", nil, wl)
	if err == nil {
		t.Fatal("DiffSync should return error when whitelist add reports failed > 0")
	}
}

func TestDiffSync_WhitelistDeleteFailed_ReturnsError(t *testing.T) {
	mock := &mockNodeWhitelistFail{
		existingWlIDs:       []string{"wl-stale"},
		failDeleteWhitelist: 1,
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := NewNodeClient(5 * time.Second)
	err := c.DiffSync(srv.URL, "test-key", nil, nil)
	if err == nil {
		t.Fatal("DiffSync should return error when whitelist delete reports failed > 0")
	}
}

func TestDiffSync_AllSuccess_NoError(t *testing.T) {
	mock := &mockNodeForDiff{
		existingRuleIDs: []string{},
		addFailed:       0,
		deleteFailed:    0,
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	c := NewNodeClient(5 * time.Second)
	target := []map[string]interface{}{
		{"id": "rule-ok", "action": "drop", "dst_ip": "1.2.3.4"},
	}
	err := c.DiffSync(srv.URL, "test-key", target, nil)
	if err != nil {
		t.Fatalf("DiffSync should succeed when no failures, got: %v", err)
	}
}
