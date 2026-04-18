package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNode simulates a Node agent for FullSync rollback tests. It exposes the
// subset of endpoints FullSync touches: GET/DELETE /rules, POST /rules/batch,
// GET/DELETE /whitelist, POST /whitelist/batch. Failures can be injected per
// endpoint via the failOn* fields.
type fakeNode struct {
	mu sync.Mutex

	rules     []map[string]interface{}
	whitelist []map[string]interface{}

	// Inject a transient failure: fail the Nth AddRulesBatch / AddWhitelistBatch
	// call and succeed thereafter (mimicking a recoverable error that only hits
	// the primary add, not the rollback re-add).
	failAddRulesOnCall     int
	failAddWhitelistOnCall int

	addRulesCalls     int
	addWhitelistCalls int
}

func (f *fakeNode) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"rules": f.rules,
				"count": len(f.rules),
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/v1/rules/batch", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			f.addRulesCalls++
			if f.failAddRulesOnCall != 0 && f.addRulesCalls == f.failAddRulesOnCall {
				http.Error(w, "injected add-rules failure", http.StatusInternalServerError)
				return
			}
			var body struct {
				Rules []map[string]interface{} `json:"rules"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f.rules = append(f.rules, body.Rules...)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "added": len(body.Rules)})
		case http.MethodDelete:
			var body struct {
				IDs []string `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			toDel := make(map[string]bool, len(body.IDs))
			for _, id := range body.IDs {
				toDel[id] = true
			}
			kept := f.rules[:0]
			for _, r := range f.rules {
				if id, ok := r["id"].(string); ok && toDel[id] {
					continue
				}
				kept = append(kept, r)
			}
			f.rules = kept
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "deleted": len(body.IDs)})
		}
	})

	mux.HandleFunc("/api/v1/whitelist", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entries": f.whitelist,
			"count":   len(f.whitelist),
		})
	})

	mux.HandleFunc("/api/v1/whitelist/batch", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			f.addWhitelistCalls++
			if f.failAddWhitelistOnCall != 0 && f.addWhitelistCalls == f.failAddWhitelistOnCall {
				http.Error(w, "injected add-whitelist failure", http.StatusInternalServerError)
				return
			}
			var body struct {
				Entries []map[string]interface{} `json:"entries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f.whitelist = append(f.whitelist, body.Entries...)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "added": len(body.Entries)})
		case http.MethodDelete:
			var body struct {
				IDs []string `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			toDel := make(map[string]bool, len(body.IDs))
			for _, id := range body.IDs {
				toDel[id] = true
			}
			kept := f.whitelist[:0]
			for _, e := range f.whitelist {
				if id, ok := e["id"].(string); ok && toDel[id] {
					continue
				}
				kept = append(kept, e)
			}
			f.whitelist = kept
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "deleted": len(body.IDs)})
		}
	})

	return mux
}

func startFakeNode(t *testing.T, f *fakeNode) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return srv
}

// TestFullSync_RollsBackRulesOnAddFailure verifies BUG-047: if AddRulesBatch
// fails after DeleteRulesBatch succeeded, the snapshot is re-inserted so the
// node does not end up with 0 rules.
func TestFullSync_RollsBackRulesOnAddFailure(t *testing.T) {
	fake := &fakeNode{
		rules: []map[string]interface{}{
			{"id": "rule-original-1", "dst_ip": "192.0.2.10", "action": "drop"},
			{"id": "rule-original-2", "dst_ip": "192.0.2.11", "action": "drop"},
		},
		failAddRulesOnCall: 1, // fail the first add (primary), let rollback succeed
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newRules := []map[string]interface{}{
		{"id": "rule-new-1", "dst_ip": "198.51.100.5", "action": "drop"},
	}

	err := cli.FullSync(srv.URL, "", newRules, nil)
	if err == nil {
		t.Fatal("FullSync must return error when AddRulesBatch fails")
	}
	if !strings.Contains(err.Error(), "rolled back to snapshot") {
		t.Errorf("error should mention rollback, got: %v", err)
	}

	// Node must have the original 2 rules restored
	if got := len(fake.rules); got != 2 {
		t.Errorf("after rollback, node has %d rules, want 2 (original snapshot)", got)
	}
	// Both AddRulesBatch calls should have happened: 1 failed attempt + 1 rollback
	if fake.addRulesCalls != 2 {
		t.Errorf("expected 2 AddRulesBatch calls (fail + rollback), got %d", fake.addRulesCalls)
	}
}

// TestFullSync_RollsBackWhitelistOnAddFailure verifies the same pattern for the
// whitelist path.
func TestFullSync_RollsBackWhitelistOnAddFailure(t *testing.T) {
	fake := &fakeNode{
		whitelist: []map[string]interface{}{
			{"id": "wl-original-1", "src_ip": "192.0.2.100"},
		},
		failAddWhitelistOnCall: 1,
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newWl := []map[string]interface{}{
		{"id": "wl-new-1", "src_ip": "198.51.100.100"},
	}

	err := cli.FullSync(srv.URL, "", nil, newWl)
	if err == nil {
		t.Fatal("FullSync must return error when AddWhitelistBatch fails")
	}
	if !strings.Contains(err.Error(), "rolled back to snapshot") {
		t.Errorf("error should mention rollback, got: %v", err)
	}
	if got := len(fake.whitelist); got != 1 {
		t.Errorf("after rollback, node has %d whitelist entries, want 1", got)
	}
	if fake.addWhitelistCalls != 2 {
		t.Errorf("expected 2 AddWhitelistBatch calls, got %d", fake.addWhitelistCalls)
	}
}

// TestFullSync_SuccessLeavesNoSpuriousRollbacks verifies the positive-control
// path: a successful sync must not trigger any rollback add calls.
func TestFullSync_SuccessLeavesNoSpuriousRollbacks(t *testing.T) {
	fake := &fakeNode{
		rules: []map[string]interface{}{
			{"id": "rule-old-1", "dst_ip": "192.0.2.10", "action": "drop"},
		},
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newRules := []map[string]interface{}{
		{"id": "rule-new-1", "dst_ip": "198.51.100.5", "action": "drop"},
		{"id": "rule-new-2", "dst_ip": "198.51.100.6", "action": "drop"},
	}

	if err := cli.FullSync(srv.URL, "", newRules, nil); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if got := len(fake.rules); got != 2 {
		t.Errorf("post-sync node has %d rules, want 2", got)
	}
	if fake.addRulesCalls != 1 {
		t.Errorf("expected exactly 1 AddRulesBatch call, got %d (spurious rollback?)", fake.addRulesCalls)
	}
}
