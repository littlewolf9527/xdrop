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

	// Inject a transient HTTP failure: fail the Nth AddRulesBatch /
	// AddWhitelistBatch call with HTTP 500.
	failAddRulesOnCall     int
	failAddWhitelistOnCall int

	// Inject a business-level partial failure: return HTTP 200 with
	// {"success":true,"added":len-N,"failed":N} on the Nth add call. Used to
	// exercise AUD-V242-001 — the gap where batch APIs can fail per-item
	// without returning an HTTP error.
	partialAddRulesOnCall        int
	partialAddRulesFailedCount   int
	partialAddWlOnCall           int
	partialAddWlFailedCount      int

	// Same pattern for batch-delete partial-failure (AUD-V242-002). The node
	// returns {"success":true,"deleted":X,"failed":Y}.
	partialDeleteRulesOnCall    int
	partialDeleteRulesFailedCnt int
	partialDeleteWlOnCall       int
	partialDeleteWlFailedCnt    int

	addRulesCalls        int
	addWhitelistCalls    int
	deleteRulesCalls     int
	deleteWhitelistCalls int
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
			if f.partialAddRulesOnCall != 0 && f.addRulesCalls == f.partialAddRulesOnCall {
				// Apply only the non-failing subset, report the rest as failed.
				accepted := len(body.Rules) - f.partialAddRulesFailedCount
				if accepted < 0 {
					accepted = 0
				}
				f.rules = append(f.rules, body.Rules[:accepted]...)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"added":   accepted,
					"failed":  f.partialAddRulesFailedCount,
				})
				return
			}
			f.rules = append(f.rules, body.Rules...)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "added": len(body.Rules)})
		case http.MethodDelete:
			f.deleteRulesCalls++
			var body struct {
				IDs []string `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Inject partial-delete: delete only the first (len-N) items and
			// report the rest as failed. Preserves the leftover in f.rules so
			// tests can assert residue.
			if f.partialDeleteRulesOnCall != 0 && f.deleteRulesCalls == f.partialDeleteRulesOnCall {
				accepted := len(body.IDs) - f.partialDeleteRulesFailedCnt
				if accepted < 0 {
					accepted = 0
				}
				toDel := make(map[string]bool, accepted)
				for _, id := range body.IDs[:accepted] {
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
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"deleted": accepted,
					"failed":  f.partialDeleteRulesFailedCnt,
				})
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
			if f.partialAddWlOnCall != 0 && f.addWhitelistCalls == f.partialAddWlOnCall {
				accepted := len(body.Entries) - f.partialAddWlFailedCount
				if accepted < 0 {
					accepted = 0
				}
				f.whitelist = append(f.whitelist, body.Entries[:accepted]...)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"added":   accepted,
					"failed":  f.partialAddWlFailedCount,
				})
				return
			}
			f.whitelist = append(f.whitelist, body.Entries...)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "added": len(body.Entries)})
		case http.MethodDelete:
			f.deleteWhitelistCalls++
			var body struct {
				IDs []string `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if f.partialDeleteWlOnCall != 0 && f.deleteWhitelistCalls == f.partialDeleteWlOnCall {
				accepted := len(body.IDs) - f.partialDeleteWlFailedCnt
				if accepted < 0 {
					accepted = 0
				}
				toDel := make(map[string]bool, accepted)
				for _, id := range body.IDs[:accepted] {
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
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"deleted": accepted,
					"failed":  f.partialDeleteWlFailedCnt,
				})
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

// TestFullSync_RollsBackOnPartialRulesFailure verifies AUD-V242-001:
// a business-level partial failure (HTTP 200 with `failed > 0` in the body)
// must be treated as a failure — triggering snapshot rollback — just like
// a transport-level error. Previously, FullSync ignored resp.Failed on the
// rules path and returned success with a partially-applied ruleset.
func TestFullSync_RollsBackOnPartialRulesFailure(t *testing.T) {
	fake := &fakeNode{
		rules: []map[string]interface{}{
			{"id": "rule-snap-1", "dst_ip": "192.0.2.20", "action": "drop"},
			{"id": "rule-snap-2", "dst_ip": "192.0.2.21", "action": "drop"},
		},
		// First AddRulesBatch returns 200 but rejects 1 of 2 target rules.
		partialAddRulesOnCall:      1,
		partialAddRulesFailedCount: 1,
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newRules := []map[string]interface{}{
		{"id": "rule-new-1", "dst_ip": "198.51.100.5", "action": "drop"},
		{"id": "rule-new-2", "dst_ip": "198.51.100.6", "action": "drop"},
	}

	err := cli.FullSync(srv.URL, "", newRules, nil)
	if err == nil {
		t.Fatal("FullSync must return error on partial add failure, got nil")
	}
	if !strings.Contains(err.Error(), "rolled back to snapshot") {
		t.Errorf("error should mention rollback, got: %v", err)
	}

	// After rollback, node must hold the full snapshot (2 original rules),
	// NOT a mix of snapshot + the 1 partial-accept.
	if got := len(fake.rules); got != 2 {
		t.Errorf("after rollback: node has %d rules, want 2 (snapshot only)", got)
	}
	// Verify the rules are actually the snapshot IDs, not the new partial set.
	ids := make(map[string]bool)
	for _, r := range fake.rules {
		if id, ok := r["id"].(string); ok {
			ids[id] = true
		}
	}
	if !ids["rule-snap-1"] || !ids["rule-snap-2"] {
		t.Errorf("after rollback: expected snapshot IDs, got %v", ids)
	}
}

// TestFullSync_RollsBackOnPartialWhitelistFailure is the whitelist analogue
// of the AUD-V242-001 partial-add regression test.
func TestFullSync_RollsBackOnPartialWhitelistFailure(t *testing.T) {
	fake := &fakeNode{
		whitelist: []map[string]interface{}{
			{"id": "wl-snap-1", "src_ip": "192.0.2.100"},
		},
		partialAddWlOnCall:      1,
		partialAddWlFailedCount: 1,
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newWl := []map[string]interface{}{
		{"id": "wl-new-1", "src_ip": "198.51.100.100"},
	}

	err := cli.FullSync(srv.URL, "", nil, newWl)
	if err == nil {
		t.Fatal("FullSync must return error on partial whitelist-add failure")
	}
	if !strings.Contains(err.Error(), "rolled back to snapshot") {
		t.Errorf("error should mention rollback, got: %v", err)
	}
	if got := len(fake.whitelist); got != 1 {
		t.Errorf("after rollback: node has %d whitelist entries, want 1", got)
	}
	ids := make(map[string]bool)
	for _, w := range fake.whitelist {
		if id, ok := w["id"].(string); ok {
			ids[id] = true
		}
	}
	if !ids["wl-snap-1"] {
		t.Errorf("after rollback: expected snapshot entry, got %v", ids)
	}
}

// TestFullSync_RollbackItselfPartiallyFails verifies the combined-error path
// for when the rollback add ALSO returns partial failure.
func TestFullSync_RollbackItselfPartiallyFails(t *testing.T) {
	fake := &fakeNode{
		rules: []map[string]interface{}{
			{"id": "rule-snap-1", "dst_ip": "192.0.2.30", "action": "drop"},
			{"id": "rule-snap-2", "dst_ip": "192.0.2.31", "action": "drop"},
		},
		failAddRulesOnCall:         1, // primary add: HTTP 500
		partialAddRulesOnCall:      2, // rollback: partial (1 of 2 snapshot rules rejected)
		partialAddRulesFailedCount: 1,
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newRules := []map[string]interface{}{
		{"id": "rule-new-1", "dst_ip": "198.51.100.5", "action": "drop"},
	}

	err := cli.FullSync(srv.URL, "", newRules, nil)
	if err == nil {
		t.Fatal("FullSync must return error when rollback is partial")
	}
	if !strings.Contains(err.Error(), "rollback partially failed") {
		t.Errorf("error should mention partial rollback, got: %v", err)
	}
}

// TestFullSync_AbortsOnPartialInitialDelete verifies AUD-V242-002: a
// HTTP 200 with failed>0 on the initial DeleteRulesBatch must abort the sync
// rather than proceeding to AddRulesBatch with partial residue still present.
func TestFullSync_AbortsOnPartialInitialDelete(t *testing.T) {
	fake := &fakeNode{
		rules: []map[string]interface{}{
			{"id": "rule-stuck-1", "dst_ip": "192.0.2.40", "action": "drop"},
			{"id": "rule-stuck-2", "dst_ip": "192.0.2.41", "action": "drop"},
		},
		// First DeleteRulesBatch returns 200 but rejects 1 of 2 rules
		partialDeleteRulesOnCall:    1,
		partialDeleteRulesFailedCnt: 1,
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newRules := []map[string]interface{}{
		{"id": "rule-new-1", "dst_ip": "198.51.100.5", "action": "drop"},
	}
	err := cli.FullSync(srv.URL, "", newRules, nil)
	if err == nil {
		t.Fatal("FullSync must abort on partial initial delete, got nil")
	}
	if !strings.Contains(err.Error(), "partial delete") {
		t.Errorf("error should mention partial delete, got: %v", err)
	}
	// AddRulesBatch must NOT have been called — the sync aborted before add.
	if fake.addRulesCalls != 0 {
		t.Errorf("AddRulesBatch should not have been called; got %d calls", fake.addRulesCalls)
	}
}

// TestFullSync_AbortsOnPartialRollbackPreClean verifies AUD-V242-002's second
// scenario: a partial primary add leaves residue on the node; rollback's
// pre-clean delete then also returns partial failure. Without this check,
// rollback would proceed to re-insert the snapshot on top of residue,
// yielding snapshot∪residue — the exact mixed-state bug this patch set is
// trying to prevent.
func TestFullSync_AbortsOnPartialRollbackPreClean(t *testing.T) {
	fake := &fakeNode{
		rules: []map[string]interface{}{
			{"id": "rule-snap-1", "dst_ip": "192.0.2.50", "action": "drop"},
		},
		// Primary add partial-succeeds: accepts 1 of 2 target rules, leaving
		// residue on the node.
		partialAddRulesOnCall:      1,
		partialAddRulesFailedCount: 1,
		// Rollback pre-clean (second delete) returns partial failure: can't
		// remove the residue the partial primary add just created.
		partialDeleteRulesOnCall:    2,
		partialDeleteRulesFailedCnt: 1,
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newRules := []map[string]interface{}{
		{"id": "rule-new-1", "dst_ip": "198.51.100.5", "action": "drop"},
		{"id": "rule-new-2", "dst_ip": "198.51.100.6", "action": "drop"},
	}
	err := cli.FullSync(srv.URL, "", newRules, nil)
	if err == nil {
		t.Fatal("FullSync must surface partial rollback pre-clean failure")
	}
	if !strings.Contains(err.Error(), "rollback pre-clean partially failed") {
		t.Errorf("error should mention pre-clean partial failure, got: %v", err)
	}
}

// TestFullSync_AbortsOnPartialInitialWhitelistDelete is the whitelist
// analogue of the rules initial-delete partial-failure test.
func TestFullSync_AbortsOnPartialInitialWhitelistDelete(t *testing.T) {
	fake := &fakeNode{
		whitelist: []map[string]interface{}{
			{"id": "wl-stuck-1", "src_ip": "192.0.2.100"},
			{"id": "wl-stuck-2", "src_ip": "192.0.2.101"},
		},
		partialDeleteWlOnCall:    1,
		partialDeleteWlFailedCnt: 1,
	}
	srv := startFakeNode(t, fake)
	cli := NewNodeClient(5 * time.Second)

	newWl := []map[string]interface{}{
		{"id": "wl-new-1", "src_ip": "198.51.100.100"},
	}
	err := cli.FullSync(srv.URL, "", nil, newWl)
	if err == nil {
		t.Fatal("FullSync must abort on partial initial whitelist delete")
	}
	if !strings.Contains(err.Error(), "partial delete") {
		t.Errorf("error should mention partial delete, got: %v", err)
	}
	if fake.addWhitelistCalls != 0 {
		t.Errorf("AddWhitelistBatch should not have been called; got %d", fake.addWhitelistCalls)
	}
}
