// disabled_no_fanout_test.go — verifies that disabled-rule code paths do not
// emit any HTTP requests to Node endpoints.  Uses a real httptest.Server as a
// spy so that test assertions are strong (zero-node fakeNodeProvider would
// return Total=0 even if sync code ran, making assertions meaningless).
package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/internal/client"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
)

// spyNodeProvider satisfies NodeProvider with one always-online node.
type spyNodeProvider struct {
	node *model.Node
}

func (p *spyNodeProvider) List() ([]*model.Node, error)      { return []*model.Node{p.node}, nil }
func (p *spyNodeProvider) Get(_ string) (*model.Node, error) { return p.node, nil }
func (p *spyNodeProvider) UpdateStatus(_, _ string)          {}
func (p *spyNodeProvider) UpdateLastSeen(_ string)           {}
func (p *spyNodeProvider) UpdateLastSync(_ string)           {}

// newSpyServer starts a minimal Node API stub that counts every inbound
// rule-mutation request and always replies {"success":true}.
func newSpyServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "added": 1, "failed": 0})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// newSpyRuleService wires a RuleService that talks to the given httptest spy.
func newSpyRuleService(t *testing.T, srv *httptest.Server) (*RuleService, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "spy.db")
	db, err := repository.NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open spy DB: %v", err)
	}
	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	repo := repository.NewSQLiteRuleRepo(db)
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	syncLogRepo := repository.NewSQLiteSyncLogRepo(db)

	node := &model.Node{
		ID:       "spy-node",
		Name:     "spy",
		Endpoint: srv.URL,
		Status:   model.NodeStatusOnline,
	}
	provider := &spyNodeProvider{node: node}
	nc := client.NewNodeClient(3 * time.Second)
	syncSvc := NewSyncService(provider, syncLogRepo, repo, wlRepo, nc, 1, 0, time.Millisecond)
	return NewRuleService(repo, syncSvc), cleanup
}

// Sanity: enabled create should call Node exactly once (POST /api/v1/rules).
func TestSpyNode_EnabledCreate_CallsNode(t *testing.T) {
	srv, calls := newSpyServer(t)
	svc, cleanup := newSpyRuleService(t, srv)
	defer cleanup()

	_, _, err := svc.Create(&model.RuleRequest{DstIP: "192.0.2.50", Action: "drop"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n := atomic.LoadInt32(calls); n == 0 {
		t.Error("expected at least one HTTP call for enabled create, got 0")
	}
}

// Disabled create must not call Node at all.
func TestSpyNode_DisabledCreate_NoFanout(t *testing.T) {
	srv, calls := newSpyServer(t)
	svc, cleanup := newSpyRuleService(t, srv)
	defer cleanup()

	f := false
	_, _, err := svc.Create(&model.RuleRequest{DstIP: "192.0.2.51", Action: "drop", Enabled: &f})
	if err != nil {
		t.Fatalf("create disabled: %v", err)
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Errorf("expected 0 HTTP calls for disabled create, got %d", n)
	}
}

// Anomaly merge into a disabled existing rule must not call Node.
func TestSpyNode_DisabledAnomalyMerge_NoFanout(t *testing.T) {
	srv, calls := newSpyServer(t)
	svc, cleanup := newSpyRuleService(t, srv)
	defer cleanup()

	// Create a disabled bad_fragment rule.
	f := false
	r1, _, err := svc.Create(&model.RuleRequest{
		DstIP:   "192.0.2.52",
		Action:  "drop",
		Decoder: "bad_fragment",
		Enabled: &f,
	})
	if err != nil {
		t.Fatalf("create disabled anomaly rule: %v", err)
	}
	// Reset call counter after the disabled create (0 calls expected, but just
	// in case the spy counted any unrelated request).
	atomic.StoreInt32(calls, 0)

	// Merge a second anomaly decoder onto the same tuple.
	r2, _, err := svc.Create(&model.RuleRequest{
		DstIP:   "192.0.2.52",
		Action:  "drop",
		Decoder: "invalid",
	})
	if err != nil {
		t.Fatalf("merge create: %v", err)
	}
	if r2.ID != r1.ID {
		t.Fatalf("expected merge to return same rule ID, got %s != %s", r2.ID, r1.ID)
	}
	if r2.Enabled {
		t.Error("merged rule must remain disabled")
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Errorf("expected 0 HTTP calls for disabled anomaly merge, got %d", n)
	}
}

// Deleting a disabled rule must not call Node (rule was never in BPF).
func TestSpyNode_DisabledDelete_NoFanout(t *testing.T) {
	srv, calls := newSpyServer(t)
	svc, cleanup := newSpyRuleService(t, srv)
	defer cleanup()

	f := false
	r, _, err := svc.Create(&model.RuleRequest{DstIP: "192.0.2.53", Action: "drop", Enabled: &f})
	if err != nil {
		t.Fatalf("create disabled: %v", err)
	}
	atomic.StoreInt32(calls, 0) // reset after disabled create

	_, err = svc.Delete(r.ID)
	if err != nil {
		t.Fatalf("delete disabled: %v", err)
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Errorf("expected 0 HTTP calls for disabled rule delete, got %d", n)
	}
}

// Sanity: enabled delete should call Node (DELETE /api/v1/rules/:id).
func TestSpyNode_EnabledDelete_CallsNode(t *testing.T) {
	srv, calls := newSpyServer(t)
	svc, cleanup := newSpyRuleService(t, srv)
	defer cleanup()

	r, _, err := svc.Create(&model.RuleRequest{DstIP: "192.0.2.54", Action: "drop"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	atomic.StoreInt32(calls, 0) // reset after create

	_, err = svc.Delete(r.ID)
	if err != nil {
		t.Fatalf("delete enabled: %v", err)
	}
	if n := atomic.LoadInt32(calls); n == 0 {
		t.Error("expected at least one HTTP call for enabled rule delete, got 0")
	}
}
