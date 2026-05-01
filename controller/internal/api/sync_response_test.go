// sync_response_test.go — B-2 verification: `sync` field is always present in
// rule mutation responses, regardless of failure count.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/littlewolf9527/xdrop/controller/internal/model"
	"github.com/littlewolf9527/xdrop/controller/internal/repository"
	"github.com/littlewolf9527/xdrop/controller/internal/service"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---- helper-level tests for syncToResponse ----

func TestSyncToResponse_AlwaysIncludesSyncOnSuccess(t *testing.T) {
	resp := gin.H{"success": true}
	sr := &service.SyncResult{Total: 1, Success: 1, Failed: 0}
	out := syncToResponse(resp, sr)
	if _, ok := out["sync"]; !ok {
		t.Fatal("sync field must be present on success too (B-2 always-present contract)")
	}
}

func TestSyncToResponse_AlwaysIncludesSyncOnFailure(t *testing.T) {
	resp := gin.H{"success": true}
	sr := &service.SyncResult{Total: 1, Success: 0, Failed: 1, Errors: map[string]string{"node-a": "boom"}}
	out := syncToResponse(resp, sr)
	got, ok := out["sync"]
	if !ok {
		t.Fatal("sync field must be present on failure")
	}
	gotSr, ok := got.(*service.SyncResult)
	if !ok {
		t.Fatalf("sync field should be *SyncResult, got %T", got)
	}
	if gotSr.Failed != 1 {
		t.Fatalf("expected sync.failed=1, got %d", gotSr.Failed)
	}
	if gotSr.Errors["node-a"] != "boom" {
		t.Fatalf("expected error map preserved, got %v", gotSr.Errors)
	}
}

func TestSyncToResponse_NilSyncIsOmitted(t *testing.T) {
	// nil is allowed (e.g. Delete with no nodes registered) — should NOT add a field.
	resp := gin.H{"success": true}
	out := syncToResponse(resp, nil)
	if _, ok := out["sync"]; ok {
		t.Fatal("sync field should be omitted when SyncResult is nil")
	}
}

// ---- Real handler JSON response tests (B-2) ----
// These verify the actual gin handler emits sync field always-present in
// responses, including when SyncResult.Failed == 0. Uses a real RuleService
// with on-disk SQLite + a no-op SyncService (no nodes).

type fakeNodeProvider struct{}

func (fakeNodeProvider) List() ([]*model.Node, error)       { return nil, nil }
func (fakeNodeProvider) Get(id string) (*model.Node, error) { return nil, nil }
func (fakeNodeProvider) UpdateStatus(id, status string)     {}
func (fakeNodeProvider) UpdateLastSeen(id string)           {}
func (fakeNodeProvider) UpdateLastSync(id string)           {}

func newTestRulesHandler(t *testing.T) (*RulesHandler, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := repository.NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}
	repo := repository.NewSQLiteRuleRepo(db)
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	syncLogRepo := repository.NewSQLiteSyncLogRepo(db)
	syncSvc := service.NewSyncService(fakeNodeProvider{}, syncLogRepo, repo, wlRepo, nil, 1, 0, time.Millisecond)
	ruleSvc := service.NewRuleService(repo, syncSvc)
	// nodeSvc and statsCache both nil — sync_response_test only exercises
	// mutation handlers (Create/Delete/...), which do not consume either.
	return NewRulesHandler(ruleSvc, nil, nil), cleanup
}

func TestRulesHandler_CreateResponse_AlwaysIncludesSync(t *testing.T) {
	h, cleanup := newTestRulesHandler(t)
	defer cleanup()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/api/v1/rules",
		strings.NewReader(`{"dst_ip":"10.99.0.1","action":"drop"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Create(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["success"] != true {
		t.Fatalf("expected success=true, got %v", resp["success"])
	}
	if _, ok := resp["sync"]; !ok {
		t.Fatal("sync field must be always-present in Create response (B-2)")
	}
}

func TestRulesHandler_UpdateResponse_AlwaysIncludesSync(t *testing.T) {
	h, cleanup := newTestRulesHandler(t)
	defer cleanup()

	// Create
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/api/v1/rules",
		strings.NewReader(`{"dst_ip":"10.99.0.2","action":"drop"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Create(c)
	var createResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResp)
	id := createResp["rule"].(map[string]interface{})["id"].(string)

	// Update
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("PUT", "/api/v1/rules/"+id,
		strings.NewReader(`{"comment":"new"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = []gin.Param{{Key: "id", Value: id}}
	h.Update(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["sync"]; !ok {
		t.Fatal("sync field must be always-present in Update response (B-2)")
	}
}

func TestRulesHandler_DeleteResponse_AlwaysIncludesSync(t *testing.T) {
	h, cleanup := newTestRulesHandler(t)
	defer cleanup()

	// Create
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/api/v1/rules",
		strings.NewReader(`{"dst_ip":"10.99.0.3","action":"drop"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Create(c)
	var createResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResp)
	id := createResp["rule"].(map[string]interface{})["id"].(string)

	// Delete
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("DELETE", "/api/v1/rules/"+id, nil)
	c.Params = []gin.Param{{Key: "id", Value: id}}
	h.Delete(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["sync"]; !ok {
		t.Fatal("sync field must be always-present in Delete response (B-2)")
	}
}

func TestRulesHandler_BatchCreateResponse_AlwaysIncludesSync(t *testing.T) {
	h, cleanup := newTestRulesHandler(t)
	defer cleanup()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/api/v1/rules/batch",
		strings.NewReader(`{"rules":[{"dst_ip":"10.99.0.4","action":"drop"}]}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.BatchCreate(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["sync"]; !ok {
		t.Fatal("sync field must be always-present in BatchCreate response (B-2)")
	}
}

// rev9 codex round 7 P3: round out B-2 always-present handler-level coverage
// for the remaining mutation entry points (BatchDelete + Whitelist mutations).
// These prevent future refactors from accidentally bypassing syncToResponse().

// rev9 codex round 8 P3: empty BatchDelete must still emit `sync` (B-2
// always-present contract). RuleService.BatchDelete returns an empty
// SyncResult{} instead of nil for empty ids.
func TestRulesHandler_EmptyBatchDeleteResponse_AlwaysIncludesSync(t *testing.T) {
	h, cleanup := newTestRulesHandler(t)
	defer cleanup()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("DELETE", "/api/v1/rules/batch",
		strings.NewReader(`{"ids":[]}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.BatchDelete(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty batch, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["sync"]; !ok {
		t.Fatal("sync field must be always-present in empty BatchDelete response (B-2 / rev9 P3)")
	}
}

func TestRulesHandler_BatchDeleteResponse_AlwaysIncludesSync(t *testing.T) {
	h, cleanup := newTestRulesHandler(t)
	defer cleanup()

	// Create one rule so BatchDelete has something to delete (and SyncResult
	// gets exercised).
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/api/v1/rules",
		strings.NewReader(`{"dst_ip":"10.99.0.50","action":"drop"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Create(c)
	var createResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResp)
	id := createResp["rule"].(map[string]interface{})["id"].(string)

	// BatchDelete
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	body := `{"ids":["` + id + `"]}`
	c.Request, _ = http.NewRequest("DELETE", "/api/v1/rules/batch",
		strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.BatchDelete(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["sync"]; !ok {
		t.Fatal("sync field must be always-present in BatchDelete response (B-2)")
	}
}

// ---- Whitelist handler tests ----

func newTestWhitelistHandler(t *testing.T) (*WhitelistHandler, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := repository.NewSQLiteDB(dbPath)
	if err != nil {
		t.Fatalf("open DB: %v", err)
	}
	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}
	ruleRepo := repository.NewSQLiteRuleRepo(db)
	wlRepo := repository.NewSQLiteWhitelistRepo(db)
	syncLogRepo := repository.NewSQLiteSyncLogRepo(db)
	syncSvc := service.NewSyncService(fakeNodeProvider{}, syncLogRepo, ruleRepo, wlRepo, nil, 1, 0, time.Millisecond)
	wlSvc := service.NewWhitelistService(wlRepo, syncSvc)
	return NewWhitelistHandler(wlSvc), cleanup
}

func TestWhitelistHandler_CreateResponse_AlwaysIncludesSync(t *testing.T) {
	h, cleanup := newTestWhitelistHandler(t)
	defer cleanup()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/api/v1/whitelist",
		strings.NewReader(`{"src_ip":"10.99.0.60"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Create(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := resp["sync"]; !ok {
		t.Fatal("sync field must be always-present in Whitelist Create response (B-2)")
	}
}

func TestWhitelistHandler_DeleteResponse_AlwaysIncludesSync(t *testing.T) {
	h, cleanup := newTestWhitelistHandler(t)
	defer cleanup()

	// Create
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("POST", "/api/v1/whitelist",
		strings.NewReader(`{"src_ip":"10.99.0.61"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Create(c)
	var createResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &createResp)
	id := createResp["entry"].(map[string]interface{})["id"].(string)

	// Delete
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("DELETE", "/api/v1/whitelist/"+id, nil)
	c.Params = []gin.Param{{Key: "id", Value: id}}
	h.Delete(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["sync"]; !ok {
		t.Fatal("sync field must be always-present in Whitelist Delete response (B-2)")
	}
}
