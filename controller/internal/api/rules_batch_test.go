package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/internal/model"
)

// OPEN-P2-01 regression: batch create rejects oversize payloads.
func TestBatchCreate_RejectsOversize(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Stub handler — we only need to hit the MaxBatchSize guard; service is never called.
	// So we wire a real handler but rely on the payload being rejected before service.
	// Use a nil-accepting handler pattern: just call the MaxBatchSize check directly via full handler.
	// Simplest: construct a RulesHandler without services, since the size check runs first.
	h := &RulesHandler{} // svc is nil; we expect 413 before svc is touched.
	r.POST("/batch", h.BatchCreate)

	rules := make([]model.RuleRequest, MaxBatchSize+1)
	for i := range rules {
		rules[i] = model.RuleRequest{Action: "drop", SrcIP: fmt.Sprintf("10.0.0.%d", i%254+1)}
	}
	body, _ := json.Marshal(map[string]any{"rules": rules})

	req := httptest.NewRequest("POST", "/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("want 413, got %d; body=%s", w.Code, w.Body.String())
	}
}

// OPEN-P2-01 regression: batch delete rejects oversize payloads.
func TestBatchDelete_RejectsOversize(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &RulesHandler{}
	r.POST("/batch-delete", h.BatchDelete)

	ids := make([]string, MaxBatchSize+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("rule_%d", i)
	}
	body, _ := json.Marshal(map[string]any{"ids": ids})

	req := httptest.NewRequest("POST", "/batch-delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("want 413, got %d; body=%s", w.Code, w.Body.String())
	}
}
