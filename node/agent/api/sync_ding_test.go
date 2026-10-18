package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func dingAssertDuplicateID(t *testing.T, w *httptest.ResponseRecorder, id string, first, second int, debt bool) {
	t.Helper()
	var body struct {
		Code      string `json:"code"`
		Error     string `json:"error"`
		Conflicts []struct {
			ID    string `json:"id"`
			Index *int   `json:"index"`
		} `json:"conflicts"`
		Added             *int  `json:"added"`
		Failed            *int  `json:"failed"`
		WithdrawalPending *bool `json:"withdrawal_pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != 409 || body.Code != "duplicate_id" || body.Added == nil || *body.Added != 0 || body.Failed == nil || *body.Failed != 1 || body.WithdrawalPending != nil {
		t.Fatalf("duplicate ID response status=%d body=%s", w.Code, w.Body.String())
	}
	if len(body.Conflicts) != 2 {
		t.Fatalf("conflicts=%+v", body.Conflicts)
	}
	for i, index := range []int{first, second} {
		if body.Conflicts[i].ID != id || body.Conflicts[i].Index == nil || *body.Conflicts[i].Index != index {
			t.Fatalf("conflict[%d]=%+v want id=%q index=%d", i, body.Conflicts[i], id, index)
		}
		if !strings.Contains(body.Error, fmt.Sprintf("index %d", index)) {
			t.Fatal(body.Error)
		}
	}
	if !strings.Contains(body.Error, id) {
		t.Fatal(body.Error)
	}
}

func TestDingDuplicateIDPreflightWithoutBPF(t *testing.T) {
	for _, rules := range []string{
		`[{"id":"same","src_cidr":"10.12.0.0/24","action":"drop"},{"id":"same","src_cidr":"10.13.0.0/24","action":"drop"}]`,
		`[{"id":"same","src_ip":"192.0.2.1","action":"drop"},{"id":"same","src_cidr":"10.13.0.0/24","action":"drop"}]`,
		`[{"id":"","action":"drop"},{"id":"same","src_ip":"192.0.2.1","action":"drop"},{"id":"same","src_ip":"192.0.2.2","action":"drop"}]`,
	} {
		h := &Handlers{} // Every BPF map and the Manager are nil.
		r := gin.New()
		r.POST("/sync", h.AtomicSync)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/sync", strings.NewReader(`{"rules":`+rules+`}`)))
		first, second := 0, 1
		if strings.Contains(rules, `"id":""`) {
			first, second = 1, 2
		}
		dingAssertDuplicateID(t, w, "same", first, second, false)
	}
}

func TestDingEmptyIDsReachR0WithoutBPF(t *testing.T) {
	receipts := 0
	h := &Handlers{quiescer: cut5ReceiptFunc(func() error { receipts++; return fmt.Errorf("R0 witness") })}
	r := gin.New()
	r.POST("/sync", h.AtomicSync)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/sync", strings.NewReader(`{"rules":[{"id":"","src_ip":"10.93.0.1","logical_id":1,"action":"drop"},{"id":"","src_ip":"10.93.0.2","logical_id":2,"action":"drop"}]}`)))
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	_, obsolete := body["withdrawal_pending"]
	if w.Code != 500 || body["code"] != "quiescence_failed" || obsolete || receipts == 0 {
		t.Fatalf("empty IDs must reach R0: %d %s receipts=%d", w.Code, w.Body.String(), receipts)
	}
}

func TestDingRuleWriteEarlyResponses(t *testing.T) {
	for _, debt := range []bool{false, true} {
		for _, route := range []struct {
			method, path string
			status       int
		}{
			{"POST", "/sync/atomic", 400},
		} {
			t.Run(fmt.Sprintf("debt=%v/%s%s", debt, route.method, route.path), func(t *testing.T) {
				h := &Handlers{}
				if debt {
					h.cidrMgr, _ = cut53PendingManager(t)
				}
				r := gin.New()
				r.POST("/sync/atomic", h.AtomicSync)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader("{")))
				var body map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				_, ok := body["withdrawal_pending"]
				if w.Code != route.status || ok {
					t.Fatalf("early response status=%d body=%s want=%d/%v", w.Code, w.Body.String(), route.status, debt)
				}
			})
		}
	}
}
