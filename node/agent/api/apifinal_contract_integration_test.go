//go:build linux && integration

package api

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

func TestAPIFinalDefaultPagination(t *testing.T) {
	h, _ := jiaHandler(t)
	h.lastRuleDropCount = map[string]uint64{}
	h.lastRuleStatsTime = map[string]int64{}
	groups := []CommitGroup{}
	for i := 1; i <= 51; i++ {
		rule := cut55Rule(fmt.Sprintf("rule-%02d", i), uint32(700+i), fmt.Sprintf("10.7.0.%d", i))
		groups = append(groups, cut55Group(t, h, rule, rule))
	}
	cut55Commit(t, h, groups...)
	router := gin.New()
	router.GET("/rules", h.ListRules)
	var bodies []map[string]any
	for _, path := range []string{"/rules", "/rules?page=1", "/rules?page=2"} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		var b map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || w.Code != 200 {
			t.Fatalf("pagination: %v %d %s", err, w.Code, w.Body)
		}
		for _, row := range b["rules"].([]any) {
			delete(row.(map[string]any), "stats")
		}
		bodies = append(bodies, b)
	}
	if !reflect.DeepEqual(bodies[0], bodies[1]) || len(bodies[0]["rules"].([]any)) != 50 || len(bodies[2]["rules"].([]any)) != 1 {
		t.Fatal("default page differs", bodies)
	}
	if !reflect.DeepEqual(bodies[0]["pagination"], map[string]any{"page": float64(1), "limit": float64(50), "total": float64(51), "pages": float64(2)}) || bodies[0]["count"] != float64(51) {
		t.Fatal("pagination metadata", bodies[0])
	}
	if bodies[0]["rules"].([]any)[0].(map[string]any)["id"] != "rule-01" || bodies[2]["rules"].([]any)[0].(map[string]any)["id"] != "rule-51" {
		t.Fatal("pagination order")
	}
	t.Log("CLOSEOUT_PAGINATION total=51 default_rows=50 second_rows=1")
}

func TestAPIFinalHealthTransitions(t *testing.T) {
	for _, order := range []bool{false, true} {
		h, r := jiaHandler(t)
		p7Health(t, h, false, false)
		atomic, wl := false, false
		paths := []string{"/api/v1/sync/atomic", "/api/v1/sync/whitelist"}
		if order {
			paths[0], paths[1] = paths[1], paths[0]
		}
		for _, path := range paths {
			payload := `{"entries":[]}`
			if path == "/api/v1/sync/atomic" {
				payload = `{"rules":[]}`
				atomic = true
			} else {
				wl = true
			}
			if w := jiaCall(t, r, "POST", path, payload); w.Code != 200 {
				t.Fatalf("full sync guard %d %s", w.Code, w.Body)
			}
			p7Health(t, h, atomic, wl)
		}
		// Rejection after a successful full sync must not reset either flag.
		if w := jiaCall(t, r, "POST", "/api/v1/sync/atomic", `{"rules":[{"id":"bad","logical_id":0}]}`); w.Code == 0 {
			t.Fatal("missing response")
		}
		p7Health(t, h, true, true)
	}
	h, r := jiaHandler(t)
	w := jiaCall(t, r, "POST", "/api/v1/sync/atomic", `{"rules":[{"id":"invalid","logical_id":799,"src_ip":"bad","action":"drop"}]}`)
	var b map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || w.Code != 200 || b["failed"] != float64(1) {
		t.Fatalf("partial-rejection guard %d %s %v", w.Code, w.Body, err)
	}
	p7Health(t, h, true, false)
	// Concurrent handler completion and reads are also covered under -race in lab.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				jiaCall(t, r, "POST", "/api/v1/sync/atomic", `{"rules":[]}`)
			}
		}()
	}
	for i := 0; i < 16; i++ {
		p7Health(t, h, true, false)
	}
	wg.Wait()
	t.Log("CLOSEOUT_HEALTH cells=4 partial_rejected=1 sticky=1 concurrent=1")
}
