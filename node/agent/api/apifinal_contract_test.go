package api

import (
	"encoding/json"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func p7ActiveBlacklist(h *Handlers) *ebpf.Map {
	if h.activeRuleSlot.Load() == 0 {
		return h.blacklist
	}
	return h.blacklistB
}
func p7ActiveCIDR(h *Handlers) *ebpf.Map {
	if h.activeRuleSlot.Load() == 0 {
		return h.cidrBlacklist
	}
	return h.cidrBlacklistB
}
func p7ActiveWhitelist(h *Handlers) *ebpf.Map {
	if h.activeWLSlot == 0 {
		return h.whitelist
	}
	return h.whitelistB
}

func p7Health(t *testing.T, h *Handlers, rules, whitelist bool) {
	t.Helper()
	r := gin.New()
	r.GET("/health", h.Health)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"status": "degraded", "reason": "awaiting_full_sync", "rules_synced": rules, "whitelist_synced": whitelist}
	if rules && whitelist {
		want = map[string]any{"status": "healthy"}
	}
	if w.Code != 200 || !reflect.DeepEqual(got, want) {
		t.Fatalf("CLOSEOUT_HEALTH mismatch: HTTP=%d got=%v want=%v", w.Code, got, want)
	}
}

func TestAPIFinalCommitDoesNotRestorePolicy(t *testing.T) {
	f := cut55Memory(t)
	p7Health(t, f.h, false, false)
	rule := cut55Rule("p7", 701, "10.7.0.1")
	w := cut55HTTP(t, f.h, []CommitGroup{cut55Group(t, f.h, rule, rule)})
	if w.Code != 200 || len(f.h.rules) != 1 {
		t.Fatalf("legal commit guard: %d %s", w.Code, w.Body)
	}
	p7Health(t, f.h, false, false)
	t.Log("CLOSEOUT_HEALTH cell=commit rules_synced=0 whitelist_synced=0 legal_commit=1")
}

func TestAPIFinalI159aReceipt(t *testing.T) {
	f := cut55Memory(t)
	h := f.h
	a := cut55Rule("a", 701, "10.7.0.1")
	cut55Commit(t, h, cut55Group(t, h, a, a))
	calls := 0
	h.quiescer = cut5ReceiptFunc(func() error { calls++; return errors.New("P7 Rc failure") })
	retired := cut55Commit(t, h, cut55Group(t, h, a))
	if retired.Receipt != "deferred" || retired.Code != "committed" || !h.pendingLogicalIDs[701] || calls == 0 {
		t.Fatalf("real pending guard: %+v pending=%v calls=%d", retired, h.pendingLogicalIDs, calls)
	}
	before := h.logicalPaymentFailures
	calls = 0
	h.logicalStateCapacity = 1
	b := cut55Rule("b", 702, "10.7.0.2")
	_, err := h.DoCommitRules([]CommitGroup{cut55Group(t, h, b, b)})
	if err == nil || err.Code != "table_full" || h.logicalPaymentFailures <= before || calls == 0 || !h.pendingLogicalIDs[701] {
		t.Fatalf("CLOSEOUT_I159A err=%v failures=%d calls=%d pending=%v", err, h.logicalPaymentFailures-before, calls, h.pendingLogicalIDs)
	}
	t.Logf("CLOSEOUT_I159A pending=1 deferred=1 table_full=1 payment_failures=%d receipts=%d", h.logicalPaymentFailures-before, calls)
}

func TestAPIFinalHealthGoldens(t *testing.T) {
	for _, healthy := range []bool{false, true} {
		h := &Handlers{}
		h.rulesSynced.Store(healthy)
		h.whitelistSynced.Store(healthy)
		r := gin.New()
		r.GET("/health", h.Health)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
		shape := "degraded"
		if healthy {
			shape = "healthy"
		}
		path := "../testdata/sync-jia/health_" + shape + "_p7.json"
		actual := struct {
			Status int    `json:"status"`
			Body   string `json:"body"`
		}{w.Code, w.Body.String()}
		if os.Getenv("P7_WRITE_GOLDEN") == "1" {
			b, err := json.MarshalIndent(actual, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.Write(append(b, '\n'))
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := actual
		if err = json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		if actual != want {
			t.Fatalf("health golden %s: %+v != %+v", shape, actual, want)
		}
		p7Health(t, h, healthy, healthy)
	}
}

// Establish pending via an actual publication whose own Rc fails; R0 remains real.
func p7DeferredCommit(t *testing.T, h *Handlers, groups ...CommitGroup) CommitResult {
	t.Helper()
	receipt, hook := h.quiescer, h.commitStageTestHook
	inRc, finished, calls := false, false, 0
	h.commitStageTestHook = func(stage string) {
		if hook != nil {
			hook(stage)
		}
		if stage == "c-Rc" {
			inRc = true
		}
		if stage == "c-9" {
			finished = true
		}
	}
	h.quiescer = cut5ReceiptFunc(func() error {
		if inRc {
			calls++
			return errors.New("P7 deferred Rc fixture")
		}
		return receipt.Quiesce()
	})
	defer func() { h.quiescer = receipt; h.commitStageTestHook = hook }()
	result := cut55Commit(t, h, groups...)
	if result.Code != "committed" || result.Receipt != "deferred" || calls == 0 || finished {
		t.Fatalf("P7 deferred guard result=%+v calls=%d finished=%v", result, calls, finished)
	}
	return result
}
