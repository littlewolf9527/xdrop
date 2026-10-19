package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func hcB03Body(t *testing.T, w *httptest.ResponseRecorder, status int, keys ...string) map[string]json.RawMessage {
	t.Helper()
	if w.Code != status {
		t.Errorf("status=%d want=%d body=%s", w.Code, status, w.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if keys != nil {
		got := make([]string, 0, len(body))
		for key := range body {
			got = append(got, key)
		}
		sort.Strings(got)
		sort.Strings(keys)
		if !reflect.DeepEqual(got, keys) {
			t.Errorf("keys=%v want=%v", got, keys)
		}
	}
	return body
}

func hcB03String(t *testing.T, body map[string]json.RawMessage, key string) string {
	t.Helper()
	var value string
	if err := json.Unmarshal(body[key], &value); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return value
}

func hcB03Counts(t *testing.T, body map[string]json.RawMessage) {
	t.Helper()
	if string(body["added"]) != "0" || string(body["failed"]) != "1" {
		t.Errorf("added=%s failed=%s want=0/1", body["added"], body["failed"])
	}
}

type hcB03RowCase struct {
	name        string
	kind        int
	cidr, plain bool
}

func hcB03Rows() []hcB03RowCase {
	return []hcB03RowCase{
		{"exact_condition", mirrorCondition, false, false},
		{"exact_rule", mirrorExact, false, false},
		{"cidr_condition", mirrorCIDRCondition, true, false},
		{"cidr_rule", mirrorCIDR, true, false},
		{"plain_exact_rule", mirrorExact, false, true},
		{"plain_cidr_rule", mirrorCIDR, true, true},
	}
}

func hcB03Seed(t *testing.T) *cut55Fixture {
	t.Helper()
	f := cut55Memory(t)
	exact := cut55Rule("old-exact", 91, "198.51.100.9")
	cidr := Rule{ID: "old-cidr", LogicalID: 92, SrcCIDR: "203.0.113.0/24", Protocol: "tcp", Action: "drop"}
	cut55Commit(t, f.h, cut55Group(t, f.h, exact, exact), cut55Group(t, f.h, cidr, cidr))
	return f
}

func hcB03Unchanged(t *testing.T, f *cut55Fixture) func() {
	t.Helper()
	slot := int(f.h.activeRuleSlot.Load())
	tables, state := cut55Snapshot(f, slot), cut53State(f.h)
	return func() {
		t.Helper()
		if int(f.h.activeRuleSlot.Load()) != slot || cut55Snapshot(f, slot) != tables || cut53State(f.h) != state {
			t.Error("failed atomic changed active tables, selector, or memory state")
		}
	}
}

func hcB03Request(t *testing.T, f *cut55Fixture, rules ...Rule) *httptest.ResponseRecorder {
	t.Helper()
	return cut53Request(t, cut53MemoryRouter(f.h), "POST", "/atomic", map[string]any{"rules": rules})
}

func TestHCB03G1WriteFailure(t *testing.T) {
	for _, tc := range hcB03Rows() {
		t.Run(tc.name, func(t *testing.T) {
			f := hcB03Seed(t)
			defer hcB03Unchanged(t, f)()
			r := cut53Pure(tc.cidr, "r", 1)
			if !tc.plain {
				ttl := "64"
				r.TTL = &ttl
			}
			shadow := 1 - int(f.h.activeRuleSlot.Load())
			f.tables[shadow][tc.kind].updateErr = fmt.Errorf("update: %w", syscall.EPERM)
			body := hcB03Body(t, hcB03Request(t, f, r), 500, "added", "error", "failed")
			hcB03Counts(t, body)
			message := hcB03String(t, body, "error")
			if !strings.Contains(message, "write shadow") || (tc.kind >= mirrorCondition && !strings.Contains(message, "condition")) {
				t.Errorf("write failure diagnostic=%q", message)
			}
		})
	}
}

func TestHCB03G2TableFull(t *testing.T) {
	for _, tc := range hcB03Rows() {
		t.Run(tc.name, func(t *testing.T) {
			f := hcB03Seed(t)
			defer hcB03Unchanged(t, f)()
			r := cut53Pure(tc.cidr, "r", 1)
			if !tc.plain {
				ttl := "64"
				r.TTL = &ttl
			}
			shadow := 1 - int(f.h.activeRuleSlot.Load())
			f.tables[shadow][tc.kind].updateErr = fmt.Errorf("update: key too big for map: %w", syscall.E2BIG)
			body := hcB03Body(t, hcB03Request(t, f, r), 409, "added", "code", "error", "failed")
			hcB03Counts(t, body)
			if hcB03String(t, body, "code") != "table_full" || !strings.HasPrefix(hcB03String(t, body, "error"), "table_full: write shadow") {
				t.Errorf("table_full diagnostic=%s", body)
			}
		})
	}
	for _, name := range []string{"enomem", "config_e2big"} {
		t.Run(name, func(t *testing.T) {
			f := hcB03Seed(t)
			defer hcB03Unchanged(t, f)()
			shadow := 1 - int(f.h.activeRuleSlot.Load())
			if name == "enomem" {
				f.tables[shadow][mirrorExact].updateErr = syscall.ENOMEM
			} else {
				f.configs[shadow].updateErr = fmt.Errorf("update: key too big for map: %w", syscall.E2BIG)
			}
			body := hcB03Body(t, hcB03Request(t, f, cut53Pure(false, "r", 1)), 500, "added", "error", "failed")
			message := hcB03String(t, body, "error")
			if name == "config_e2big" && !strings.Contains(message, "copy shadow config") {
				t.Errorf("did not reach config write: %s", message)
			}
		})
	}
	t.Run("selector_e2big", func(t *testing.T) {
		f := hcB03Seed(t)
		defer hcB03Unchanged(t, f)()
		f.selector.updateErr = fmt.Errorf("update: key too big for map: %w", syscall.E2BIG)
		body := hcB03Body(t, hcB03Request(t, f, cut53Pure(false, "r", 1)), 500, "added", "error", "failed")
		message := hcB03String(t, body, "error")
		if !strings.Contains(message, "failed to flip config selector:") {
			t.Errorf("did not reach selector write: %s", message)
		}
	})
}

func hcB03Writes(f *cut55Fixture) [11]int {
	var writes [11]int
	for slot := range f.tables {
		for kind, table := range f.tables[slot] {
			writes[slot*4+kind] = table.writes
		}
		writes[8+slot] = f.configs[slot].writes
	}
	writes[10] = f.selector.writes
	return writes
}

func TestHCB03G3Preflight(t *testing.T) {
	for _, name := range []string{"zero_rate", "missing_logical_id"} {
		t.Run(name, func(t *testing.T) {
			f := hcB03Seed(t)
			a, b := cut53Pure(false, "a", 1), cut53Pure(false, "b", 2)
			wantReason := "rate_limit must be > 0 for rate_limit action"
			if name == "zero_rate" {
				b.Action, b.RateLimit = "rate_limit", 0
			} else {
				a.LogicalID, b.LogicalID = 0, 0
				wantReason = "missing/duplicate logical_id 0"
			}
			before := hcB03Writes(f)
			body := hcB03Body(t, hcB03Request(t, f, a, b), 409)
			if hcB03String(t, body, "code") != "condition_group_invalid" {
				t.Errorf("preflight code=%s", body["code"])
			}
			var conflicts []atomicConditionConflict
			if err := json.Unmarshal(body["conflicts"], &conflicts); err != nil {
				t.Fatal(err)
			}
			if len(conflicts) != 2 || conflicts[1].ID != "b" || conflicts[1].Reason != wantReason {
				t.Errorf("conflicts=%+v want member b reason=%q and 2 members", conflicts, wantReason)
			}
			if after := hcB03Writes(f); after != before {
				t.Errorf("preflight wrote tables: before=%v after=%v", before, after)
			}
		})
	}
}

func TestHCB03G5FailedCount(t *testing.T) {
	t.Run("r0", func(t *testing.T) {
		f := cut55Memory(t)
		calls := 0
		f.h.quiescer = cut53Receipt(func() error { calls++; return fmt.Errorf("R0 fixture failure") })
		body := hcB03Body(t, hcB03Request(t, f, cut53Pure(false, "r", 1)), 500, "added", "code", "error", "failed")
		hcB03Counts(t, body)
		if hcB03String(t, body, "code") != "quiescence_failed" || calls != 3 {
			t.Errorf("R0 code=%s calls=%d", body["code"], calls)
		}
		if !strings.Contains(hcB03String(t, body, "error"), "quiescence failed after 3 attempts: R0 fixture failure") {
			t.Errorf("R0 diagnostic=%s", body["error"])
		}
	})
	t.Run("duplicate_id", func(t *testing.T) {
		f := cut55Memory(t)
		r := cut53Pure(false, "r", 1)
		body := hcB03Body(t, hcB03Request(t, f, r, r), 409)
		hcB03Counts(t, body)
		if hcB03String(t, body, "code") != "duplicate_id" {
			t.Errorf("duplicate code=%s", body["code"])
		}
	})
}
