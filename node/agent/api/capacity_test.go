package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

var capacityKeys = []string{"blacklist", "cidr_blacklist", "cond", "cidr_cond", "whitelist", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "logical_state"}

func capacityJSON(t *testing.T, stats Stats) string {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.JSON(200, stats)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	return w.Body.String()
}

func TestCapacityReport(t *testing.T) {
	t.Run("CR-shape", func(t *testing.T) {
		base := Stats{TotalPackets: 17, AgentState: &AgentState{ExactRules: 2}, XDPInfo: &XDPInfo{Mode: "traditional"}}
		old := capacityJSON(t, base)
		report := &CapacityReport{}
		var fields []string
		for i, entry := range report.entries() {
			entry.Limit, entry.Used = i+20, i+1
			fields = append(fields, fmt.Sprintf("%q:{\"limit\":%d,\"used\":%d}", capacityKeys[i], i+20, i+1))
		}
		base.Capacity = report
		got := capacityJSON(t, base)
		want := strings.TrimSuffix(old, "}") + ",\"capacity\":{" + strings.Join(fields, ",") + "}}"
		if got != want || strings.Index(got, "\"xdp_info\"") >= strings.Index(got, "\"capacity\"") {
			t.Fatalf("shape/order/prefix got=%s want=%s", got, want)
		}
		var body struct{ Capacity map[string]map[string]int }
		if err := json.Unmarshal([]byte(got), &body); err != nil || len(body.Capacity) != 10 {
			t.Fatalf("integer ten-key shape: %v %+v", err, body)
		}
		for _, key := range capacityKeys {
			if len(body.Capacity[key]) != 2 {
				t.Fatal("entry keys", key)
			}
		}
	})
	t.Run("CR-omit", func(t *testing.T) {
		if got := capacityJSON(t, Stats{}); strings.Contains(got, "\"capacity\"") {
			t.Fatal(got)
		}
	})
	t.Run("CR-init", func(t *testing.T) {
		h := &Handlers{}
		want := [10]int{500000, 500000, 500000, 500000, 50000, 50000, 50000, 50000, 50000, 1000000}
		for i, e := range h.initialCapacity().entries() {
			if e.Limit != want[i] || e.Used != 0 {
				t.Fatalf("%s=%+v", capacityKeys[i], e)
			}
		}
		if h.publishedCapacity.Load() != nil {
			t.Fatal("initial construction published unexpectedly")
		}
	})
	t.Run("CR-merge", func(t *testing.T) {
		h := &Handlers{}
		rows, prefixes := newAtomicTableRows(), cidr.TrieEntries{}
		for i := range rows {
			prefixes[i] = make(map[string]uint32)
			for n := 0; n <= i; n++ {
				rows[i][fmt.Sprint(n)] = []byte{1}
				prefixes[i][fmt.Sprint("prefix", n)] = uint32(n + 1)
			}
		}
		h.publishAtomicCapacity(rows, prefixes, 11)
		firstPointer := h.publishedCapacity.Load()
		first := *firstPointer
		if first.Whitelist != (CapacityEntry{50000, 0}) || first.LogicalState.Used != 11 {
			t.Fatal("nil publication base", first)
		}
		for i, e := range first.entries() {
			if i < 4 && e.Used != i+1 {
				t.Fatal("atomic rows", first)
			}
			if i >= 5 && i < 9 && e.Used != i-4 {
				t.Fatalf("atomic trie %s used=%d want=%d", capacityKeys[i], e.Used, i-4)
			}
		}
		h.publishWhitelistCapacity(7)
		secondPointer := h.publishedCapacity.Load()
		second := *secondPointer
		if secondPointer == firstPointer || *firstPointer != first {
			t.Fatal("immutable publication after whitelist", *firstPointer, first)
		}
		want := first
		want.Whitelist.Used = 7
		if second != want || *h.publishedCapacity.Load() == first {
			t.Fatal("whitelist changed unrelated fields", second, want)
		}
		h.logicalStateCapacity = 31
		h.publishCommitCapacity([4]int{8, 9, 10, 11}, prefixes, 17)
		thirdPointer := h.publishedCapacity.Load()
		third := *thirdPointer
		if thirdPointer == firstPointer || thirdPointer == secondPointer || *firstPointer != first || *secondPointer != second {
			t.Fatal("immutable publication after commit", *firstPointer, *secondPointer)
		}
		want = second
		want.LogicalState = CapacityEntry{31, 17}
		entries := want.entries()
		for i := 0; i < 4; i++ {
			entries[i].Used = 8 + i
			entries[5+i].Used = i + 1
		}
		if third != want {
			t.Fatal("commit merge", third, want)
		}
		if first.Whitelist.Used != 0 || second.LogicalState.Used != 11 {
			t.Fatal("old publications mutated")
		}
	})
}
