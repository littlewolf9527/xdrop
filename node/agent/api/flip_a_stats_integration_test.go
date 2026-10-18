//go:build linux && integration

package api

import (
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"strings"
	"testing"
	"time"
)

type flipAPublicationGate struct {
	configPublishMap
	pause func(string)
	fail  bool
}

func (m flipAPublicationGate) Update(k, v interface{}, flags ebpf.MapUpdateFlags) error {
	m.pause("before")
	if m.fail {
		return fmt.Errorf("flipA selector failure")
	}
	err := m.configPublishMap.Update(k, v, flags)
	if err == nil {
		m.pause("selector")
	}
	return err
}

// 甲-4 / MA-6: distinct counts, bounded lock-free reads at the actual boundary,
// post-publication equality, pre-flip rollback and deferred-receipt persistence.
func TestFlipAStatsPublicationELF(t *testing.T) {
	for _, name := range []string{"atomic", "commit", "whitelist", "atomic-fail", "commit-fail", "whitelist-fail", "atomic-deferred", "commit-deferred"} {
		t.Run(name, func(t *testing.T) {
			h, router, _, _ := b7ELFCollection(t)
			a := cut55Rule("a", 1, "192.0.2.1")
			if _, err := h.DoAtomicSync([]Rule{a}); err != nil {
				t.Fatal(err)
			}
			old := h.getAgentState()
			want := old
			want.ActiveSlot = 1 - old.ActiveSlot
			kind := strings.Split(name, "-")[0]
			failed := strings.HasSuffix(name, "-fail")
			if kind == "whitelist" {
				want.WhitelistEntries = 2
			} else {
				want.RuleMapSelector = 1 - old.RuleMapSelector
				want.CIDRRules = 1
			}
			if old.ExactRules == want.ExactRules && old.CIDRRules == want.CIDRRules && old.WhitelistEntries == want.WhitelistEntries {
				t.Fatal("different-count publication guard")
			}
			read := func() AgentState {
				got := make(chan Stats, 1)
				go func() {
					w := jiaCall(t, router, "GET", "/api/v1/stats", "")
					var body Stats
					if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil {
						got <- Stats{}
						return
					}
					got <- body
				}()
				select {
				case body := <-got:
					if body.AgentState == nil || body.RulesCount != body.AgentState.ExactRules+body.AgentState.CIDRRules || body.WhitelistCount != body.AgentState.WhitelistEntries {
						t.Fatal("stats mixed top-level counts")
					}
					return *body.AgentState
				case <-time.After(200 * time.Millisecond):
					t.Fatal("stats blocked beyond 200 ms")
					return AgentState{}
				}
			}
			if read() != old {
				t.Fatal("initial snapshot")
			}
			stages, release := make(chan string, 3), make(chan struct{})
			t.Cleanup(func() { close(release); atomicStageTestHook = nil })
			pause := func(stage string) { stages <- stage; <-release }
			shadow, active, selector := h.configPublishTables()
			h.configPublishFixture = &configPublishTableSet{shadow, active, flipAPublicationGate{selector, pause, failed}}
			atomicStageTestHook = func(stage string, owner *Handlers) {
				if owner == h && stage == "flip" {
					pause("published")
				}
			}
			h.commitStageTestHook = func(stage string) {
				if stage == "c-7" {
					pause("published")
				}
			}
			if strings.HasSuffix(name, "-deferred") {
				h.quiescenceConfirmed = true
				h.quiescer = cut5ReceiptFunc(func() error { return fmt.Errorf("flipA deferred receipt") })
			}
			prefix := Rule{ID: "p", LogicalID: 2, SrcCIDR: "198.51.100.0/24", Action: "drop"}
			group := cut55Group(t, h, prefix, prefix)
			done := make(chan error, 1)
			go func() {
				var err error
				switch kind {
				case "atomic":
					_, err = h.DoAtomicSync([]Rule{a, prefix})
				case "commit":
					_, e := h.DoCommitRules([]CommitGroup{group})
					if e != nil {
						err = e
					}
				case "whitelist":
					err = h.DoWhitelistAtomicSync([]SyncWhitelistEntry{{ID: "w1", SrcIP: "203.0.113.1"}, {ID: "w2", SrcIP: "203.0.113.2"}})
				}
				done <- err
			}()
			observed := 0
			for {
				select {
				case stage := <-stages:
					observed++
					got := read()
					if got != old && got != want {
						t.Fatalf("mixed publication stage=%s got=%+v old=%+v want=%+v", stage, got, old, want)
					}
					if stage == "before" && got != old {
						t.Error("pre-flip snapshot changed")
					}
					if stage == "published" && got != want {
						t.Error("published snapshot remains old")
					}
					release <- struct{}{}
				case err := <-done:
					if (err != nil) != failed || observed == 0 {
						t.Fatalf("publication guard error=%v stages=%d", err, observed)
					}
					if failed {
						want = old
					}
					if got := read(); got != want {
						t.Fatalf("publication completed snapshot got=%+v want=%+v", got, want)
					}
					return
				case <-time.After(2 * time.Second):
					t.Fatal("writer did not reach publication boundary")
				}
			}
		})
	}
}
