//go:build linux && integration

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// B1 cut 5-4 positive witness: flag-zero rules use logical state; deletion
// retires ownership and only receipt-backed payment reclaims the bucket.
func TestB1LegacyTupleBucketELF(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		for _, batch := range []bool{false} {
			t.Run(fmt.Sprintf("cidr=%v/batch=%v", isCIDR, batch), func(t *testing.T) {
				h, r, p := b7ELF(t)
				rule := b7Rule(isCIDR)
				rule.Action = "rate_limit"
				rule.RateLimit = 17
				b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, rule, rule)}), 200, "committed")
				if err := h.activeMap().Put(uint32(ConfigRLCPUDivisor), uint64(1)); err != nil {
					t.Fatal(err)
				}
				rules, key, bucket := b7Table(h, isCIDR)
				packet := b7Packet()
				packet[46] = 0x50
				if got, _, err := p.Test(packet); err != nil || got != 2 {
					t.Fatalf("B1_LEGACY cold verdict=%d err=%v", got, err)
				}
				var values []struct{ Tokens, Last uint64 }
				if err := bucket.Lookup(rule.LogicalID, &values); err != nil {
					t.Fatal(err)
				}
				seen := 0
				for _, v := range values {
					if v.Last != 0 {
						seen++
						if v.Tokens != 33 {
							t.Fatalf("B1_LEGACY tuple tokens=%d want=33", v.Tokens)
						}
					}
				}
				if seen != 1 {
					t.Fatalf("B1_LEGACY initialized CPUs=%d", seen)
				}
				// Reusing an existing zero-timestamp row must take the old initialization
				// path, without inserting a different tuple or a logical-ID bucket.
				for i := range values {
					values[i].Tokens = 999
					values[i].Last = 0
				}
				if err := bucket.Put(rule.LogicalID, values); err != nil {
					t.Fatal(err)
				}
				// Repeat > 1 may replay map side effects after EINTR; consume the
				// 34-token burst one packet at a time, then check the final DROP.
				var got uint32
				var err error
				b1LegacyRunPinned(t, func() {
					for i := 0; i < 35; i++ {
						got, err = p.Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
						want := uint32(2)
						if i == 34 {
							want = 1
						}
						if err != nil || got != want {
							t.Fatalf("B1_LEGACY packet=%d/35 verdict=%d want=%d err=%v", i+1, got, want, err)
						}
					}
				})
				if err != nil || got != 1 {
					t.Fatalf("B1_LEGACY exhausted verdict=%d err=%v", got, err)
				}
				var counter RuleValue
				if err := rules.Lookup(key, &counter); err != nil {
					t.Fatal(err)
				}
				if counter.LogicalID != rule.LogicalID || counter.Pad2[0] != 0 {
					t.Fatalf("flag-zero logical row=%+v", counter)
				}
				match, drop := h.logicalCounters(rule.LogicalID)
				if match != 36 || drop != 1 {
					t.Fatalf("B1_LOGICAL match/drop=%d/%d want=36/1", match, drop)
				}
				for _, path := range []string{"/api/v1/rules", "/api/v1/rules?page=1&limit=10"} {
					w := jiaCall(t, r, "GET", path, "")
					var reply struct {
						Rules []struct {
							ID    string `json:"id"`
							Stats struct {
								Match uint64 `json:"match_count"`
								Drop  uint64 `json:"drop_count"`
							} `json:"stats"`
						} `json:"rules"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
						t.Fatal(err)
					}
					if w.Code != 200 || len(reply.Rules) != 1 || reply.Rules[0].ID != "r" || reply.Rules[0].Stats.Match != 36 || reply.Rules[0].Stats.Drop != 1 {
						t.Fatalf("B1_LEGACY ListRules %s code=%d body=%s", path, w.Code, w.Body.String())
					}
				}
				p7DeferredCommit(t, h, cut55Group(t, h, rule))
				if err := bucket.Lookup(rule.LogicalID, &values); err != nil || !h.pendingLogicalIDs[rule.LogicalID] {
					t.Fatalf("delete must retain logical bucket and debt: pending=%v err=%v", h.pendingLogicalIDs, err)
				}
				h.syncMu.Lock()
				h.publishMu.Lock()
				h.rulesMu.Lock()
				paidErr := h.payPendingLogicalLocked()
				h.rulesMu.Unlock()
				h.publishMu.Unlock()
				h.syncMu.Unlock()
				if paidErr != nil {
					t.Fatal(paidErr)
				}
				if err := bucket.Lookup(rule.LogicalID, &values); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("paid logical bucket remains: %v", err)
				}
				var counts []LogicalRuleCounters
				if err := h.idCounts.Lookup(rule.LogicalID, &counts); !errors.Is(err, ebpf.ErrKeyNotExist) || h.pendingLogicalIDs[rule.LogicalID] {
					t.Fatalf("paid logical counters/debt remain: %v", err)
				}

				t.Logf("B1_LEGACY cidr=%v batch=%v packets=36 logical_lookup=PASS deletion_retained=PASS payment=PASS counter_readback=36/1", isCIDR, batch)
			})
		}
	}
}

// Pin the whole packet sequence; deferred restoration also runs on Fatalf.
func b1LegacyRunPinned(t *testing.T, run func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var cpus unix.CPUSet
	if err := unix.SchedGetaffinity(0, &cpus); err != nil {
		t.Fatal(err)
	}
	cpu := 0
	for !cpus.IsSet(cpu) {
		cpu++
	}
	var one unix.CPUSet
	one.Set(cpu)
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.SchedSetaffinity(0, &cpus); err != nil {
			t.Error(err)
		}
	}()
	run()
}
