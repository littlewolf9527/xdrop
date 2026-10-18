//go:build linux && integration

package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/eval"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
	"golang.org/x/sys/unix"
)

func cut56Install(t *testing.T, h *Handlers, router *gin.Engine, entry string, r Rule) {
	t.Helper()
	if entry == "full" {
		w := cut53Request(t, router, "POST", "/api/v1/sync/atomic", map[string]any{"rules": []Rule{r}})
		if w.Code != 200 {
			t.Fatalf("CUT56_FULL_ACCEPT anomaly rate_limit rejected: %d %s", w.Code, w.Body.String())
		}
		b := cut56Body(t, w, 200, "")
		if b["success"] != true || b["added"] != float64(1) || b["failed"] != float64(0) {
			t.Fatalf("CUT56_FULL_ACCEPT body=%v", b)
		}
	} else {
		w := cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, r, r)})
		if w.Code != 200 {
			t.Fatalf("CUT56_COMMIT_ACCEPT anomaly rate_limit rejected: %d %s", w.Code, w.Body.String())
		}
		cut56Body(t, w, 200, "committed")
	}
}

func TestCut56EntryAndReadbackELF(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		for _, entry := range []string{"full", "commit"} {
			t.Run(fmt.Sprintf("cidr=%v/%s", isCIDR, entry), func(t *testing.T) {
				h, router, _ := b7ELF(t)
				cut55KernelReceipt(t, h)
				r := cut56Rule(isCIDR)
				cut56Install(t, h, router, entry, r)
				// Full-sync goldens are expected contract bytes; verify the real API response.
				if entry == "full" {
					w := cut53Request(t, router, "POST", "/api/v1/sync/atomic", map[string]any{"rules": []Rule{r}})
					cut56Body(t, w, 200, "")
					cut53P3Golden(t, "anomaly_full_p8", fmt.Sprintf("cidr=%v", isCIDR), w)
				}
				cut55KernelMirror(t, h)
				kind, cond := mirrorExact, mirrorCondition
				var key []byte
				if isCIDR {
					kind, cond = mirrorCIDR, mirrorCIDRCondition
					key = cidrRuleKeyToBytes(h.cidrRules[r.ID].Key)
				} else {
					key = ruleKeyToBytes(h.rules[r.ID].Key)
				}
				for side := 0; side < 2; side++ {
					tables := h.ruleTablesAt(side)
					raw, err := tables[cond].LookupBytes(key)
					if err != nil {
						t.Fatal(err)
					}
					var row ConditionValue
					if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &row); err != nil {
						t.Fatal(err)
					}
					cut56Row(t, row, r)
					value, err := tables[kind].LookupBytes(key)
					if err != nil || len(value) != 32 || value[28] != RuleHasConditions {
						t.Fatalf("CUT56_ROW kernel rule flag must be 1: %x err=%v", value, err)
					}
					if value[1] != 0 || value[2] != 0 || value[3] != 0 || binary.LittleEndian.Uint32(value[24:28]) != 0 {
						t.Fatalf("CUT56_ROW legacy predicates must be zero: %x", value)
					}
				}
				for _, m := range []*ebpf.Map{h.configA, h.configB} {
					var count uint64
					if err := m.Lookup(uint32(ConfigAnomalyRuleCount), &count); err != nil || count != 0 {
						t.Fatalf("CUT56_K16 kernel count=%d err=%v", count, err)
					}
				}
				stored, ok := h.storedGroupRule(r.ID)
				if !ok || stored.Action != r.Action || stored.RateLimit != r.RateLimit || stored.LogicalID != r.LogicalID || stored.MatchAnomaly != r.MatchAnomaly {
					t.Fatalf("CUT56_ROW stored=%+v exists=%v", stored, ok)
				}
				t.Logf("CUT56_ENTRY_ELF cidr=%v entry=%s accepted=1 sides=2 action=2 rate=7 logical_id=5617 flag=1 k16=0", isCIDR, entry)
			})
		}
	}
}

func cut56Packet(flags, anomaly bool) []byte {
	p := cut53Packet([4]byte{192, 0, 2, 1}, 64)
	if !flags {
		p[47] = 16
	}
	if anomaly {
		binary.BigEndian.PutUint16(p[16:18], 60)
	}
	return p
}

func TestCut56ANDTruthTableELF(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		for _, entry := range []string{"full", "commit"} {
			t.Run(fmt.Sprintf("cidr=%v/%s", isCIDR, entry), func(t *testing.T) {
				h, router, p := b7ELF(t)
				cut55KernelReceipt(t, h)
				r := cut56Rule(isCIDR)
				r.Action, r.RateLimit, r.TcpFlags = "drop", 0, "SYN"
				cut56Install(t, h, router, entry, r)
				tables := cut53EvalTables(t)
				intent := cut53Oracle(t, tables, []Rule{r})
				for _, flags := range []bool{true, false} {
					for _, anomaly := range []bool{true, false} {
						attrs := eval.B1Packet{Packet: eval.Packet{Tuple: eval.Tuple{Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("10.1.0.1"), Sport: 12345, Dport: 80, Proto: 6}, Length: 40, Flags: 2}, TTL: 64}
						if !flags {
							attrs.Flags = 16
						}
						if anomaly {
							attrs.Anomaly, attrs.Length = 4, 60
						}
						prediction, err := eval.EvaluateB1Cut54(tables, intent, attrs)
						hit := flags && anomaly
						if err != nil || (prediction.RuleID == r.ID) != hit {
							t.Fatalf("CUT56_AND oracle flags=%v anomaly=%v decision=%+v err=%v", flags, anomaly, prediction, err)
						}
						before, err := ReadLogicalRuleCounters(h.idCounts, r.LogicalID)
						if err != nil {
							t.Fatal(err)
						}
						got, _, err := p.Test(cut56Packet(flags, anomaly))
						want := uint32(2)
						if hit {
							want = 1
						}
						if err != nil || got != want {
							t.Fatalf("CUT56_AND flags=%v anomaly=%v verdict=%d want=%d err=%v", flags, anomaly, got, want, err)
						}
						after, err := ReadLogicalRuleCounters(h.idCounts, r.LogicalID)
						if err != nil {
							t.Fatal(err)
						}
						delta := uint64(0)
						if hit {
							delta = 1
						}
						if after.Match-before.Match != delta || after.Drop-before.Drop != delta {
							t.Fatalf("CUT56_AND flags=%v anomaly=%v counter_delta=%d/%d want=%d", flags, anomaly, after.Match-before.Match, after.Drop-before.Drop, delta)
						}
						t.Logf("CUT56_AND_ELF cidr=%v entry=%s flags=%v anomaly=%v hit=%v verdict=%d counter_delta=%d", isCIDR, entry, flags, anomaly, hit, got, delta)
					}
				}
			})
		}
	}
}

func TestCut56RateELF(t *testing.T) {
	var available unix.CPUSet
	if err := unix.SchedGetaffinity(0, &available); err != nil {
		t.Fatal(err)
	}
	possible, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	var cpus []int
	for cpu := 0; cpu < possible && cpu < 1024 && len(cpus) < 2; cpu++ {
		if available.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) == 0 {
		t.Fatal("CUT56_RATE no available CPU")
	}
	// A large explicit TD-074 divisor gives capacity=1 and a 585-second refill
	// interval at rate=7. The cold PASS and next-packet DROP remain real packet runs.
	const divisor uint64 = 4096
	for _, isCIDR := range []bool{false, true} {
		for _, entry := range []string{"full", "commit"} {
			t.Run(fmt.Sprintf("cidr=%v/%s", isCIDR, entry), func(t *testing.T) {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				defer func() {
					if err := unix.SchedSetaffinity(0, &available); err != nil {
						t.Error(err)
					}
				}()
				h, router, p := b7ELF(t)
				cut55KernelReceipt(t, h)
				for _, m := range []*ebpf.Map{h.configA, h.configB} {
					if err := m.Put(uint32(ConfigRLCPUDivisor), divisor); err != nil {
						t.Fatal(err)
					}
				}
				observations := map[string][]uint64{}
				for _, variant := range []string{"anomaly", "ttl"} {
					r := cut56Rule(isCIDR)
					if variant == "ttl" {
						r.ID = "ttl"
						r.LogicalID++
						r.MatchAnomaly = 0
						r.TTL = cut4BString("64")
					}
					cut56Install(t, h, router, entry, r)
					var configured uint64
					if err := h.activeMap().Lookup(uint32(ConfigRLCPUDivisor), &configured); err != nil || configured != divisor {
						t.Fatalf("CUT56_RATE divisor=%d err=%v", configured, err)
					}
					total := uint64(0)
					var prior []ratelimit.State
					for _, cpu := range cpus {
						var one unix.CPUSet
						one.Set(cpu)
						if err := unix.SchedSetaffinity(0, &one); err != nil {
							t.Fatal(err)
						}
						before, err := ReadLogicalRuleCounters(h.idCounts, r.LogicalID)
						if err != nil {
							t.Fatal(err)
						}
						got, _, err := p.Test(cut56Packet(true, variant == "anomaly"))
						if err != nil || got != 2 {
							t.Fatalf("CUT56_RATE cold bucket first packet must PASS: cidr=%v entry=%s variant=%s cpu=%d verdict=%d err=%v", isCIDR, entry, variant, cpu, got, err)
						}
						buckets := make([]ratelimit.State, possible)
						if err := h.idRLStates.Lookup(r.LogicalID, &buckets); err != nil {
							t.Fatalf("CUT56_RATE logical bucket key missing: id_rl_states[%d]: %v", r.LogicalID, err)
						}
						want := ratelimit.ModelCapacity(r.RateLimit, divisor) - 1
						if buckets[cpu].LastUpdate == 0 || buckets[cpu].Tokens != want {
							t.Fatalf("CUT56_RATE cold tokens=%d initialized=%v want=%d cpu=%d", buckets[cpu].Tokens, buckets[cpu].LastUpdate != 0, want, cpu)
						}
						for other, v := range buckets {
							if other == cpu {
								continue
							}
							expected := ratelimit.State{}
							if prior != nil {
								expected = prior[other]
							}
							if v != expected {
								t.Fatalf("CUT56_RATE CPU buckets not independent: cpu=%d other=%d got=%+v want=%+v", cpu, other, v, expected)
							}
						}
						sent := uint64(1)
						drops := uint64(0)
						for i := 0; i < 64; i++ {
							verdict, _, err := p.Test(cut56Packet(true, variant == "anomaly"))
							if err != nil {
								t.Fatal(err)
							}
							sent++
							if verdict == 1 {
								drops++
								break
							}
							if verdict != 2 {
								t.Fatalf("CUT56_RATE invalid verdict=%d", verdict)
							}
						}
						if drops != 1 {
							t.Fatal("CUT56_RATE same CPU exhaustion must DROP")
						}
						after, err := ReadLogicalRuleCounters(h.idCounts, r.LogicalID)
						if err != nil {
							t.Fatal(err)
						}
						if after.Match-before.Match != sent || after.Drop-before.Drop != drops {
							t.Fatalf("CUT56_RATE id_counts logical match delta=%d drop delta=%d want=%d/%d", after.Match-before.Match, after.Drop-before.Drop, sent, drops)
						}
						if err := h.idRLStates.Lookup(r.LogicalID, &buckets); err != nil {
							t.Fatal(err)
						}
						if buckets[cpu].Tokens != 0 {
							t.Fatalf("CUT56_RATE exhausted tokens=%d want=0", buckets[cpu].Tokens)
						}
						observations[variant] = append(observations[variant], want, sent, drops, buckets[cpu].Tokens)
						prior = buckets
						total += sent
						t.Logf("CUT56_RATE_CPU cidr=%v entry=%s variant=%s cpu=%d cold_pass=1 cold_tokens=%d sent=%d drops=%d logical_bucket=1 exact_counts=1 independent=1", isCIDR, entry, variant, cpu, want, sent, drops)
					}
					counts, err := ReadLogicalRuleCounters(h.idCounts, r.LogicalID)
					if err != nil || counts.Match != total {
						t.Fatalf("CUT56_RATE total logical matches=%d want=%d err=%v", counts.Match, total, err)
					}
				}
				if !reflect.DeepEqual(observations["anomaly"], observations["ttl"]) {
					t.Fatalf("CUT56_RATE equivalent condition behavior differs: %v", observations)
				}
				t.Logf("CUT56_RATE_EQUIVALENCE cidr=%v entry=%s cpus=%d rate=7 divisor=4096 equal_tokens=1 equal_first=1 equal_exhaustion=1", isCIDR, entry, len(cpus))
			})
		}
	}
	t.Logf("CUT56_MULTI_CPU available_selected=%d possible=%d independent_witness=%v", len(cpus), possible, len(cpus) >= 2)
}
