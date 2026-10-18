//go:build linux && integration

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/bpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func b7ELF(t *testing.T) (*Handlers, *gin.Engine, *ebpf.Program) {
	h, r, p, _ := b7ELFCollection(t)
	return h, r, p
}

func b7ELFCollection(t *testing.T) (*Handlers, *gin.Engine, *ebpf.Program, *ebpf.Collection) {
	t.Helper()
	return prefixABCollection(t, nil)
}
func prefixABCollection(t *testing.T, configure func(*ebpf.CollectionSpec)) (*Handlers, *gin.Engine, *ebpf.Program, *ebpf.Collection) {
	t.Helper()
	path := os.Getenv("XDROP_BPF_ELF")
	if path == "" {
		path = "../../bpf/xdrop_main.elf"
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("ELF SHA256=%x", sha256.Sum256(raw))
	spec, e := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			t.Fatalf("unexpected pinning: %s", name)
		}
	}
	if configure != nil {
		configure(spec)
	}
	coll, e := ebpf.NewCollection(spec)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(coll.Close)
	h, r := jiaHandler(t)
	h.idCounts = coll.Maps["id_counts"]
	h.idRLStates = coll.Maps["id_rl_states"]
	h.condA, h.condB = coll.Maps["cond_a"], coll.Maps["cond_b"]
	h.cidrCondA, h.cidrCondB = coll.Maps["cidr_cond_a"], coll.Maps["cidr_cond_b"]
	h.blacklist = coll.Maps["blacklist"]
	h.blacklistB = coll.Maps["blacklist_b"]
	h.cidrBlacklist = coll.Maps["cidr_blacklist"]
	h.cidrBlacklistB = coll.Maps["cidr_blist_b"]
	h.configA = coll.Maps["config_a"]
	h.configB = coll.Maps["config_b"]
	h.activeConfig = coll.Maps["active_config"]
	h.condRowMissing = coll.Maps["cond_row_missing"]
	h.cidrMgr = cidr.NewManager(coll.Maps["sv4_cidr_trie"], coll.Maps["dv4_cidr_trie"], coll.Maps["sv6_cidr_trie"], coll.Maps["dv6_cidr_trie"], coll.Maps["sv4_cidr_trie_b"], coll.Maps["dv4_cidr_trie_b"], coll.Maps["sv6_cidr_trie_b"], coll.Maps["dv6_cidr_trie_b"])
	if e := h.initDynamicConfig(h.configA); e != nil {
		t.Fatal(e)
	}
	if e := h.initDynamicConfig(h.configB); e != nil {
		t.Fatal(e)
	}
	main := coll.Programs["xdp_firewall_main"]
	if main == nil || coll.Maps["prog_tail_map"] == nil {
		t.Fatal("ELF missing main packet program or tail map")
	}
	for _, name := range []string{"tail_stash", "rl_states", "cidr_rl_states"} {
		if coll.Maps[name] != nil {
			t.Fatalf("retired map remains: %s", name)
		}
	}
	if coll.Programs["xdp_anomaly_verify"] != nil {
		t.Fatal("retired anomaly program remains")
	}
	if err := bpf.ClearRetiredTailSlot(coll.Maps["prog_tail_map"]); err != nil {
		t.Fatal(err)
	}
	return h, r, main, coll
}
func b7Packet() []byte {
	p := make([]byte, 54)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14] = 0x45
	binary.BigEndian.PutUint16(p[16:18], 40)
	p[22] = 64
	p[23] = 6
	copy(p[26:30], []byte{10, 0, 0, 1})
	copy(p[30:34], []byte{10, 1, 0, 1})
	binary.BigEndian.PutUint16(p[34:36], 12345)
	binary.BigEndian.PutUint16(p[36:38], 80)
	p[46] = 0x40
	p[47] = 2 // Full TCP header, deliberately invalid doff=4.
	return p
}
func b7Verdict(t *testing.T, p *ebpf.Program, want uint32) {
	t.Helper()
	got, _, e := p.Test(b7Packet())
	if e != nil {
		t.Fatal(e)
	}
	if got != want {
		t.Fatalf("packet verdict=%d want=%d", got, want)
	}
}

// Each stream has one owner; the concurrent stream is read only after done.
type b7PacketCounts struct{ packets, drop, pass, other uint64 }

func (c *b7PacketCounts) record(verdict uint32) {
	c.packets++
	switch verdict {
	case 1:
		c.drop++
	case 2:
		c.pass++
	default:
		c.other++
	}
}

func TestB7ELFCounterContinuation(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprintf("cidr=%v", isCIDR), func(t *testing.T) {
			h, _, p := b7ELF(t)
			v := b7Rule(isCIDR)
			b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, v, v)}), 200, "committed")
			table, key, _ := b7Table(h, isCIDR)
			readCounters := func() (uint64, uint64) {
				t.Helper()
				wire := b7Read(t, table, key)
				if binary.LittleEndian.Uint32(wire[8:12]) != v.LogicalID || !bytes.Equal(wire[12:24], make([]byte, 12)) {
					t.Fatalf("ELF rule wire must contain logical ID and zero reserved bytes: id=%d wire=%x", v.LogicalID, wire)
				}
				counts, err := ReadLogicalRuleCounters(h.idCounts, v.LogicalID)
				if err != nil {
					t.Fatal(err)
				}
				return counts.Match, counts.Drop
			}
			// No userspace counter seeding: only the real ELF increments them.
			for i := 0; i < 7; i++ {
				b7Verdict(t, p, 1)
			}
			matchBefore, dropBefore := readCounters()
			if matchBefore != 7 || dropBefore != 7 {
				t.Fatalf("ELF did not produce initial counters: match=%d drop=%d", matchBefore, dropBefore)
			}
			v.PktLenMax = 0
			v.RateLimit = 100
			b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, v, v)}), 200, "committed")
			table, key, _ = b7Table(h, isCIDR)
			matchPut, dropPut := readCounters()
			for i := 0; i < 5; i++ {
				b7Verdict(t, p, 1)
			}
			matchAfter, dropAfter := readCounters()
			t.Logf("CUT54_B7_COUNTER_WIRE cidr=%v logical_id=%d reserved_zero=1 reads=4", isCIDR, v.LogicalID)
			t.Logf("ELF counters cidr=%v before_match=%d before_drop=%d after_put_match=%d after_put_drop=%d after_5_packets_match=%d after_5_packets_drop=%d", isCIDR, matchBefore, dropBefore, matchPut, dropPut, matchAfter, dropAfter)
			if matchPut != matchBefore || dropPut != dropBefore {
				t.Errorf("PUT reset ELF-generated counters: before=%d/%d after=%d/%d", matchBefore, dropBefore, matchPut, dropPut)
			}
			if matchAfter != matchBefore+5 || dropAfter != dropBefore+5 {
				t.Errorf("ELF counters did not continue from pre-PUT reading: before=%d/%d after=%d/%d", matchBefore, dropBefore, matchAfter, dropAfter)
			}
		})
	}
}

func TestB7ELFPublicationStage(t *testing.T) {
	h, r, p := b7ELF(t)
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprintf("cidr=%v", isCIDR), func(t *testing.T) {
			v := b7Rule(isCIDR)
			v.LogicalID = 17
			b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, v, v)}), 200, "committed")
			b7Verdict(t, p, 1)
			for _, toAnomaly := range []bool{true, false} {
				t.Run(fmt.Sprintf("toAnomaly=%v", toAnomaly), func(t *testing.T) {
					expectedBefore := uint64(0)
					if !toAnomaly {
						expectedBefore = 0
					}
					if readCfg(t, h.activeMap(), ConfigAnomalyRuleCount) != expectedBefore {
						t.Fatal("not first/last anomaly")
					}
					if toAnomaly {
						v.MatchAnomaly = AnomalyInvalid
					} else {
						v.MatchAnomaly = 0
					}
					if w := yiAtomicCall(t, r, []Rule{v}); w.Code != 200 {
						t.Fatal(w.Body.String())
					}
					b7Verdict(t, p, 1)
					t.Logf("full-sync predicate published; post-sync drop=1 pass=0")
				})
			}
			b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, v)}), 200, "committed")
			b7Verdict(t, p, 2)
		})
	}
}
