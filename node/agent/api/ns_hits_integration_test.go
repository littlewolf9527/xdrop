//go:build linux && integration

package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"golang.org/x/sys/unix"
)

func TestNSHitsPackets(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(os.Getenv("XDROP_BPF_ELF"))
	nsScaleCheck(t, err)
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	coll, err := ebpf.NewCollection(spec)
	nsScaleCheck(t, err)
	defer coll.Close()
	nsScaleCheck(t, coll.Maps["config_a"].Put(uint32(0), uint64(1)))
	nsScaleCheck(t, coll.Maps["config_a"].Put(uint32(2), uint64(1<<16)))
	key := make([]byte, 40)
	binary.BigEndian.PutUint16(key[34:], 80)
	key[36] = 6
	nsScaleCheck(t, coll.Maps["blacklist"].Put(key, RuleValue{LogicalID: 71, Action: ActionDrop}))
	h := &Handlers{idCounts: coll.Maps["id_counts"], logicalOwners: map[uint32]string{71: "packet-rule"}}
	h.SetHits(coll.Maps["hot_ids"], 20)
	packet := make([]byte, 94)
	binary.BigEndian.PutUint16(packet[12:], 0x0800)
	packet[14], packet[22], packet[23], packet[46], packet[47] = 0x45, 64, 6, 0x50, 2
	binary.BigEndian.PutUint16(packet[16:], 80)
	binary.BigEndian.PutUint16(packet[36:], 80)
	copy(packet[26:34], []byte{10, 0, 0, 1, 10, 1, 0, 1})
	before, err := hitsClock()
	nsScaleCheck(t, err)
	for i := 0; i < 3; i++ {
		verdict, err := coll.Programs["xdp_firewall_main"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
		nsScaleCheck(t, err)
		if verdict != 1 {
			t.Fatalf("NS_CELL class=behavior name=hits_packet_verdict got=%d pass=false", verdict)
		}
	}
	after, err := hitsClock()
	nsScaleCheck(t, err)
	for _, path := range []string{"cold", "hot"} {
		r := nsHitsRead(t, h, before)
		pass := len(r.Hits) == 1 && r.Hits[0].RuleID == "packet-rule" && r.Hits[0].MatchCount == 3 && r.Hits[0].DropCount == 3 && r.Hits[0].MatchBytes == 282 && r.Hits[0].DropBytes == 282 && r.Hits[0].LastHitNS >= before && r.Hits[0].LastHitNS <= after && !r.Truncated
		t.Logf("NS_CELL class=behavior name=hits_packet_window path=%s sent=3 scanned=%d returned=%d pass=%t", path, r.Scanned, len(r.Hits), pass)
		if !pass {
			t.Fatal(r)
		}
	}
}

func nsRealMap(t *testing.T, n uint32) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ns_counts", Type: ebpf.PerCPUHash, KeySize: 4, ValueSize: 40, MaxEntries: n, Flags: unix.BPF_F_NO_PREALLOC})
	if err != nil {
		t.Fatalf("NS_CELL class=apparatus pass=false map_error=%q", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func nsHotMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ns_hot", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 8, MaxEntries: 16384})
	nsScaleCheck(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func TestNSHitsRealMap(t *testing.T) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil || cpus < 2 {
		t.Fatalf("NS_CELL class=apparatus pass=false cpus=%d error=%v; rebuild fixture with >=2 possible CPUs", cpus, err)
	}
	h := &Handlers{idCounts: nsRealMap(t, 10004), logicalOwners: map[uint32]string{7: "rule-7"}}
	hot := nsHotMap(t)
	h.SetHits(hot, 20)
	values := make([]LogicalRuleCounters, cpus)
	now, err := hitsClock()
	if err != nil {
		t.Fatal(err)
	}
	values[0] = LogicalRuleCounters{Match: 2, Drop: 1, MatchBytes: 188, DropBytes: 94, LastHitNS: now - 2}
	values[1] = LogicalRuleCounters{Match: 3, Drop: 2, MatchBytes: 282, DropBytes: 188, LastHitNS: now}
	if err := h.idCounts.Put(uint32(7), values); err != nil {
		t.Fatal(err)
	}
	nsScaleCheck(t, hot.Put(uint32(7), now))
	var hotBack uint64
	nsScaleCheck(t, hot.Lookup(uint32(7), &hotBack))
	if hotBack != now {
		t.Fatal("NS_CELL class=apparatus pass=false hot_fixture_readback")
	}
	var back []LogicalRuleCounters
	if err := h.idCounts.Lookup(uint32(7), &back); err != nil || back[0] != values[0] || back[1] != values[1] {
		t.Fatal("NS_CELL class=apparatus pass=false CPU_fixture_readback", err)
	}
	for _, path := range []string{"cold", "hot", "expired"} {
		if path == "expired" {
			time.Sleep(2100 * time.Millisecond)
		}
		r := nsHitsRead(t, h, now-1)
		pass := len(r.Hits) == 1 && r.Hits[0].LogicalID == 7 && r.Hits[0].LastHitNS == now && r.Hits[0].MatchCount == 5 && r.Hits[0].DropCount == 3 && r.Hits[0].MatchBytes == 470 && r.Hits[0].DropBytes == 282 && !r.Truncated
		t.Logf("NS_CELL class=behavior name=max_cpu_time path=%s cpus=%d t_min=%d since_ns=%d t_max=%d scanned=%d returned=%d pass=%t", path, cpus, now-2, now-1, now, r.Scanned, len(r.Hits), pass)
		if !pass {
			t.Fatal(r)
		}
	}
	delete(h.logicalOwners, 7)
	if r := nsHitsRead(t, h, 0); len(r.Hits) != 0 {
		t.Fatal("cached retired ID returned")
	}
	// A physical rule and its owner use the same ID in ListRules and Hits.
	bl, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ns_rule", Type: ebpf.Hash, KeySize: 40, ValueSize: 32, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	h.blacklist = bl
	h.rules = map[string]StoredRule{"rule-7": {LogicalID: 7, Action: "drop"}}
	h.logicalOwners[7] = "rule-7"
	h.lastRuleDropCount = map[string]uint64{}
	h.lastRuleStatsTime = map[string]int64{}
	if err := bl.Put(RuleKey{}, RuleValue{LogicalID: 7, Action: ActionDrop}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/rules?limit=1000", nil)
	h.ListRules(c)
	var listed struct{ Rules []Rule }
	if json.Unmarshal(w.Body.Bytes(), &listed) != nil || len(listed.Rules) != 1 || listed.Rules[0].ID != nsHitsRead(t, h, 0).Hits[0].RuleID {
		t.Fatal("ListRules owner identity", w.Body.String())
	}
	clear(values)
	values[0] = LogicalRuleCounters{Match: 1, LastHitNS: now}
	for id := uint32(1); id <= 10003; id++ {
		values[0].Drop = uint64(id)
		if err := h.idCounts.Put(id, values); err != nil {
			t.Fatal(err)
		}
		nsScaleCheck(t, hot.Put(id, now))
		h.logicalOwners[id] = fmt.Sprint("rule-", id)
	}
	time.Sleep(2100 * time.Millisecond)
	r := nsHitsRead(t, h, 0)
	pass := r.Truncated && r.Scanned == 10003 && len(r.Hits) == 10000
	for i, v := range r.Hits {
		pass = pass && v.LogicalID == uint32(10003-i)
	}
	t.Logf("NS_CELL class=behavior name=retained_ID_set rows=%d returned=%d truncated=%t pass=%t", r.Scanned, len(r.Hits), r.Truncated, pass)
	if !pass {
		t.Fatal("wrong retained IDs")
	}
}
