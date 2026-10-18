//go:build linux && integration

package api

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

func prefixABRule(n int) Rule {
	return Rule{ID: fmt.Sprint("ab", n), LogicalID: uint32(9300 + n), SrcCIDR: fmt.Sprintf("10.93.%d.0/24", n), Protocol: "tcp", Action: "drop"}
}

func prefixABAssert(t *testing.T, h *Handlers, coll *ebpf.Collection, slot int) {
	t.Helper()
	want := h.cidrMgr.Snapshot([2][]string{})
	for i, base := range []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie"} {
		name := base
		if slot == 1 {
			name += "_b"
		}
		actual := cut53KernelMapBytes(t, coll.Maps[name])
		if len(actual) != len(want[i]) {
			t.Fatalf("I3 %s rows=%d want=%d", name, len(actual), len(want[i]))
		}
		for key, id := range want[i] {
			v := actual[key]
			if len(v) != 4 || binary.LittleEndian.Uint32([]byte(v)) != id {
				t.Fatalf("I3/I4 %s prefix=%x id=%d actual=%x", name, key, id, v)
			}
		}
	}
	for _, r := range h.cidrRules {
		if r.SrcCIDR != "" {
			id, ok := h.cidrMgr.GetSrcID(r.SrcCIDR)
			if !ok || id != r.Key.SrcID {
				t.Fatal("I4 rule key and global prefix ID diverge")
			}
		}
		if r.DstCIDR != "" {
			id, ok := h.cidrMgr.GetDstID(r.DstCIDR)
			if !ok || id != r.Key.DstID {
				t.Fatal("I4 destination rule ID diverges")
			}
		}
	}
}

func TestPrefixABAtomicCommitELF(t *testing.T) {
	h, _, _, coll := b7ELFCollection(t)
	cut55KernelReceipt(t, h)
	var ws []*dingTrie
	h.cidrMgr, ws = cut53WrapTries(coll)
	for _, n := range []int{1, 2} {
		if n == 2 {
			ws[4].failDelete = true
		}
		if _, err := h.DoAtomicSync([]Rule{prefixABRule(n)}); err != nil {
			t.Fatal(err)
		}
	}
	if !h.mirrorReady || len(cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie_b"])) != 1 {
		t.Fatal("fixture requires ready row mirror and stale old trie")
	}
	ws[4].failDelete = false
	if !dingHasPrefix(t, ws[4].table, 24, [4]byte{10, 93, 1, 0}) {
		t.Fatal("stale old prefix missing after failed R5c delete")
	}
	r := prefixABRule(3)
	result := cut55Commit(t, h, cut55Group(t, h, r, r))
	if result.Receipt != "confirmed" {
		t.Fatal("commit receipt did not confirm")
	}
	for slot := 0; slot < 2; slot++ {
		prefixABAssert(t, h, coll, slot)
	}
	t.Log("CLOSEOUT_PREFIX_SEQUENCE atomic_then_commit=1 row_mirror_ready=1 copies_exact=2")
}

func TestPrefixABReusedPrefixIDELF(t *testing.T) {
	h, _, _, coll := b7ELFCollection(t)
	cut55KernelReceipt(t, h)
	p := prefixABRule(1)
	if _, err := h.DoAtomicSync([]Rule{p}); err != nil {
		t.Fatal(err)
	}
	oldID := h.cidrRules[p.ID].Key.SrcID
	restore := flipBReceipt(t, h, func() error { return errors.New("R5c deferred fixture") })
	if _, err := h.DoAtomicSync([]Rule{prefixABRule(2)}); err != nil {
		t.Fatal(err)
	}
	restore()
	old := cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie_b"])
	if len(old) != 1 {
		t.Fatal("stale prefix fixture missing")
	}
	for _, v := range old {
		if binary.LittleEndian.Uint32([]byte(v)) != oldID {
			t.Fatal("stale ID fixture missing")
		}
	}
	if _, err := h.DoAtomicSync([]Rule{p}); err != nil {
		t.Fatal(err)
	}
	if h.cidrRules[p.ID].Key.SrcID <= oldID {
		t.Fatal("global ID reused")
	}
	prefixABAssert(t, h, coll, int(h.activeRuleSlot.Load()))
	t.Log("CLOSEOUT_PREFIX_REID old_copy_old_id=1 monotonic_new_id=1 overwritten=1")
}

func prefixABFamilyRule(kind, n int) Rule {
	r := prefixABRule(n)
	prefix := r.SrcCIDR
	if kind >= 2 {
		prefix = fmt.Sprintf("fd00:93:%x::/64", n)
	}
	r.SrcCIDR = ""
	if kind%2 == 0 {
		r.SrcCIDR = prefix
	} else {
		r.DstCIDR = prefix
	}
	return r
}

func prefixABCapacityCollection(t *testing.T, kind int) (*Handlers, *ebpf.Collection, string) {
	t.Helper()
	name := []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie"}[kind]
	h, _, _, coll := prefixABCollection(t, func(spec *ebpf.CollectionSpec) {
		for _, n := range []string{name, name + "_b"} {
			if spec.Maps[n] == nil {
				t.Fatal("capacity fixture missing", n)
			}
			spec.Maps[n].MaxEntries = 2
		}
	})
	cut55KernelReceipt(t, h)
	for _, n := range []string{name, name + "_b"} {
		info, err := coll.Maps[n].Info()
		if err != nil || info.MaxEntries != 2 {
			t.Fatal("kernel capacity precondition", n, err)
		}
	}
	return h, coll, name
}

func TestPrefixABFullUnknownELF(t *testing.T) {
	for kind := 0; kind < 4; kind++ {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			h, coll, name := prefixABCapacityCollection(t, kind)
			for _, n := range []int{1, 3} {
				restore := func() {}
				if n == 3 {
					restore = flipBReceipt(t, h, func() error { return errors.New("R5c deferred fixture") })
				}
				if _, err := h.DoAtomicSync([]Rule{prefixABFamilyRule(kind, n), prefixABFamilyRule(kind, n+1)}); err != nil {
					t.Fatal(err)
				}
				restore()
			}
			for _, n := range []string{name, name + "_b"} {
				if len(cut53KernelMapBytes(t, coll.Maps[n])) != 2 {
					t.Fatal("full unknown copy precondition", n)
				}
			}
			if _, err := h.DoAtomicSync([]Rule{prefixABFamilyRule(kind, 5), prefixABFamilyRule(kind, 6)}); err != nil {
				t.Fatal("full unknown copy must delete before writing", err)
			}
			prefixABAssert(t, h, coll, int(h.activeRuleSlot.Load()))
		})
	}
	if !t.Failed() {
		t.Log("CLOSEOUT_PREFIX_FULL_UNKNOWN families=4 kernel_capacity=2 prior_occupancy=2 next_occupancy=2 success=1")
	}
}

func TestPrefixABCapacityELF(t *testing.T) {
	for kind := 0; kind < 4; kind++ {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			h, coll, name := prefixABCapacityCollection(t, kind)
			old := []Rule{prefixABFamilyRule(kind, 1), prefixABFamilyRule(kind, 2)}
			next := []Rule{prefixABFamilyRule(kind, 3), prefixABFamilyRule(kind, 4)}
			result := cut55Commit(t, h, cut55Group(t, h, old[0], old[0]), cut55Group(t, h, old[1], old[1]))
			if result.Receipt != "confirmed" {
				t.Fatal("old copies not confirmed")
			}
			for _, n := range []string{name, name + "_b"} {
				if len(cut53KernelMapBytes(t, coll.Maps[n])) != 2 {
					t.Fatal("old-copy occupancy precondition", n)
				}
			}
			w := cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, old[0]), cut55Group(t, h, old[1]), cut55Group(t, h, next[0], next[0]), cut55Group(t, h, next[1], next[1])})
			if w.Code != 200 {
				t.Fatalf("CLOSEOUT_WITNESS AB-4 new_set_capacity: status=%d body=%s", w.Code, w.Body.String())
			}
			prefixABAssert(t, h, coll, 0)
			prefixABAssert(t, h, coll, 1)
			before := []map[string]string{b7Snapshot(t, coll.Maps[name]), b7Snapshot(t, coll.Maps[name+"_b"]), b7Snapshot(t, h.activeConfig)}
			_, err := h.DoCommitRules([]CommitGroup{cut55Group(t, h, old[0], old[0])})
			if err == nil || err.Status != 409 || err.Code != "table_full" || err.Groups[0].Excess != 1 {
				t.Fatalf("kernel new-set over-capacity control: %+v", err)
			}
			after := []map[string]string{b7Snapshot(t, coll.Maps[name]), b7Snapshot(t, coll.Maps[name+"_b"]), b7Snapshot(t, h.activeConfig)}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("over-capacity rejection mutated a trie/selector")
			}
		})
	}
	if !t.Failed() {
		t.Log("CLOSEOUT_PREFIX_CAPACITY_ELF families=4 kernel_capacity=2 old=2 new=2 union=4 status=200 over_capacity_controls=4")
	}
}

func TestPrefixABFailureCopiesELF(t *testing.T) {
	for _, phase := range []string{"pre-put", "post-delete", "deferred"} {
		t.Run(phase, func(t *testing.T) {
			h, _, _, coll := b7ELFCollection(t)
			cut55KernelReceipt(t, h)
			var ws []*dingTrie
			h.cidrMgr, ws = cut53WrapTries(coll)
			old, next := prefixABRule(1), prefixABRule(2)
			cut55Commit(t, h, cut55Group(t, h, old, old))
			oldSlot := int(h.activeRuleSlot.Load())
			oldBytes := b7Snapshot(t, ws[oldSlot*4].table)
			receipt := h.quiescer
			switch phase {
			case "pre-put":
				ws[(1-oldSlot)*4].failPut = true
			case "post-delete":
				ws[oldSlot*4].failDelete = true
			case "deferred":
				h.quiescer = cut53Receipt(func() error { return errors.New("deferred witness") })
			}
			result, err := h.DoCommitRules([]CommitGroup{cut55Group(t, h, old), cut55Group(t, h, next, next)})
			if phase == "pre-put" {
				if err == nil || err.Code != "commit_failed" || int(h.activeRuleSlot.Load()) != oldSlot {
					t.Fatal("I6 preflip failure published", result, err)
				}
			} else {
				if err != nil || result.Code != "committed" || int(h.activeRuleSlot.Load()) == oldSlot {
					t.Fatal("I6 postflip failure must remain successful", result, err)
				}
				wantReceipt := "confirmed"
				if phase == "deferred" {
					wantReceipt = "deferred"
				}
				if result.Receipt != wantReceipt {
					t.Fatal("receipt shape", result)
				}
			}
			if !reflect.DeepEqual(oldBytes, b7Snapshot(t, ws[oldSlot*4].table)) {
				t.Fatal("I2/I6 old copy changed before its permitted repair")
			}
			for _, w := range ws {
				w.failPut, w.failDelete = false, false
			}
			h.quiescer = receipt
			r := prefixABRule(3)
			cut55Commit(t, h, cut55Group(t, h, r, r))
			prefixABAssert(t, h, coll, 0)
			prefixABAssert(t, h, coll, 1)
		})
	}
	t.Log("CLOSEOUT_PREFIX_FAILURE preflip=1 postflip=1 deferred=1 recovered_copies=6")
}
