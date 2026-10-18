package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

// All migrated retention witnesses observe the receipt after selector publication.
func flipBReceipt(t *testing.T, h *Handlers, fn func() error) func() {
	t.Helper()
	prior, slot := h.quiescer, h.activeRuleSlot.Load()
	hits := 0
	h.quiescer = cut5ReceiptFunc(func() error {
		if h.activeRuleSlot.Load() != slot {
			hits++
			if err := fn(); err != nil {
				return err
			}
		}
		return prior.Quiesce()
	})
	restore := func() {
		h.quiescer = prior
		if hits == 0 {
			t.Error("R5c witness not reached after selector flip")
		}
	}
	t.Cleanup(restore)
	return restore
}

type flipBMap struct {
	ruleMirrorMap
	read  func(*ebpf.MapBatchCursor, interface{}, interface{}, *ebpf.BatchOptions) (int, error)
	after func()
}

func (m *flipBMap) BatchLookup(c *ebpf.MapBatchCursor, k, v interface{}, o *ebpf.BatchOptions) (int, error) {
	if m.read != nil {
		return m.read(c, k, v, o)
	}
	return m.ruleMirrorMap.BatchLookup(c, k, v, o)
}
func (m *flipBMap) BatchUpdate(k, v interface{}, o *ebpf.BatchOptions) (int, error) {
	return m.ruleMirrorMap.BatchUpdate(k, v, o)
}
func (m *flipBMap) BatchDelete(k interface{}, o *ebpf.BatchOptions) (int, error) {
	return m.ruleMirrorMap.BatchDelete(k, o)
}
func (m *flipBMap) Update(k, v interface{}, f ebpf.MapUpdateFlags) error {
	err := m.ruleMirrorMap.Update(k, v, f)
	if err == nil && m.after != nil {
		m.after()
	}
	return err
}
func (m *flipBMap) MaxEntries() uint32 { return 500000 }
func flipBInstall(f *cut55Fixture, slot, kind int, m ruleMirrorMap) {
	f.h.mirrorTableFixture = func(s, k int) ruleMirrorMap {
		if s == slot && k == kind {
			return m
		}
		return f.tables[s][k]
	}
}
func flipBClone(rows map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range rows {
		out[k] = bytes.Clone(v)
	}
	return out
}

// MB-1/2: nonempty expected set, actual orphan or same-key wrong value, all four maps.
func TestFlipBShadowDelta(t *testing.T) {
	for _, mode := range []string{"extra", "value"} {
		for kind := 0; kind < 4; kind++ {
			t.Run(fmt.Sprintf("%s/%d", mode, kind), func(t *testing.T) {
				f := cut55Memory(t)
				r := cut55Rule("r", 1, "192.0.2.1")
				if kind%2 == 1 {
					r.SrcIP = ""
					r.SrcCIDR = "192.0.2.0/24"
				}
				if kind >= 2 {
					r.TTL = cut4BString("64")
				}
				if w := prefixABAtomicHTTP(t, f, []Rule{r}); w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				slot := 1 - int(f.h.activeRuleSlot.Load())
				for k := range f.tables[slot] {
					f.tables[slot][k].rows = flipBClone(f.tables[1-slot][k].rows)
				}
				table := f.tables[slot][kind]
				want := flipBClone(table.rows)
				if len(want) != 1 {
					t.Fatal("nonempty physical row guard")
				}
				id := "MB-1"
				if mode == "extra" {
					key := make([]byte, table.KeySize())
					copy(key, []byte{0x20, 1, 0x0d, 0xb8})
					table.rows[string(key)] = make([]byte, table.ValueSize())
				} else {
					id = "MB-2"
					for _, v := range table.rows {
						v[0] ^= 1
					}
				}
				writes, deletes := table.writes, table.deletes
				t.Logf("MB_GUARD id=%s kind=%d expected=1 perturbation=1", id, kind)
				w := prefixABAtomicHTTP(t, f, []Rule{r})
				if w.Code != 200 || !reflect.DeepEqual(table.rows, want) {
					t.Logf("MB_ABORT id=%s verify=%v selector_unchanged=%v", id, strings.Contains(w.Body.String(), "verify shadow"), int(f.h.activeRuleSlot.Load()) == 1-slot)
					t.Fatalf("%s shadow delta failed status=%d body=%s", id, w.Code, w.Body.String())
				}
				if (mode == "extra" && (table.deletes-deletes != 1 || table.writes != writes)) || (mode == "value" && (table.writes-writes != 1 || table.deletes != deletes)) {
					t.Fatal("delta did not delete/write exactly the difference")
				}
			})
		}
	}
}

// MB-3: a successful syscall is insufficient; independently corrupted bytes must abort.
func TestFlipBReadback(t *testing.T) {
	for _, orphan := range []bool{false, true} {
		t.Run(fmt.Sprint(orphan), func(t *testing.T) {
			f := cut55Memory(t)
			slot := 1 - int(f.h.activeRuleSlot.Load())
			table := f.tables[slot][mirrorExact]
			hits := 0
			m := &flipBMap{ruleMirrorMap: table, after: func() {
				hits++
				if orphan {
					key := make([]byte, 40)
					copy(key, []byte{0x20, 1, 0x0d, 0xb8})
					table.rows[string(key)] = make([]byte, 32)
				} else {
					for _, v := range table.rows {
						v[0] ^= 1
					}
				}
			}}
			flipBInstall(f, slot, mirrorExact, m)
			w := prefixABAtomicHTTP(t, f, []Rule{cut55Rule("r", 1, "192.0.2.1")})
			t.Logf("MB_GUARD id=MB-3 successful_writes=%d corruption=1", hits)
			if hits != 1 {
				t.Fatal("corrupting successful write not reached")
			}
			if w.Code != 500 || !strings.Contains(w.Body.String(), "verify shadow blacklist:") || int(f.h.activeRuleSlot.Load()) == slot {
				t.Fatalf("MB-3 readback allowed corrupt publication status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// MB-4: one full batch and a terminal partial batch containing an orphan to delete.
func TestFlipBTerminalBatch(t *testing.T) {
	f := cut55Memory(t)
	r := cut55Rule("r", 1, "192.0.2.1")
	table := f.tables[1][0]
	for i := 0; i < atomicBatchSize+1; i++ {
		key := make([]byte, 40)
		copy(key, []byte{0x20, 1, 0x0d, 0xb8})
		binary.BigEndian.PutUint32(key[12:], uint32(i+1))
		table.rows[string(key)] = make([]byte, 32)
	}
	terminal := 0
	m := &flipBMap{ruleMirrorMap: table}
	m.read = func(c *ebpf.MapBatchCursor, k, v interface{}, o *ebpf.BatchOptions) (int, error) {
		n, e := table.BatchLookup(c, k, v, o)
		if e == ebpf.ErrKeyNotExist && n > 0 {
			terminal++
		}
		return n, e
	}
	flipBInstall(f, 1, 0, m)
	t.Logf("MB_GUARD id=MB-4 initial=%d batch=%d remainder=1 expected=1", len(table.rows), atomicBatchSize)
	w := prefixABAtomicHTTP(t, f, []Rule{r})
	if terminal == 0 {
		t.Fatal("terminal n>0 witness not reached")
	}
	if w.Code != 200 || len(table.rows) != 1 || table.deletes != atomicBatchSize+1 {
		t.Fatalf("MB-4 terminal orphan retained status=%d rows=%d deletes=%d", w.Code, len(table.rows), table.deletes)
	}
}

// Batch contracts: ENOSPC restarts from scratch/new cursor; short nonterminal batches continue.
func TestFlipBBatchContracts(t *testing.T) {
	f := cut55Memory(t)
	table := f.tables[1][0]
	p, _ := f.h.prepareAtomicRule(cut55Rule("r", 1, "192.0.2.1"))
	key := ruleKeyToBytes(p.Exact)
	value := ruleValueToBytes(p.Value)
	for _, mode := range []string{"restart", "cap", "error"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			var first *ebpf.MapBatchCursor
			m := &flipBMap{ruleMirrorMap: table}
			m.read = func(c *ebpf.MapBatchCursor, k, v interface{}, _ *ebpf.BatchOptions) (int, error) {
				calls++
				kb, vb := reflect.ValueOf(k), reflect.ValueOf(v)
				if mode == "cap" {
					return 0, syscall.ENOSPC
				}
				if mode == "error" {
					return 0, syscall.EIO
				}
				if calls == 1 {
					first = c
					junk := bytes.Clone(key)
					copy(junk, []byte{0x20, 1, 0x0d, 0xb8})
					copy(atomicBatchBytes(kb, 0), junk)
					copy(atomicBatchBytes(vb, 0), value)
					return 1, nil
				}
				if calls == 2 {
					if c != first || kb.Len() != atomicBatchSize {
						t.Error("cursor changed inside scan")
					}
					return 0, syscall.ENOSPC
				}
				if c == first || kb.Len() != 2*atomicBatchSize {
					t.Error("ENOSPC did not restart with doubled buffer")
				}
				copy(atomicBatchBytes(kb, 0), key)
				copy(atomicBatchBytes(vb, 0), value)
				return 1, ebpf.ErrKeyNotExist
			}
			got, err := atomicReadTable(m)
			if mode == "restart" {
				if err != nil || calls != 3 || len(got) != 1 || !bytes.Equal(got[string(key)], value) {
					t.Fatal("restart leaked partial scan", calls, err)
				}
			} else if err == nil || (mode == "cap" && calls != 5) {
				t.Fatal("read error swallowed", calls, err)
			}
		})
	}
	// A fault after one successful operation retains precisely that prefix.
	keys := atomicBatchBuffer(40, 2)
	values := atomicBatchBuffer(32, 2)
	copy(atomicBatchBytes(keys, 0), key)
	copy(atomicBatchBytes(keys, 1), key)
	atomicBatchBytes(keys, 1)[15] ^= 1
	fault := &flipAWriteFault{ruleMirrorMap: table}
	n, err := fault.BatchUpdate(keys.Interface(), values.Interface(), nil)
	if n != 1 || err == nil || len(table.rows) != 1 {
		t.Fatal("partial batch prefix not retained", n, err)
	}
	n, err = table.BatchDelete(keys.Interface(), nil)
	if n != 1 || err == nil || len(table.rows) != 0 {
		t.Fatal("partial delete prefix not retained", n, err)
	}
	if err := atomicWriteRows(nil, mirrorExact, nil, nil, true); err != nil {
		t.Fatal("empty batch issued")
	}
}

// MB-5: physical counts and both bitmap bits include skipped and newly written groups.
func TestFlipBSkippedCounts(t *testing.T) {
	f := cut55Memory(t)
	a := cut55Rule("a", 1, "192.0.2.1")
	c := Rule{ID: "c", LogicalID: 2, SrcCIDR: "192.0.2.0/24", Action: "drop"}
	if w := prefixABAtomicHTTP(t, f, []Rule{a, c}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	slot := 1 - int(f.h.activeRuleSlot.Load())
	for k := range f.tables[slot] {
		f.tables[slot][k].rows = flipBClone(f.tables[1-slot][k].rows)
	}
	b, d := a, c
	b.ID, b.LogicalID, b.DstPort = "b", 3, 80
	d.ID, d.LogicalID, d.DstPort, d.Protocol = "d", 4, 80, "tcp"
	seen := 0
	cidrBeforeAtomicPublishTestHook = func(h *Handlers) {
		seen++
		cfg := f.configs[1-h.activeSlot]
		for _, idx := range []uint32{ConfigBlacklistCount, ConfigCIDRRuleCount} {
			if binary.LittleEndian.Uint64(cfg.rows[string(cut55Bytes(idx))]) != 2 {
				t.Errorf("MB-5 skipped physical count missing index=%d", idx)
			}
		}
		for kind, rs := range [][]Rule{{a, b}, {c, d}} {
			var bits uint64
			for _, r := range rs {
				p, e := h.prepareAtomicRule(r)
				if e != nil {
					t.Fatal(e)
				}
				combo := getComboType(p.Exact)
				if kind == 1 {
					combo = getCIDRComboType(p.CIDR)
				}
				bits |= 1 << uint(combo)
			}
			idx := []uint32{ConfigRuleBitmap, ConfigCIDRBitmap}[kind]
			if bits == 0 || binary.LittleEndian.Uint64(cfg.rows[string(cut55Bytes(idx))]) != bits {
				t.Errorf("MB-5 skipped bitmap missing kind=%d", kind)
			}
		}
	}
	defer func() { cidrBeforeAtomicPublishTestHook = nil }()
	before := []int{f.tables[slot][0].writes, f.tables[slot][1].writes}
	w := prefixABAtomicHTTP(t, f, []Rule{a, c, b, d})
	if seen != 1 || w.Code != 200 || f.tables[slot][0].writes-before[0] != 1 || f.tables[slot][1].writes-before[1] != 1 {
		t.Fatal("skip/new execution guard", seen, w.Code)
	}
	t.Log("MB_GUARD id=MB-5 skipped=2 new=2 physical=4 logical=4")
}
