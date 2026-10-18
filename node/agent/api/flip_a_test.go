package api

import (
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"net"
	"reflect"
	"testing"
)

type flipAWriteFault struct {
	ruleMirrorMap
	calls int
}

func (m *flipAWriteFault) Update(k, v interface{}, flags ebpf.MapUpdateFlags) error {
	m.calls++
	if m.calls == 2 {
		return fmt.Errorf("flipA second write fault")
	}
	return m.ruleMirrorMap.Update(k, v, flags)
}

func (m *flipAWriteFault) BatchLookup(c *ebpf.MapBatchCursor, k, v interface{}, o *ebpf.BatchOptions) (int, error) {
	return m.ruleMirrorMap.BatchLookup(c, k, v, o)
}
func (m *flipAWriteFault) BatchDelete(k interface{}, o *ebpf.BatchOptions) (int, error) {
	return m.ruleMirrorMap.BatchDelete(k, o)
}
func (m *flipAWriteFault) BatchUpdate(k, v interface{}, _ *ebpf.BatchOptions) (int, error) {
	kb, vb := reflect.ValueOf(k), reflect.ValueOf(v)
	for i := 0; i < kb.Len(); i++ {
		if err := m.Update(atomicBatchBytes(kb, i), atomicBatchBytes(vb, i), ebpf.UpdateAny); err != nil {
			return i, err
		}
	}
	return kb.Len(), nil
}

// 甲-1 / MA-1: identical HTTP bytes and stored rules, including per-request errors.
func TestFlipAMemoEquivalent(t *testing.T) {
	a := cut55Rule("a", 1, "192.0.2.1")
	b := cut55Rule("b", 2, "192.0.2.2")
	bad := b
	bad.ID, bad.LogicalID, bad.Action, bad.SrcIP = "bad", 4, "invalid", "192.0.2.3"
	duplicate := a
	duplicate.ID, duplicate.LogicalID = "duplicate", 5
	zero := b
	zero.LogicalID = 0
	member := a
	member.ID, member.LogicalID = "member", 3
	member.TTL = cut4BString("64")
	prefix := Rule{ID: "prefix", LogicalID: 6, SrcCIDR: "192.0.2.17/24", DstCIDR: "198.51.100.18/24", Action: "drop"}
	badPrefix := prefix
	badPrefix.ID, badPrefix.LogicalID, badPrefix.SrcCIDR = "bad-prefix", 7, "invalid-prefix"
	// A5/P1-1: the oracle calls only the pre-memo APIs, never memo helpers.
	t.Run("independent-cidr-oracle", func(t *testing.T) {
		inputs := []string{
			"", " ", "\t", "\n", "invalid-prefix", "192.0.2.1", "::1", "192.0.2.1/", "::1/",
			" 192.0.2.1/24", "192.0.2.1/24 ", "192.0.2.1/24\n", "192.0.2.1/ 24", "192.0.2.1/+24",
			"192.0.2.1/024", "192.0.2.1/255.255.255.0", "192.0.2.1/24/1", "192.0.2.1//24",
			"192.000.2.1/24", "192.0.002.1/24", "192.0.2.001/24", "192.0.2.1%zone/24",
			"::1%lo0/128", "::1%/128", "[::1]/128", "::1/128/1", "::1//128", "::1/0128",
			"::1/+128", "::1/ 128", " ::1/128", "::1/128 ", "::1/128\t", "::1/ffff",
			"::ffff:192.0.2.1/120", "::FFFF:192.0.2.1/120", "::ffff:192.0.002.1/120",
			"127.0.0.1/8", "10.1.2.3/8", "100.64.1.2/10", "172.16.1.2/12", "192.168.1.2/16",
		}
		for _, address := range []string{"192.0.2.129", "::1", "::FFFF:192.0.2.129", "0:0:0:0:0:0:0:1"} {
			for _, prefix := range []string{"0", "24", "32", "128", "129", "-1", "9999999999999999999999"} {
				inputs = append(inputs, address+"/"+prefix)
			}
		}
		unique := map[string]bool{}
		for i, input := range inputs {
			unique[input] = true
			wantIP, wantNet, parseErr := net.ParseCIDR(input)
			wantNorm, normErr := cidr.NormalizeCIDR(input)
			for _, mode := range []string{"nil", "first", "hit"} {
				t.Run(fmt.Sprintf("%02d/%s", i, mode), func(t *testing.T) {
					var pm, nm *atomicMemo
					if mode != "nil" {
						pm, nm = &atomicMemo{cidrs: map[string]atomicCIDRParse{}}, &atomicMemo{cidrs: map[string]atomicCIDRParse{}}
					}
					if mode == "hit" {
						pm.parse(input)
						nm.normalize(input)
					}
					got := pm.parse(input)
					normalized, err := nm.normalize(input)
					if !reflect.DeepEqual(got.ip, wantIP) || !reflect.DeepEqual(got.network, wantNet) || fmt.Sprint(got.err) != fmt.Sprint(parseErr) || got.normalized != wantNorm || fmt.Sprint(got.normalizeErr) != fmt.Sprint(normErr) || normalized != wantNorm || fmt.Sprint(err) != fmt.Sprint(normErr) {
						t.Fatalf("independent CIDR oracle input=%q mode=%s parse=%+v normalize=%q error=%v; want ip=%v network=%v parse_error=%v normalize=%q error=%v", input, mode, got, normalized, err, wantIP, wantNet, parseErr, wantNorm, normErr)
					}
				})
			}
		}
		if len(unique) < 60 {
			t.Fatalf("independent CIDR corpus too small: %d", len(unique))
		}
		t.Logf("FLIPA_CIDR_ORACLE inputs=%d unique=%d modes=3", len(inputs), len(unique))
	})
	t.Run("invalid-prefix-reason", func(t *testing.T) {
		w := prefixABAtomicHTTP(t, cut55Memory(t), []Rule{a, badPrefix, b})
		var body struct {
			Added, Failed int
			Rejected      []AtomicSyncRejection
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || body.Added != 2 || body.Failed != 1 || len(body.Rejected) != 1 || body.Rejected[0].ID != badPrefix.ID {
			t.Fatalf("middle invalid prefix execution guard: status=%d body=%s error=%v", w.Code, w.Body.String(), err)
		}
		if got := body.Rejected[0].Reason; got != "invalid src_cidr: invalid CIDR: invalid-prefix" {
			t.Fatalf("ba1ab48 invalid-prefix reason got=%q want=%q", got, "invalid src_cidr: invalid CIDR: invalid-prefix")
		}
	})
	for name, rules := range map[string][]Rule{"cidr": {prefix}, "cidr-error": {prefix, badPrefix}, "middle": {a, bad, b}, "logical": {a, zero}, "condition": {a, member}, "abort": {a, bad, b}, "duplicate": {a, duplicate}, "changed-error": {bad}} {
		t.Run(name, func(t *testing.T) {
			var replies [2][]string
			var states [2]map[string]StoredRule
			var prefixes [2]map[string]StoredCIDRRule
			for mode := 0; mode < 2; mode++ {
				f := cut55Memory(t)
				atomicMemoTestHook = func(m **atomicMemo) {
					if mode == 0 {
						*m = nil
					}
				}
				defer func() { atomicMemoTestHook = nil }()
				for request, input := range [][]Rule{{a}, rules} {
					var fault *flipAWriteFault
					if name == "abort" && request == 1 {
						input = append([]Rule(nil), input...)
						input[0].PktLenMax = 512
						slot := 1 - int(f.h.activeRuleSlot.Load())
						fault = &flipAWriteFault{ruleMirrorMap: f.tables[slot][mirrorExact]}
						f.h.mirrorTableFixture = func(s, k int) ruleMirrorMap {
							if s == slot && k == mirrorExact {
								return fault
							}
							return f.tables[s][k]
						}
					}
					w := prefixABAtomicHTTP(t, f, input)
					if fault != nil && (fault.calls != 2 || w.Code != 500) {
						t.Fatalf("abort guard calls=%d status=%d", fault.calls, w.Code)
					}
					replies[mode] = append(replies[mode], fmt.Sprintf("%d:%s", w.Code, w.Body.Bytes()))
				}
				states[mode] = f.h.rules
				prefixes[mode] = f.h.cidrRules
			}
			if !reflect.DeepEqual(replies[0], replies[1]) || !reflect.DeepEqual(states[0], states[1]) || !reflect.DeepEqual(prefixes[0], prefixes[1]) {
				t.Fatalf("request memo leaked or reordered: replies=%v", replies)
			}
		})
	}
}

// 甲-2 and MA-5: an untouched prefix survives c-3/c-6 and the first commit's U side.
func TestFlipASnapshotAndFirstCommit(t *testing.T) {
	// A5/P1-2: a prefix still referenced after Old/Members deltas cannot exit.
	t.Run("shared-prefix-retained", func(t *testing.T) {
		for _, dst := range []bool{false, true} {
			for _, replaceSurvivor := range []bool{false, true} {
				t.Run(fmt.Sprintf("dst=%t/replace=%t", dst, replaceSurvivor), func(t *testing.T) {
					f := cut55Memory(t)
					a := Rule{ID: "shared-80", LogicalID: 1, SrcCIDR: "192.0.2.0/24", SrcPort: 80, Protocol: "tcp", Action: "drop"}
					if dst {
						a.SrcCIDR, a.DstCIDR = "", a.SrcCIDR
					}
					b, n := a, a
					b.ID, b.LogicalID, b.SrcPort = "shared-443", 2, 443
					n.ID, n.LogicalID = "new-25", 3
					if dst {
						n.DstCIDR = "192.0.2.0/25"
					} else {
						n.SrcCIDR = "192.0.2.0/25"
					}
					cut55Commit(t, f.h, cut55Group(t, f.h, a, a), cut55Group(t, f.h, b, b))
					if len(f.h.cidrRules) != 2 {
						t.Fatal("shared prefix seed must contain both owners")
					}
					groups := []CommitGroup{cut55Group(t, f.h, a), cut55Group(t, f.h, n, n)}
					if replaceSurvivor {
						groups = append(groups, cut55Group(t, f.h, b, b))
					}
					w := cut55HTTP(t, f.h, groups)
					var body CommitResult
					if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 409 || body.Code != "cidr_overlap" {
						t.Fatalf("retained shared prefix must reject: status=%d body=%s error=%v", w.Code, w.Body.String(), err)
					}
					t.Logf("FLIPA_MA3_RETAINED dst=%t replace=%t status=%d code=%s", dst, replaceSurvivor, w.Code, body.Code)
				})
			}
		}
	})
	for _, seedAtomic := range []bool{false, true} {
		t.Run(fmt.Sprint(seedAtomic), func(t *testing.T) {
			f := cut55Memory(t)
			r := Rule{ID: "prefix", LogicalID: 1, SrcCIDR: "192.0.2.0/24", Action: "drop"}
			if seedAtomic {
				prefixABAtomicBody(t, prefixABAtomicHTTP(t, f, []Rule{r}), 200, `{"success":true,"added":1,"failed":0,"rules":0,"cidr_rules":1,"rejected":[]}`)
			} else {
				cut55Commit(t, f.h, cut55Group(t, f.h, r, r))
			}
			key := string([]byte{24, 0, 0, 0, 192, 0, 2, 0})
			id, _ := f.h.cidrMgr.GetSrcID(r.SrcCIDR)
			witnesses := 0
			f.h.commitStageTestHook = func(stage string) {
				if stage == "c-3" || stage == "c-6" {
					witnesses++
					if got := f.h.cidrMgr.Snapshot([2][]string{})[0]; !reflect.DeepEqual(got, map[string]uint32{key: id}) {
						t.Fatalf("untouched Snapshot bytes stage=%s got=%x", stage, got)
					}
				}
				if stage == "c-7" {
					f.bindConfig()
				}
			}
			f.h.quiescer = cut5ReceiptFunc(func() error { return nil })
			f.bindConfig()
			exact := cut55Rule("exact", 2, "203.0.113.1")
			cut55Commit(t, f.h, cut55Group(t, f.h, exact, exact))
			if witnesses != 2 || !reflect.DeepEqual(f.tries[0].rows, map[string]uint32{key: id}) || !reflect.DeepEqual(f.tries[0].rows, f.triesB[0].rows) {
				t.Fatal("first commit must preserve complete want on U side")
			}
		})
	}
}

// 甲-1: abort preserves the complete rejected list, even though HTTP omits it.
func TestFlipAMemoAbortResult(t *testing.T) {
	var encoded [2][]byte
	for mode := range encoded {
		f := cut55Memory(t)
		fault := &flipAWriteFault{ruleMirrorMap: f.tables[1][mirrorExact]}
		f.h.mirrorTableFixture = func(s, k int) ruleMirrorMap {
			if s == 1 && k == mirrorExact {
				return fault
			}
			return f.tables[s][k]
		}
		atomicMemoTestHook = func(m **atomicMemo) {
			if mode == 0 {
				*m = nil
			}
		}
		defer func() { atomicMemoTestHook = nil }()
		a, b := cut55Rule("a", 1, "192.0.2.1"), cut55Rule("b", 2, "192.0.2.2")
		bad := cut55Rule("bad", 3, "192.0.2.3")
		bad.Action = "invalid"
		result, err := f.h.DoAtomicSync([]Rule{a, bad, b})
		if err == nil || fault.calls != 2 || result.Added != 1 || result.Failed != 2 || len(result.Rejected) != 1 {
			t.Fatalf("abort execution guard: result=%+v calls=%d error=%v", result, fault.calls, err)
		}
		encoded[mode], err = json.Marshal(struct {
			Result AtomicSyncResult
			Error  string
		}{result, err.Error()})
		if err != nil {
			t.Fatal(err)
		}
	}
	if string(encoded[0]) != string(encoded[1]) {
		t.Fatalf("abort bytes differ: %s / %s", encoded[0], encoded[1])
	}
}

// 甲-3 / MA-5: seed boot-time state without Align/Apply, so the old copy is U.
func TestFlipAFirstCommitUnknown(t *testing.T) {
	f := cut55Memory(t)
	r := Rule{ID: "boot-prefix", LogicalID: 1, SrcCIDR: "192.0.2.0/24", Action: "drop"}
	id, err := f.h.cidrMgr.ReserveSrcID(r.SrcCIDR)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.h.prepareAtomicRule(r)
	if err != nil {
		t.Fatal(err)
	}
	p.CIDR.SrcID = id
	f.h.cidrRules[r.ID] = ruleToStoredCIDR(p.CIDR, r.SrcCIDR, "", r)
	addRuleID(f.h.cidrRuleKeyIndex, p.CIDR, r.ID)
	f.h.logicalOwners[r.LogicalID] = r.ID
	f.tables[0][mirrorCIDR].rows[string(cidrRuleKeyToBytes(p.CIDR))] = ruleValueToBytes(p.Value)
	key := string([]byte{24, 0, 0, 0, 192, 0, 2, 0})
	f.tries[0].rows[key] = id
	stages := []string{}
	f.h.commitStageTestHook = func(stage string) {
		stages = append(stages, stage)
		if stage == "c-7" {
			f.bindConfig()
		}
	}
	exact := cut55Rule("exact", 2, "203.0.113.1")
	result := cut55Commit(t, f.h, cut55Group(t, f.h, exact, exact))
	if result.Receipt != "confirmed" || len(stages) == 0 || stages[len(stages)-1] != "c-9" {
		t.Fatal("first commit must complete c-9 with confirmed receipt")
	}
	if !reflect.DeepEqual(f.tries[0].rows, map[string]uint32{key: id}) || !reflect.DeepEqual(f.tries[0].rows, f.triesB[0].rows) {
		t.Fatal("first commit must preserve complete want on U side")
	}
}
