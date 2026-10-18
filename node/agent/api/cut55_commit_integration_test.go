//go:build linux && integration

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
)

func cut55KernelMirror(t *testing.T, h *Handlers) {
	t.Helper()
	a, b := h.ruleTablesAt(0), h.ruleTablesAt(1)
	for kind := range a {
		if !reflect.DeepEqual(cut53KernelMapBytes(t, a[kind]), cut53KernelMapBytes(t, b[kind])) {
			t.Fatalf("G2 kernel table %d differs", kind)
		}
	}
}
func cut55KernelSide(t *testing.T, h *Handlers, slot int) [4]map[string]string {
	t.Helper()
	var out [4]map[string]string
	for i, m := range h.ruleTablesAt(slot) {
		out[i] = cut53KernelMapBytes(t, m)
	}
	return out
}
func cut55KernelReceipt(t *testing.T, h *Handlers) {
	t.Helper()
	q, err := newKernelQuiescer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	h.quiescer = q
}

func TestCut55GenerationELF(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		t.Run(fmt.Sprint(isCIDR), func(t *testing.T) {
			h, _, program := b7ELF(t)
			cut55KernelReceipt(t, h)
			old := cut53Pure(isCIDR, "moving", 17)
			old.DstPort = 0
			// Deferred commit Rc leaves R0 pending for the next real commit.
			p7DeferredCommit(t, h, cut55Group(t, h, old, old))
			if h.quiescenceConfirmed {
				t.Fatal("G1 fixture must require R0")
			}
			active := int(h.activeRuleSlot.Load())
			oldRows := cut55KernelSide(t, h, active)
			narrowed := old
			narrowed.DstPort = 80
			ttl := "64"
			narrowed.TTL = &ttl
			groups := []CommitGroup{cut55Group(t, h, old), cut55Group(t, h, narrowed, narrowed)}
			var sequence []string
			prior := h.quiescer
			receipts := 0
			h.quiescer = cut53Receipt(func() error { receipts++; sequence = append(sequence, "receipt"); return prior.Quiesce() })
			packet := cut53Packet([4]byte{192, 0, 2, 1}, 64)
			h.commitStageTestHook = func(stage string) {
				sequence = append(sequence, stage)
				switch stage {
				case "c-3":
					if receipts != 1 {
						t.Fatal("R0 missing before shadow writes")
					}
					cut55KernelMirror(t, h)
				case "c-4", "c-5", "c-6":
					if !reflect.DeepEqual(oldRows, cut55KernelSide(t, h, active)) {
						t.Fatal("G3 active generation overwritten before flip")
					}
					cut53Verdict(t, program, packet, 1)
				case "c-7", "c-9":
					cut53Verdict(t, program, packet, 1)
				case "c-Rc":
					if !reflect.DeepEqual(oldRows, cut55KernelSide(t, h, active)) {
						t.Fatal("old side repaired before Rc")
					}
				}
			}
			result := cut55Commit(t, h, groups...)
			h.commitStageTestHook = nil
			want := []string{"c-R0", "receipt", "c-3", "c-4", "c-5", "c-6", "c-7", "c-Rc", "receipt", "c-9"}
			if !reflect.DeepEqual(sequence, want) || result.Receipt != "confirmed" {
				t.Fatalf("G1 receipt/write order=%v want=%v result=%+v", sequence, want, result)
			}
			cut55KernelMirror(t, h)
			// B version starts from a live conditional group, with a pure unrelated POST
			// creating the pending generation. Active condition bytes must remain intact.
			u := cut55Rule("u", 99, "203.0.113.99")
			p7DeferredCommit(t, h, cut55Group(t, h, u, u))
			active = int(h.activeRuleSlot.Load())
			oldRows = cut55KernelSide(t, h, active)
			narrowed.PktLenMax = 100
			seen := 0
			h.commitStageTestHook = func(stage string) {
				if stage == "c-4" || stage == "c-5" || stage == "c-6" {
					seen++
					if !reflect.DeepEqual(oldRows, cut55KernelSide(t, h, active)) {
						t.Fatal("G3 conditional active row overwritten or deleted")
					}
					cut53Verdict(t, program, packet, 1)
				}
			}
			cut55Commit(t, h, cut55Group(t, h, narrowed, narrowed))
			h.commitStageTestHook = nil
			if seen != 3 {
				t.Fatal("G3 windows not reached")
			}
			cut55KernelMirror(t, h)
			t.Logf("CUT55_GENERATION cidr=%v old_windows=3 new_windows=2 r0=1 rc=1 conditional_windows=3 pass=0", isCIDR)
		})
	}
}

type cut55FaultMap struct {
	ruleMirrorMap
	phase string
	hits  *int
}

func (m cut55FaultMap) NextKey(a, b interface{}) error {
	if m.phase == "enumerate" {
		return errors.New("iteration only")
	}
	return m.ruleMirrorMap.NextKey(a, b)
}
func (m cut55FaultMap) Delete(a interface{}) error {
	if m.phase == "delete" {
		return errors.New("delete only")
	}
	return m.ruleMirrorMap.Delete(a)
}
func (m cut55FaultMap) Update(a, b interface{}, f ebpf.MapUpdateFlags) error {
	if m.phase == "write" {
		return errors.New("write only")
	}
	return m.ruleMirrorMap.Update(a, b, f)
}

func (m cut55FaultMap) BatchLookup(c *ebpf.MapBatchCursor, k, v interface{}, o *ebpf.BatchOptions) (int, error) {
	if m.phase == "enumerate" {
		if m.hits != nil {
			*m.hits++
		}
		return 0, errors.New("iteration only")
	}
	return m.ruleMirrorMap.BatchLookup(c, k, v, o)
}
func (m cut55FaultMap) BatchDelete(k interface{}, o *ebpf.BatchOptions) (int, error) {
	if m.phase == "delete" {
		if m.hits != nil {
			*m.hits++
		}
		return 0, m.Delete(nil)
	}
	return m.ruleMirrorMap.BatchDelete(k, o)
}
func (m cut55FaultMap) BatchUpdate(k, v interface{}, o *ebpf.BatchOptions) (int, error) {
	if m.phase == "write" {
		if m.hits != nil {
			*m.hits++
		}
		return 0, m.Update(nil, nil, ebpf.UpdateAny)
	}
	return m.ruleMirrorMap.BatchUpdate(k, v, o)
}

func TestCut55FullStrictAndAbortELF(t *testing.T) {
	for _, phase := range []string{"enumerate", "delete"} {
		for _, isCIDR := range []bool{false, true} {
			t.Run(fmt.Sprintf("strict_%s/cidr_%v", phase, isCIDR), func(t *testing.T) {
				h, _, program := b7ELF(t)
				r := cut53Pure(isCIDR, "u", 17)
				targetKind := mirrorExact
				if isCIDR {
					targetKind = mirrorCIDR
				}
				if _, err := h.DoAtomicSync([]Rule{r}); err != nil {
					t.Fatal(err)
				}
				cut55KernelMirror(t, h)
				active := int(h.activeRuleSlot.Load())
				before := cut55KernelSide(t, h, active)
				hits := 0
				if phase == "delete" {
					table := h.mirrorTable(1-active, targetKind)
					key := make([]byte, table.KeySize())
					copy(key, []byte{0x20, 1, 0x0d, 0xb8})
					if err := table.Update(key, make([]byte, table.ValueSize()), ebpf.UpdateAny); err != nil {
						t.Fatal(err)
					}
				}
				h.mirrorTableFixture = func(slot, kind int) ruleMirrorMap {
					m := h.ruleTablesAt(slot)[kind]
					if slot != active && kind == targetKind {
						return cut55FaultMap{m, phase, &hits}
					}
					return m
				}
				_, err := h.DoAtomicSync([]Rule{r})
				if hits == 0 {
					t.Fatal("strict fault not executed")
				}
				if err == nil || !strings.Contains(err.Error(), "clear shadow") {
					t.Fatal("Step 1 strict error was swallowed", err)
				}
				if h.mirrorReady || int(h.activeRuleSlot.Load()) != active || !reflect.DeepEqual(before, cut55KernelSide(t, h, active)) {
					t.Fatal("strict Step 1 changed active or lost pending flag")
				}
				cut53Verdict(t, program, cut53Packet([4]byte{192, 0, 2, 1}, 64), 1)
				h.mirrorTableFixture = nil
				n := cut55Rule("n", 18, "203.0.113.18")
				cut55Commit(t, h, cut55Group(t, h, n, n))
				cut55KernelMirror(t, h)
				if _, err := h.DoAtomicSync(nil); err != nil {
					t.Fatal(err)
				}
				cut55KernelMirror(t, h)
				for _, side := range []int{0, 1} {
					for _, rows := range cut55KernelSide(t, h, side) {
						if len(rows) != 0 {
							t.Fatal("Step 1 recovery full sync left stale rows")
						}
					}
				}
				cut53Verdict(t, program, cut53Packet([4]byte{192, 0, 2, 1}, 64), 2)
				t.Logf("CUT55_STEP1 phase=%s cidr=%v abort=1 zero_visible=1 repaired=1 full_recovery_empty=1", phase, isCIDR)
			})
		}
	}
	// Each observable full-sync stage after Step 1 is a separate M3 witness.
	for _, stage := range []string{"2-exact-condition", "2-exact-rule", "2-cidr-condition", "2-cidr-rule", "3a", "flip", "5b", "6"} {
		t.Run("abort_"+stage, func(t *testing.T) {
			h, _, _ := b7ELF(t)
			u := cut53Pure(false, "u", 17)
			u.DstPort = 81
			if _, err := h.DoAtomicSync([]Rule{u}); err != nil {
				t.Fatal(err)
			}
			if !h.mirrorReady {
				t.Fatal("M3 fixture not initially aligned")
			}
			reached := false
			hits := 0
			originalReceipt := h.quiescer
			var restore func()
			failFD := func(target **ebpf.Map) {
				clone, err := (*target).Clone()
				if err != nil {
					t.Fatal(err)
				}
				original := *target
				if err := original.Close(); err != nil {
					t.Fatal(err)
				}
				restore = func() { *target = clone }
				t.Cleanup(func() { clone.Close() })
			}
			atomicStageTestHook = func(got string, owner *Handlers) {
				if owner != h || got != stage {
					return
				}
				reached = true
				shadow := 1 - int(h.activeRuleSlot.Load())
				switch stage {
				case "2-exact-condition":
					if shadow == 0 {
						failFD(&h.blacklist)
					} else {
						failFD(&h.blacklistB)
					}
				case "2-exact-rule":
					if shadow == 0 {
						failFD(&h.cidrCondA)
					} else {
						failFD(&h.cidrCondB)
					}
				case "2-cidr-condition":
					if shadow == 0 {
						failFD(&h.cidrBlacklist)
					} else {
						failFD(&h.cidrBlacklistB)
					}
				case "2-cidr-rule", "3a":
					if h.activeSlot == 0 {
						failFD(&h.configB)
					} else {
						failFD(&h.configA)
					}
				case "flip", "5b":
					h.quiescer = cut53Receipt(func() error { return errors.New("R5c injected") })
				case "6":
					h.mirrorTableFixture = func(slot, kind int) ruleMirrorMap {
						m := h.ruleTablesAt(slot)[kind]
						if slot != int(h.activeRuleSlot.Load()) && kind == 0 {
							return cut55FaultMap{m, "enumerate", &hits}
						}
						return m
					}
				}
			}
			c := cut53Pure(true, "c", 18)
			v := "64"
			c.TTL = &v
			e := cut53Pure(false, "e", 19)
			e.TTL = &v
			_, fullErr := h.DoAtomicSync([]Rule{u, e, c})
			atomicStageTestHook = nil
			h.quiescer = originalReceipt
			if restore != nil {
				restore()
			}
			h.mirrorTableFixture = nil
			if !reached || h.mirrorReady {
				t.Fatal("full abort did not retain whole alignment debt")
			}
			if stage != "flip" && stage != "5b" && stage != "6" && fullErr == nil {
				t.Fatal("preflip fault did not abort full sync")
			}
			if stage == "6" && hits == 0 {
				t.Fatal("Step 6 fault not executed")
			}
			if stage == "6" && h.mirrorFailures == 0 {
				t.Fatal("Step 6 iteration error was swallowed")
			}
			n := cut55Rule("n", 20, "203.0.113.20")
			prior := h.mirrorAlignments
			cut55Commit(t, h, cut55Group(t, h, n, n))
			if h.mirrorAlignments != prior+1 {
				t.Fatal("M3 next commit did not take whole alignment")
			}
			cut55KernelMirror(t, h)
			if _, ok := h.rules["u"]; !ok {
				t.Fatal("M3 undeclared U disappeared")
			}
			t.Logf("CUT55_FULL_ABORT stage=%s reached=1 whole_alignment=1 undeclared_u=1", stage)
		})
	}
}

func TestCut55PrefixDebtELF(t *testing.T) {
	for _, next := range []string{"commit", "full"} {
		t.Run(next, func(t *testing.T) {
			h, _, program, coll := b7ELFCollection(t)
			cut55KernelReceipt(t, h)
			old := cut53Pure(true, "old", 17)
			old.SrcCIDR = "192.0.2.0/24"
			cut55Commit(t, h, cut55Group(t, h, old, old))
			original := h.quiescer
			h.quiescer = cut53Receipt(func() error { return errors.New("Rc fails") })
			result := cut55Commit(t, h, cut55Group(t, h, old))
			if result.Receipt != "deferred" {
				t.Fatal("prefix Rc debt missing")
			}
			if len(h.cidrMgr.ListSrcCIDRs()) != 0 || len(cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie_b"])) != 1 || len(cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie"])) != 0 {
				t.Fatal("exit prefix released before Rc")
			}
			h.quiescer = original
			u := cut55Rule("u", 18, "203.0.113.18")
			switch next {
			case "commit":
				cut55Commit(t, h, cut55Group(t, h, u, u))
			case "full":
				if _, err := h.DoAtomicSync([]Rule{u}); err != nil {
					t.Fatal(err)
				}
			}
			if len(h.cidrMgr.ListSrcCIDRs()) != 0 || len(cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie_b"])) != 0 || len(cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie"])) != 0 {
				t.Fatal("D5 full/commit did not settle deferred prefix debt")
			}
			n := cut53Pure(true, "nested", 19)
			n.SrcCIDR = "192.0.2.0/25"
			cut55Commit(t, h, cut55Group(t, h, n, n))
			cut55KernelMirror(t, h)
			cut53Verdict(t, program, cut53Packet([4]byte{192, 0, 2, 1}, 64), 1)
			t.Logf("CUT55_PREFIX_DEBT next=%s deferred=1 settled=1 nested_accepted=1", next)
		})
	}
}

func TestCut55ListRulesRace(t *testing.T) {
	h, _, program := b7ELF(t)
	router := gin.New()
	router.GET("/api/v1/rules", h.ListRules)
	cut55KernelReceipt(t, h)
	r := cut53Pure(false, "moving", 17)
	cut55Commit(t, h, cut55Group(t, h, r, r))
	const iterations = 40
	var wg sync.WaitGroup
	failures := make(chan error, 3)
	wg.Add(1)
	go func() {
		defer wg.Done()
		current := r
		for i := 0; i < iterations; i++ {
			next := current
			if next.DstPort == 80 {
				next.DstPort = 0
			} else {
				next.DstPort = 80
			}
			_, err := h.DoCommitRules([]CommitGroup{cut55Group(t, h, current), cut55Group(t, h, next, next)})
			if err != nil {
				failures <- err
				return
			}
			current = next
			if _, _, err := program.Test(cut53Packet([4]byte{192, 0, 2, 1}, 64)); err != nil {
				failures <- err
				return
			}
		}
	}()
	for _, path := range []string{"/api/v1/rules", "/api/v1/rules?page=1&limit=100"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			var high uint64
			for i := 0; i < iterations*4; i++ {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
				var body struct {
					Rules []Rule `json:"rules"`
				}
				if w.Code != 200 {
					failures <- fmt.Errorf("list status %d", w.Code)
					return
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					failures <- err
					return
				}
				for _, got := range body.Rules {
					if got.ID != "moving" || got.Stats == nil {
						failures <- fmt.Errorf("unexpected list rule %+v", got)
						return
					}
					count := got.Stats.MatchCount
					if count != 0 && count < high {
						failures <- fmt.Errorf("list counter regressed %d < %d", count, high)
						return
					}
					if count > high {
						high = count
					}
				}
			}
		}(path)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	cut55KernelMirror(t, h)
	t.Logf("CUT55_LIST_RACE flips=%d readers=2 reads=%d monotonic_or_zero=1", iterations, iterations*8)
}

func TestCut55PrefixTransitionELF(t *testing.T) {
	h, _, program, coll := b7ELFCollection(t)
	cut55KernelReceipt(t, h)
	a := cut53Pure(true, "a", 17)
	b := cut53Pure(true, "b", 18)
	b.SrcCIDR = "198.51.100.0/24"
	cut55Commit(t, h, cut55Group(t, h, a, a))
	old := cut53Packet([4]byte{192, 0, 2, 1}, 64)
	next := cut53Packet([4]byte{198, 51, 100, 1}, 64)
	oldCopy := cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie_b"])
	windows := 0
	h.commitStageTestHook = func(stage string) {
		switch stage {
		case "c-6":
			windows++
			cut53Verdict(t, program, old, 1)
			cut53Verdict(t, program, next, 2)
		case "c-7", "c-Rc":
			windows++
			if len(cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie"])) != 1 || len(cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie_b"])) != 1 {
				t.Fatal("G4 before Rc: new A and old B must each contain one prefix")
			}
			if !reflect.DeepEqual(oldCopy, cut53KernelMapBytes(t, coll.Maps["sv4_cidr_trie_b"])) {
				t.Fatal("G4 old B prefix released before Rc")
			}
			cut53Verdict(t, program, old, 2)
			cut53Verdict(t, program, next, 1)
		case "c-9":
			windows++
			cut53Verdict(t, program, old, 2)
			cut53Verdict(t, program, next, 1)
		}
	}
	cut55Commit(t, h, cut55Group(t, h, a), cut55Group(t, h, b, b))
	h.commitStageTestHook = nil
	if windows != 4 || len(h.cidrMgr.ListSrcCIDRs()) != 1 {
		t.Fatal("G4 windows or release missing")
	}
	t.Log("CUT55_PREFIX_TRANSITION windows=4 verdicts=8 active_before_rc=1 old_before_rc=1 each_after_rc=1")
}

func TestCut55LogicalAdmissionDeleteFailureELF(t *testing.T) {
	h, _, _ := b7ELF(t)
	r := cut53Pure(false, "r", 17)
	cut55Commit(t, h, cut55Group(t, h, r, r))
	p7DeferredCommit(t, h, cut55Group(t, h, r))
	if !h.pendingLogicalIDs[17] {
		t.Fatal("delete did not create logical debt")
	}
	h.logicalStateCapacity = 1
	original := h.idCounts
	closed, err := original.Clone()
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	h.idCounts = closed
	before := cut55KernelSide(t, h, int(h.activeRuleSlot.Load()))
	n := cut55Rule("n", 18, "203.0.113.18")
	_, rejected := h.DoCommitRules([]CommitGroup{cut55Group(t, h, n, n)})
	h.idCounts = original
	if rejected == nil || rejected.Code != "table_full" || !h.pendingLogicalIDs[17] {
		t.Fatal("M5b delete failure lost debt or admitted", rejected)
	}
	if !reflect.DeepEqual(before, cut55KernelSide(t, h, int(h.activeRuleSlot.Load()))) {
		t.Fatal("M5b delete failure wrote business maps")
	}
	t.Log("CUT55_FAILURE_ROW9A_KERNEL delete_failure=1 debt_retained=1 business_writes=0")
}

func TestCut55FailuresELF(t *testing.T) {
	for _, stage := range []string{"R0", "c-3", "c-4", "c-5", "c-6", "c-7", "Rc", "c-9", "delta-write", "delta-delete"} {
		t.Run(stage, func(t *testing.T) {
			h, _, program := b7ELF(t)
			cut55KernelReceipt(t, h)
			r := cut53Pure(true, "r", 17)
			v := "64"
			r.TTL = &v
			cut55Commit(t, h, cut55Group(t, h, r, r))
			old := int(h.activeRuleSlot.Load())
			before := cut55KernelSide(t, h, old)
			oldConfig := cut53KernelMapBytes(t, h.activeMap())
			oldSelector := cut53KernelMapBytes(t, h.activeConfig)
			reached := false
			h.commitFaultTestHook = func(s string) error {
				if s == stage {
					reached = true
					return errors.New("injected " + stage)
				}
				return nil
			}
			if stage == "R0" || stage == "Rc" {
				h.quiescenceConfirmed = stage == "Rc"
				h.quiescer = cut53Receipt(func() error { reached = true; return errors.New("receipt failure") })
			}
			if stage == "delta-write" || stage == "delta-delete" {
				phase := "write"
				if stage == "delta-delete" {
					phase = "delete"
					r.TTL = nil
				}
				h.mirrorTableFixture = func(slot, kind int) ruleMirrorMap {
					m := h.ruleTablesAt(slot)[kind]
					if slot != old && kind == mirrorCIDR {
						return cut55FaultMap{m, phase, nil}
					}
					return m
				}
				h.commitStageTestHook = func(s string) {
					if s == "c-3" {
						reached = true
					}
				}
			}
			r.PktLenMax = 100
			if stage == "delta-delete" {
				r.PktLenMax = 0
				r.RateLimit = 77
			}
			out, rejection := h.DoCommitRules([]CommitGroup{cut55Group(t, h, r, r)})
			if !reached {
				t.Fatal("failure target not reached")
			}
			if stage == "Rc" || stage == "c-9" {
				if rejection != nil || out.Code != "committed" {
					t.Fatal(out, rejection)
				}
				receipt := "confirmed"
				if stage == "Rc" {
					receipt = "deferred"
					if !reflect.DeepEqual(before, cut55KernelSide(t, h, old)) {
						t.Fatal("deferred touched old side")
					}
				}
				if out.Receipt != receipt {
					t.Fatal(out)
				}
			} else {
				if rejection == nil || rejection.Status != 500 {
					t.Fatal("expected kernel-path failure", out, rejection)
				}
				if int(h.activeRuleSlot.Load()) != old || !reflect.DeepEqual(before, cut55KernelSide(t, h, old)) || !reflect.DeepEqual(oldConfig, cut53KernelMapBytes(t, h.activeMap())) || !reflect.DeepEqual(oldSelector, cut53KernelMapBytes(t, h.activeConfig)) {
					t.Fatal("failure changed visible generation")
				}
			}
			cut53Verdict(t, program, cut53Packet([4]byte{192, 0, 2, 1}, 64), 1)
			t.Logf("CUT55_FAILURE_ELF stage=%s reached=1 verdict_drop=1", stage)
		})
	}
}

func TestCut55FullNonemptyConditionsELF(t *testing.T) {
	h, _, program := b7ELF(t)
	v := "64"
	e, c := cut53Pure(false, "e", 17), cut53Pure(true, "c", 18)
	e.TTL = &v
	c.TTL = &v
	for turn := 0; turn < 2; turn++ {
		if _, err := h.DoAtomicSync([]Rule{e, c}); err != nil {
			t.Fatal(err)
		}
		cut55KernelMirror(t, h)
		if len(cut53KernelMapBytes(t, h.activeCond())) != 1 || len(cut53KernelMapBytes(t, h.activeCidrCond())) != 1 {
			t.Fatal("nonempty condition witness was empty")
		}
		cut53Verdict(t, program, cut53Packet([4]byte{192, 0, 2, 1}, 64), 1)
	}
	t.Log("CUT55_NONEMPTY_FULL generations=2 mirrored_tables=8 condition_rows=4")
}

func TestCut55LogicalStateMoveELF(t *testing.T) {
	h, _, program := b7ELF(t)
	cut55KernelReceipt(t, h)
	r := cut53Pure(false, "r", 17)
	r.DstPort = 80
	r.Action = "rate_limit"
	r.RateLimit = 100
	cut55Commit(t, h, cut55Group(t, h, r, r))
	packet := cut53Packet([4]byte{192, 0, 2, 1}, 64)
	if _, _, err := program.Test(packet); err != nil {
		t.Fatal(err)
	}
	before := cut54OrphanLogicalBytes(t, h)
	for _, kind := range []string{"move", "condition", "pure"} {
		old := r
		switch kind {
		case "move":
			r.DstPort = 0
		case "condition":
			v := "64"
			r.TTL = &v
		case "pure":
			r.TTL = nil
		}
		groups := []CommitGroup{cut55Group(t, h, r, r)}
		if kind == "move" {
			groups = append([]CommitGroup{cut55Group(t, h, old)}, groups...)
		}
		cut55Commit(t, h, groups...)
		if !reflect.DeepEqual(before, cut54OrphanLogicalBytes(t, h)) {
			t.Fatalf("G6 %s reset logical counters or tokens", kind)
		}
	}
	if _, _, err := program.Test(packet); err != nil {
		t.Fatal(err)
	}
	counts, err := ReadLogicalRuleCounters(h.idCounts, 17)
	if err != nil || counts.Match != 2 {
		t.Fatal("G6 counters did not continue", counts, err)
	}
	t.Log("CUT55_LOGICAL_CONTINUITY transitions=3 counter_and_token_preserved=3 match=2")
}

func TestCut55ValidationELF(t *testing.T) {
	h, _, program := b7ELF(t)
	r := cut53Pure(false, "r", 17)
	cut55Commit(t, h, cut55Group(t, h, r, r))
	active := int(h.activeRuleSlot.Load())
	before := cut55KernelSide(t, h, active)
	r.LogicalID = 0
	_, err := h.DoCommitRules([]CommitGroup{cut55Group(t, h, r, r)})
	if err == nil || err.Status != 400 || err.Code != "validation_rejected" || len(err.Groups) != 1 || err.Groups[0].Index != 0 {
		t.Fatal("P1 commit rejection missing", err)
	}
	if active != int(h.activeRuleSlot.Load()) || !reflect.DeepEqual(before, cut55KernelSide(t, h, active)) {
		t.Fatal("P1 failure changed visible generation")
	}
	cut53Verdict(t, program, cut53Packet([4]byte{192, 0, 2, 1}, 64), 1)
	t.Log("CUT55_FAILURE_ROW1_ELF zero_visible=1 verdict_drop=1")
}

func TestCut55ConditionalReceiptELF(t *testing.T) {
	h, _, program := b7ELF(t)
	cut55KernelReceipt(t, h)
	r := cut53Pure(false, "condition", 17)
	oldTTL, newTTL := "64", "64,65"
	r.TTL = &oldTTL
	cut55Commit(t, h, cut55Group(t, h, r, r))
	u := cut55Rule("unrelated", 18, "203.0.113.18")
	p7DeferredCommit(t, h, cut55Group(t, h, u, u))
	if h.quiescenceConfirmed {
		t.Fatal("conditional receipt fixture must require R0")
	}
	slot := int(h.activeRuleSlot.Load())
	before := cut55KernelSide(t, h, slot)
	r.TTL = &newTTL
	reached := false
	h.commitStageTestHook = func(stage string) {
		if stage == "c-Rc" {
			reached = true
			if !reflect.DeepEqual(before, cut55KernelSide(t, h, slot)) {
				t.Fatal("conditional old side repaired before successful Rc")
			}
		}
	}
	result := cut55Commit(t, h, cut55Group(t, h, r, r))
	h.commitStageTestHook = nil
	if !reached || result.Receipt != "confirmed" {
		t.Fatal("conditional Rc success branch not reached", result)
	}
	cut55KernelMirror(t, h)
	cut53Verdict(t, program, cut53Packet([4]byte{192, 0, 2, 1}, 64), 1)
	t.Log("CUT55_CONDITIONAL_RECEIPT old_condition=1 r0_pending=1 rc_success=1 old_side_unchanged_at_rc=1")
}

func TestCut55DirtyPureWriteELF(t *testing.T) {
	h, _, program := b7ELF(t)
	cut55KernelReceipt(t, h)
	seed := cut55Rule("seed", 17, "203.0.113.17")
	cut55Commit(t, h, cut55Group(t, h, seed, seed))
	r := cut53Pure(false, "pure", 18)
	cut55Commit(t, h, cut55Group(t, h, r, r))
	changed := r
	changed.RateLimit = 1
	h.commitFaultTestHook = func(stage string) error {
		if stage == "c-4" {
			return errors.New("P7 dirty preparation abort")
		}
		return nil
	}
	_, rejection := h.DoCommitRules([]CommitGroup{cut55Group(t, h, changed, changed)})
	h.commitFaultTestHook = nil
	if rejection == nil || rejection.Message != "P7 dirty preparation abort" {
		t.Fatal("dirty abort guard", rejection)
	}
	if !h.mirrorReady || len(h.mirrorDirty[mirrorExact]) == 0 || len(h.mirrorDebt[mirrorExact]) != 0 {
		t.Fatal("pure dirty fixture must bypass whole alignment and old-side debt")
	}
	alignments := h.mirrorAlignments
	reached := false
	h.commitStageTestHook = func(stage string) {
		if stage == "c-3" {
			reached = true
			cut55KernelMirror(t, h)
		}
	}
	next := cut55Rule("next", 19, "203.0.113.19")
	cut55Commit(t, h, cut55Group(t, h, next, next))
	h.commitStageTestHook = nil
	if !reached || h.mirrorAlignments != alignments {
		t.Fatal("pure dirty witness did not reach incremental catch-up")
	}
	cut55KernelMirror(t, h)
	cut53Verdict(t, program, cut53Packet([4]byte{192, 0, 2, 1}, 64), 1)
	t.Log("CUT55_DIRTY_PURE aligned_before=1 commit_abort=1 dirty_catchup=1 whole_alignment=0 undeclared_drop=1")
}
