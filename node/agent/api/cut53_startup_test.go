package api

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type cut53Receipt func() error

func (f cut53Receipt) Quiesce() error { return f() }

type cut53StartupMap struct {
	name, fail string
	present    bool
	traversed  bool
	trace      *[]string
}

func (*cut53StartupMap) KeySize() uint32 { return 4 }
func (m *cut53StartupMap) NextKey(cursor, out interface{}) error {
	phase := "enumerate"
	if m.traversed && cursor == nil {
		phase = "recount"
	}
	if m.fail == phase {
		return fmt.Errorf("fault %s %s", m.name, phase)
	}
	if cursor != nil {
		m.traversed = true
		return ebpf.ErrKeyNotExist
	}
	if phase == "recount" {
		*m.trace = append(*m.trace, "zero:"+m.name)
	}
	if !m.present {
		return ebpf.ErrKeyNotExist
	}
	copy(*out.(*[]byte), []byte{7, 0, 0, 0})
	return nil
}
func (m *cut53StartupMap) Delete(interface{}) error {
	if m.fail == "delete" {
		return fmt.Errorf("fault %s delete", m.name)
	}
	if m.fail != "nonempty" {
		m.present = false
	}
	return nil
}

var cut53BusinessNames = []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b", "cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b", "whitelist", "whitelist_b"}

func TestCut53StartupFaultMatrix(t *testing.T) {
	all := append(append([]string{}, cut53BusinessNames...), "id_counts", "id_rl_states")
	for _, target := range all {
		for _, phase := range []string{"enumerate", "delete", "recount", "nonempty"} {
			t.Run(target+"/"+phase, func(t *testing.T) {
				var trace []string
				var business, logical []startupTable
				for i, name := range all {
					m := &cut53StartupMap{name: name, present: true, trace: &trace}
					if name == target {
						m.fail = phase
					}
					v := startupTable{name, m}
					if i < len(cut53BusinessNames) {
						business = append(business, v)
					} else {
						logical = append(logical, v)
					}
				}
				called := false
				err := clearStartupTables(business, logical, cut53Receipt(func() error { trace = append(trace, "receipt"); return nil }))
				if err == nil {
					called = true
				}
				wantPhase := phase
				if phase == "nonempty" {
					wantPhase = "recount"
				}
				wantStage := "logical"
				for _, name := range cut53BusinessNames {
					if name == target {
						wantStage = "business"
					}
				}
				if called || err == nil || !strings.Contains(err.Error(), wantStage+" "+target+": "+wantPhase+":") {
					t.Fatalf("M5c failure did not refuse startup before NewHandlers: target=%s phase=%s error=%v", target, phase, err)
				}
			})
		}
	}
	for _, failReceipt := range []bool{false, true} {
		t.Run(fmt.Sprintf("receipt_failure=%v", failReceipt), func(t *testing.T) {
			var trace []string
			var business, logical []startupTable
			for i, name := range all {
				v := startupTable{name, &cut53StartupMap{name: name, present: true, trace: &trace}}
				if i < len(cut53BusinessNames) {
					business = append(business, v)
				} else {
					logical = append(logical, v)
				}
			}
			err := clearStartupTables(business, logical, cut53Receipt(func() error {
				trace = append(trace, "receipt")
				if failReceipt {
					return fmt.Errorf("receipt injected")
				}
				return nil
			}))
			want := []string{}
			for _, name := range cut53BusinessNames {
				want = append(want, "zero:"+name)
			}
			want = append(want, "receipt")
			if !failReceipt {
				want = append(want, "zero:id_counts", "zero:id_rl_states")
			}
			if !reflect.DeepEqual(trace, want) || (err != nil) != failReceipt || (failReceipt && !strings.Contains(err.Error(), "startup receipt:")) {
				t.Fatalf("M5c order=%v want=%v error=%v", trace, want, err)
			}
		})
	}
	t.Logf("CUT54_STARTUP business_tables=%d logical_tables=%d map_fault_cells=%d receipt_fault_cells=1 positive=1 new_handlers_on_failure=0", len(cut53BusinessNames), len(all)-len(cut53BusinessNames), len(all)*4)
}

func TestCut53StartupReceiptCreationFailure(t *testing.T) {
	main, gate := &ebpf.Collection{Maps: map[string]*ebpf.Map{}}, &ebpf.Collection{Maps: map[string]*ebpf.Map{}}
	for _, name := range cut53BusinessNames {
		main.Maps[name] = &ebpf.Map{}
	}
	gate.Maps["whitelist_b"] = &ebpf.Map{}
	main.Maps["id_counts"], main.Maps["id_rl_states"] = &ebpf.Map{}, &ebpf.Map{}
	old := newQuiescer
	defer func() { newQuiescer = old }()
	hits := 0
	newQuiescer = func() (quiescer, error) { hits++; return nil, fmt.Errorf("create fault") }
	if err := PreparePinnedStartup(main, gate); err == nil || !strings.Contains(err.Error(), "create startup receipt") || hits != 1 {
		t.Fatalf("receipt factory refusal hits=%d err=%v", hits, err)
	}
}
