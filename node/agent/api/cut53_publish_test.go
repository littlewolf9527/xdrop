package api

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type cut53ConfigFault struct {
	target      string
	trace       []string
	hits, flips int
}
type cut53ConfigMap struct {
	name  string
	data  map[uint32][8]byte
	fault *cut53ConfigFault
	calls map[string]int
}

func (m *cut53ConfigMap) operation(op string, key interface{}) (uint32, error) {
	i := binary.LittleEndian.Uint32(key.([]byte))
	base := fmt.Sprintf("%s/%s/%d", m.name, op, i)
	m.calls[base]++
	point := fmt.Sprintf("%s/%d", base, m.calls[base])
	m.fault.trace = append(m.fault.trace, point)
	if point == m.fault.target {
		m.fault.hits++
		return i, fmt.Errorf("injected %s", point)
	}
	return i, nil
}
func (m *cut53ConfigMap) Lookup(key, out interface{}) error {
	i, err := m.operation("lookup", key)
	if err != nil {
		return err
	}
	v, ok := m.data[i]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*out.(*[8]byte) = v
	return nil
}
func (m *cut53ConfigMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	i, err := m.operation("update", key)
	if err != nil {
		return err
	}
	if flags != ebpf.UpdateExist {
		return fmt.Errorf("unexpected update flag %v", flags)
	}
	if _, ok := m.data[i]; !ok {
		return ebpf.ErrKeyNotExist
	}
	var v [8]byte
	copy(v[:], value.([]byte))
	m.data[i] = v
	if m.name == "selector" {
		m.fault.flips++
	}
	return nil
}
func cut53PublishFixture(target string) (*Handlers, *cut53ConfigFault, *cut53ConfigMap) {
	f := &cut53ConfigFault{target: target}
	makeMap := func(name string) *cut53ConfigMap {
		m := &cut53ConfigMap{name: name, data: map[uint32][8]byte{}, fault: f, calls: map[string]int{}}
		for i := uint32(0); i < ConfigMapEntries; i++ {
			var v [8]byte
			binary.LittleEndian.PutUint64(v[:], uint64(i+10))
			m.data[i] = v
		}
		return m
	}
	active, shadow, selector := makeMap("active"), makeMap("shadow"), makeMap("selector")
	selector.data[0] = [8]byte{}
	h := &Handlers{configPublishFixture: &configPublishTableSet{shadow, active, selector}}
	return h, f, selector
}
func TestCut53PublishEveryFailure(t *testing.T) {
	for _, wl := range []bool{true} {
		call := func(h *Handlers) error {
			if wl {
				return h.publishConfigUpdateForWLSync(3, [64]int{1})
			}
			return h.publishConfigUpdateForWLSync(3, [64]int{1})
		}
		h, control, _ := cut53PublishFixture("")
		if err := call(h); err != nil {
			t.Fatal(err)
		}
		want := int(2*ConfigMapEntries) + 11 // seven dynamic updates, three count reads, one selector.
		if wl {
			want = int(2*ConfigMapEntries) + 4
		}
		if len(control.trace) != want || control.flips != 1 || h.activeSlot != 1 {
			t.Fatalf("positive publish wl=%v operations=%d want=%d flips=%d", wl, len(control.trace), want, control.flips)
		}
		for _, point := range control.trace {
			t.Run(fmt.Sprintf("wl=%v/%s", wl, point), func(t *testing.T) {
				h, f, selector := cut53PublishFixture(point)
				before := selector.data[0]
				err := call(h)
				if err == nil || f.hits != 1 {
					t.Fatalf("TD085 target was not reached exactly once: %s hits=%d err=%v", point, f.hits, err)
				}
				if f.flips != 0 || h.activeSlot != 0 || !reflect.DeepEqual(before, selector.data[0]) {
					t.Fatalf("TD085 pre-flip failure flipped selector: %s", point)
				}
			})
		}
		t.Logf("CUT53_TD085 wl=%v fault_cells=%d target_hits=1 flips_on_failure=0 positive_flips=1", wl, want)
	}
}

func TestCut54PublishDoesNotWriteAnomalyCount(t *testing.T) {
	h, control, _ := cut53PublishFixture("")
	h.rules = map[string]StoredRule{"anomaly": {LogicalID: 17, Action: "drop", MatchAnomaly: AnomalyInvalid}}
	h.cidrRules = map[string]StoredCIDRRule{"cidr-anomaly": {LogicalID: 18, Action: "drop", MatchAnomaly: AnomalyBadFragment}}
	if err := h.publishConfigUpdateForWLSync(3, [64]int{1}); err != nil {
		t.Fatal(err)
	}
	// The first 2*ConfigMapEntries operations copy each active slot to shadow.
	// Dynamic writes follow that segment, ending at the selector publication.
	prefix := fmt.Sprintf("shadow/update/%d/", ConfigAnomalyRuleCount)
	copies, dynamicWrites := 0, 0
	for i, point := range control.trace {
		if !strings.HasPrefix(point, prefix) {
			continue
		}
		if i < int(2*ConfigMapEntries) {
			copies++
		} else {
			dynamicWrites++
		}
	}
	if copies != 1 || dynamicWrites != 0 {
		t.Fatalf("B3 anomaly slot copy=%d dynamic writes=%d want=1/0", copies, dynamicWrites)
	}
	t.Log("CUT54_ANOMALY_SLOT anomaly_rules=2 copied_slots=1 dynamic_writes=0")
}
