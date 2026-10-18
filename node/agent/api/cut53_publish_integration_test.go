//go:build linux && integration

package api

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type cut53KernelConfigMap struct {
	*ebpf.Map
	tracker *cut53ConfigMap
	bad     *ebpf.Map
}

func (m *cut53KernelConfigMap) Lookup(key, out interface{}) error {
	_, err := m.tracker.operation("lookup", key)
	if err != nil {
		return m.bad.Lookup(key, out)
	}
	return m.Map.Lookup(key, out)
}
func (m *cut53KernelConfigMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	_, err := m.tracker.operation("update", key)
	if err != nil {
		return m.bad.Update(key, value, flags)
	}
	return m.Map.Update(key, value, flags)
}
func TestCut53PublishKernelEveryFailure(t *testing.T) {
	for _, wl := range []bool{true} {
		call := func(h *Handlers) error {
			if wl {
				return h.publishConfigUpdateForWLSync(3, [64]int{1})
			}
			return h.publishConfigUpdateForWLSync(3, [64]int{1})
		}
		control, trace, _ := cut53PublishFixture("")
		if err := call(control); err != nil {
			t.Fatal(err)
		}
		for _, point := range trace.trace {
			t.Run(fmt.Sprintf("wl=%v/%s", wl, point), func(t *testing.T) {
				h, _, _ := b7Handler(t)
				fault := &cut53ConfigFault{target: point}
				wrap := func(name string, m *ebpf.Map) configPublishMap {
					bad, err := m.Clone()
					if err != nil {
						t.Fatal(err)
					}
					if err := bad.Close(); err != nil {
						t.Fatal(err)
					}
					return &cut53KernelConfigMap{m, &cut53ConfigMap{name: name, fault: fault, calls: map[string]int{}}, bad}
				}
				h.configPublishFixture = &configPublishTableSet{wrap("shadow", h.shadowMap()), wrap("active", h.activeMap()), wrap("selector", h.activeConfig)}
				before, slot := cut53KernelMapBytes(t, h.activeConfig), h.activeSlot
				err := call(h)
				if err == nil || fault.hits != 1 || !errors.Is(err, unix.EBADF) {
					t.Fatalf("TD085 syscall target not reached: point=%s hits=%d error=%v", point, fault.hits, err)
				}
				if h.activeSlot != slot || !reflect.DeepEqual(before, cut53KernelMapBytes(t, h.activeConfig)) {
					t.Fatalf("TD085 kernel selector flipped after %s", point)
				}
			})
		}
		t.Logf("CUT53_TD085_KERNEL wl=%v fault_cells=%d syscall_errors=EBADF selector_flips=0", wl, len(trace.trace))
	}
}
