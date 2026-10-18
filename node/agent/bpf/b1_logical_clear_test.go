//go:build linux && integration

package bpf

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func b1KeyCount(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	var previous any
	count := 0
	for {
		var next uint32
		if err := m.NextKey(previous, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return count
			}
			t.Fatal(err)
		}
		count++
		previous = next
	}
}

func TestB1LogicalStartupClear(t *testing.T) {
	spec, _, _ := loadMainELF(t)
	for _, name := range []string{"id_counts", "id_rl_states"} {
		t.Run(name, func(t *testing.T) {
			m, err := ebpf.NewMap(spec.Maps[name])
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			values := nsLogicalBuffer(name, mustPossibleCPUs(t))
			if values.Len() < 2 {
				t.Fatal("startup clear requires multiple possible CPUs")
			}
			for cpu := 0; cpu < values.Len(); cpu++ {
				values.Index(cpu).Index(0).SetUint(uint64(cpu + 1))
				values.Index(cpu).Index(1).SetUint(uint64(cpu + 11))
			}
			for id := uint32(1); id <= 7; id++ {
				if err := m.Put(id, values.Interface()); err != nil {
					t.Fatal(err)
				}
			}
			if got := b1KeyCount(t, m); got != 7 {
				t.Fatalf("startup clear precondition rows=%d want=7", got)
			}
			// main.main invokes this same production function after ClearDataMaps.
			deleted, err := ClearMapKeys(m)
			if err != nil {
				t.Fatal(err)
			}
			if remaining := b1KeyCount(t, m); remaining != 0 {
				t.Fatalf("B1_STARTUP_CLEAR map=%s remaining=%d want=0 deleted=%d", name, remaining, deleted)
			}
			if deleted != 7 {
				t.Fatalf("startup clear deleted=%d want=7", deleted)
			}
			if deleted, err = ClearMapKeys(m); err != nil || deleted != 0 {
				t.Fatalf("empty clear deleted=%d err=%v", deleted, err)
			}
			t.Logf("B1_STARTUP_CLEAR map=%s CPUs=%d populated=7 deleted=7 remaining=0 empty_retry=0", name, values.Len())
		})
	}
}

func TestB1LogicalClearErrors(t *testing.T) {
	spec, _, _ := loadMainELF(t)
	t.Run("iteration-closed-fd", func(t *testing.T) {
		m, err := ebpf.NewMap(spec.Maps["id_counts"])
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		deleted, err := ClearMapKeys(m)
		if err == nil {
			t.Fatal("B1_CLEAR_ERROR iteration error swallowed: got nil want non-nil")
		}
		if deleted != 0 || !strings.Contains(err.Error(), "iterate keys") {
			t.Fatalf("iteration error deleted=%d err=%v", deleted, err)
		}
		t.Logf("B1_CLEAR_ERROR iteration deleted=%d err=%v", deleted, err)
	})
	t.Run("deletion-frozen-map", func(t *testing.T) {
		m, err := ebpf.NewMap(spec.Maps["id_rl_states"])
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		if err := m.Put(uint32(1), make([][2]uint64, mustPossibleCPUs(t))); err != nil {
			t.Fatal(err)
		}
		if err := m.Freeze(); err != nil {
			t.Fatal(err)
		}
		deleted, err := ClearMapKeys(m)
		if err == nil || !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "delete key") || deleted != 0 {
			t.Fatalf("B1_CLEAR_ERROR deletion deleted=%d err=%v want=0/EPERM", deleted, err)
		}
		if got := b1KeyCount(t, m); got != 1 {
			t.Fatalf("failed deletion rows=%d want=1", got)
		}
		t.Logf("B1_CLEAR_ERROR deletion deleted=%d err=%v remaining=1", deleted, err)
	})
}
