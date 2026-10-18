//go:build linux && integration

package api

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// Use the ELF's real map shapes, including all four tries and both PERCPU
// logical tables. Capacities alone are reduced; no programs are loaded here.
func cut53StartupCollections(t *testing.T) (*ebpf.Collection, *ebpf.Collection) {
	t.Helper()
	path := os.Getenv("XDROP_BPF_ELF")
	if path == "" {
		path = "../../bpf/xdrop_main.elf"
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	main, gate := &ebpf.Collection{Maps: map[string]*ebpf.Map{}}, &ebpf.Collection{Maps: map[string]*ebpf.Map{}}
	t.Cleanup(main.Close)
	t.Cleanup(gate.Close)
	names := append(append([]string{}, cut53BusinessNames...), "id_counts", "id_rl_states")
	for _, name := range names {
		source := name
		if source == "whitelist_b" {
			source = "whitelist"
		}
		ms := spec.Maps[source].Copy()
		ms.MaxEntries = 4
		if ms.Pinning != ebpf.PinNone {
			t.Fatalf("unexpected startup fixture pin: %s", name)
		}
		m, err := ebpf.NewMap(ms)
		if err != nil {
			t.Fatal(err)
		}
		owner := main
		if name == "whitelist_b" {
			owner = gate
		}
		owner.Maps[name] = m
		key := make([]byte, m.KeySize())
		var value any = make([]byte, m.ValueSize())
		if m.Type() == ebpf.PerCPUHash {
			cpus, err := ebpf.PossibleCPU()
			if err != nil {
				t.Fatal(err)
			}
			width := uint32(16)
			if name == "id_counts" {
				width = 40
			}
			if m.ValueSize() != width {
				t.Fatalf("unexpected logical width=%d", m.ValueSize())
			}
			value = atomicBatchBuffer(width, cpus).Interface()
		}
		if err := m.Put(key, value); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	return main, gate
}

func TestCut53StartupKernelFaultMatrix(t *testing.T) {
	names := append(append([]string{}, cut53BusinessNames...), "receipt", "id_counts", "id_rl_states", "success")
	for _, target := range names {
		t.Run(target, func(t *testing.T) {
			main, gate := cut53StartupCollections(t)
			if target != "receipt" && target != "success" {
				m := main.Maps[target]
				if target == "whitelist_b" {
					m = gate.Maps[target]
				}
				b7Freeze(t, m)
			}
			factory := newQuiescer
			defer func() { newQuiescer = factory }()
			receipts := 0
			newQuiescer = func() (quiescer, error) {
				q, err := newKernelQuiescer()
				if err != nil {
					return nil, err
				}
				t.Cleanup(func() { q.Close() })
				if target == "receipt" {
					b7Freeze(t, q.outer)
				}
				return cut53Receipt(func() error {
					receipts++
					for _, name := range cut53BusinessNames {
						m := main.Maps[name]
						if name == "whitelist_b" {
							m = gate.Maps[name]
						}
						if len(cut53KernelMapBytes(t, m)) != 0 {
							t.Fatalf("startup receipt before business empty: %s", name)
						}
					}
					for _, name := range []string{"id_counts", "id_rl_states"} {
						if len(cut53KernelMapBytes(t, main.Maps[name])) != 1 {
							t.Fatalf("startup logical state cleared before receipt: %s", name)
						}
					}
					return q.Quiesce()
				}), nil
			}
			err := PreparePinnedStartup(main, gate)
			// The main.go AST test independently requires Fatalf before NewHandlers.
			constructorReached := err == nil
			if target != "success" {
				if constructorReached || err == nil || !strings.Contains(err.Error(), target) {
					t.Fatalf("M5c kernel failure did not refuse before NewHandlers: %s error=%v", target, err)
				}
			} else {
				if err != nil || !constructorReached {
					t.Fatal(err)
				}
				for _, coll := range []*ebpf.Collection{main, gate} {
					for name, m := range coll.Maps {
						if len(cut53KernelMapBytes(t, m)) != 0 {
							t.Fatalf("restart orphan: %s", name)
						}
					}
				}
			}
			want := 0
			if target == "receipt" || target == "id_counts" || target == "id_rl_states" || target == "success" {
				want = 1
			}
			if receipts != want {
				t.Fatalf("receipt ordering got=%d want=%d", receipts, want)
			}
			t.Logf("CUT53_STARTUP_KERNEL target=%s receipts=%d constructor_reached=%v", target, receipts, constructorReached)
		})
	}
	t.Log(fmt.Sprintf("CUT53_STARTUP_KERNEL business_faults=%d receipt_faults=1 logical_faults=2 success=1", len(cut53BusinessNames)))
}
