//go:build linux && integration

package api

import (
	"testing"

	"github.com/cilium/ebpf"
)

func b7SetLogicalCounts(t *testing.T, h *Handlers, id uint32, match, drop uint64) {
	t.Helper()
	n, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 || n == 0 {
		t.Fatalf("invalid logical fixture id=%d cpus=%d", id, n)
	}
	values := make([]LogicalRuleCounters, n)
	values[0] = LogicalRuleCounters{Match: match, Drop: drop}
	if err := h.idCounts.Put(id, values); err != nil {
		t.Fatal(err)
	}
}
