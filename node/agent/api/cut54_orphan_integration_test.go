//go:build linux && integration

package api

import (
	"testing"
)

func TestCut54OwnerInvariantELF(t *testing.T) {
	for _, isCIDR := range []bool{false, true} {
		h, _, _ := b7Handler(t)
		rows := []Rule{cut53Pure(isCIDR, "full", 1), cut53Pure(isCIDR, "single", 2), cut53Pure(isCIDR, "batch-a", 3), cut53Pure(isCIDR, "batch-b", 4)}
		for i := range rows {
			rows[i].DstPort = uint16(80 + i)
		}
		if out, err := h.DoAtomicSync(rows[:1]); err != nil || out.Added != 1 {
			t.Fatal(out, err)
		}
		cut54AssertOwnerInvariant(t, h)
		b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, rows[1], rows[1])}), 200, "committed")
		cut54AssertOwnerInvariant(t, h)
		b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, rows[2], rows[2]), cut55Group(t, h, rows[3], rows[3])}), 200, "committed")
		if len(h.rules)+len(h.cidrRules) != 4 {
			t.Fatal("multi-group commit did not add both owners")
		}
		cut54AssertOwnerInvariant(t, h)
		b7Code(t, cut55HTTP(t, h, []CommitGroup{cut55Group(t, h, rows[1])}), 200, "committed")
		cut54AssertOwnerInvariant(t, h)
	}
	t.Log("CUT54_OWNER_INVARIANT_ELF stages=8 full=2 commit_one=2 commit_two=2 retire=2")
}

// Shared by the surviving commit logical-state move witness.
func cut54OrphanLogicalBytes(t *testing.T, h *Handlers) []map[string]string {
	return []map[string]string{cut53KernelMapBytes(t, h.idCounts), cut53KernelMapBytes(t, h.idRLStates)}
}
