package bpf

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

type cut54TailSlot struct {
	occupied bool
	failure  error
	calls    int
}

func (m *cut54TailSlot) Delete(key interface{}) error {
	m.calls++
	if key != uint32(0) {
		return errors.New("wrong tail slot")
	}
	if m.failure != nil {
		return m.failure
	}
	if !m.occupied {
		return syscall.ENOENT
	}
	m.occupied = false
	return nil
}
func TestCut54RetiredTailSlot(t *testing.T) {
	for _, name := range []string{"new_map", "pinned_slot", "non_enoent"} {
		t.Run(name, func(t *testing.T) {
			m := &cut54TailSlot{occupied: name == "pinned_slot"}
			if name == "non_enoent" {
				m.failure = syscall.EPERM
			}
			err := ClearRetiredTailSlot(m)
			if name == "non_enoent" {
				if !errors.Is(err, syscall.EPERM) || !strings.Contains(err.Error(), "prog_tail_map slot 0") {
					t.Fatalf("non-ENOENT must refuse startup: %v", err)
				}
			} else if err != nil || m.occupied {
				t.Fatalf("retired slot must be empty without rejecting startup: %v occupied=%v", err, m.occupied)
			}
			if m.calls != 1 {
				t.Fatalf("slot 0 delete attempts=%d want=1", m.calls)
			}
		})
	}
	t.Log("CUT54_SLOT0 cases=3 empty_accept=1 pinned_clear=1 error_refuse=1")
}
