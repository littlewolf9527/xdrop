package ifmgr

import (
	"testing"
)

// TestRestoreInterface_NoStateReturnsNil verifies that RestoreInterface
// returns nil when the interface was never configured (no saved state to
// restore).
func TestRestoreInterface_NoStateReturnsNil(t *testing.T) {
	m := NewInterfaceManager()
	if err := m.RestoreInterface("nonexistent0"); err != nil {
		t.Errorf("RestoreInterface on unknown interface: got %v, want nil", err)
	}
}

// TestRestoreAll_EmptyReturnsNil verifies RestoreAll on an empty manager is a
// silent no-op.
func TestRestoreAll_EmptyReturnsNil(t *testing.T) {
	m := NewInterfaceManager()
	if err := m.RestoreAll(); err != nil {
		t.Errorf("RestoreAll on empty manager: got %v, want nil", err)
	}
}

// TestRestoreInterface_AggregatesSubOperationErrors verifies BUG-027 fix:
// each sub-restore failure is joined into the returned error rather than
// being silently discarded.
//
// We seed the manager with a state that will force every sub-operation to
// attempt (PROMISC off, offload restore, down), targeting a nonexistent
// interface name so every shell-out fails. RestoreInterface should then
// return a joined error containing multiple wrapped failures.
func TestRestoreInterface_AggregatesSubOperationErrors(t *testing.T) {
	m := NewInterfaceManager()
	const badName = "xdrop_test_no_such_iface_42"
	m.originalStates[badName] = &InterfaceState{
		Name:       badName,
		WasUp:      false, // force setInterfaceDown
		WasPromisc: false, // force setPromiscuous off
		GRO:        true,  // force setOffload gro on
		LRO:        true,
		TSO:        true,
	}

	err := m.RestoreInterface(badName)
	if err == nil {
		t.Fatal("expected aggregated error, got nil")
	}

	// After Restore, state must be cleared regardless of success/failure so a
	// repeat call is idempotent.
	if _, stillThere := m.originalStates[badName]; stillThere {
		t.Error("originalStates entry was not cleared after RestoreInterface")
	}

	// The joined error must include at least 2 distinct sub-errors (promisc,
	// offload, down). errors.Join formats them on separate lines.
	msg := err.Error()
	lines := 0
	for _, c := range msg {
		if c == '\n' {
			lines++
		}
	}
	if lines < 1 {
		t.Errorf("expected aggregated error with multiple lines, got: %q", msg)
	}
}

// TestRestoreAll_AggregatesPerInterfaceErrors verifies RestoreAll joins
// errors from each interface's RestoreInterface call.
func TestRestoreAll_AggregatesPerInterfaceErrors(t *testing.T) {
	m := NewInterfaceManager()
	for _, name := range []string{"xdrop_test_missing_a", "xdrop_test_missing_b"} {
		m.originalStates[name] = &InterfaceState{
			Name:       name,
			WasPromisc: false, // forces at least one failing operation per iface
		}
	}

	err := m.RestoreAll()
	if err == nil {
		t.Fatal("expected aggregated error for 2 missing interfaces, got nil")
	}
}
