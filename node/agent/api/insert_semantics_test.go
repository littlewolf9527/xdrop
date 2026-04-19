//go:build linux && integration

// NEW-UT-01 (§7 + §8.1.2): xdrop's rule-insert path relies on duplicate-key
// rejection. Pre-migration goebpf.Insert used BPF_NOEXIST; post-migration we
// must use cilium Update(UpdateNoExist) to preserve fail-on-duplicate
// semantics. Substituting Put (BPF_ANY) would silently allow overwrites and
// let two rules alias the same slot.
//
// This is tagged `integration` because it spins up a real in-process
// ebpf.Map via ebpf.NewMap, which requires CAP_BPF / root. Run on the lab
// host with: `go test -tags=integration -race ./api/...`.
package api

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func newHashMapForSemantics(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xdrop_sem",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 8,
	})
	if err != nil {
		t.Skipf("ebpf.NewMap failed (insufficient privileges or kernel?): %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// Duplicate Update(UpdateNoExist) must return ErrKeyExist — this is the
// contract xdrop's AddRule rejection relies on.
func TestInsertSemantics_UpdateNoExistRejectsDuplicate(t *testing.T) {
	m := newHashMapForSemantics(t)

	key := uint32(1)
	val := uint32(42)

	if err := m.Update(key, val, ebpf.UpdateNoExist); err != nil {
		t.Fatalf("first Update(UpdateNoExist) unexpectedly failed: %v", err)
	}

	err := m.Update(key, val, ebpf.UpdateNoExist)
	if err == nil {
		t.Fatal("second Update(UpdateNoExist) must return an error on existing key")
	}
	if !errors.Is(err, ebpf.ErrKeyExist) {
		t.Errorf("expected ebpf.ErrKeyExist, got %v", err)
	}
}

// UpdateExist must fail on missing key — preserves goebpf.Update semantics
// for code paths that assume "update only, never create".
func TestInsertSemantics_UpdateExistRejectsMissing(t *testing.T) {
	m := newHashMapForSemantics(t)

	key := uint32(99)
	val := uint32(0xdead)

	err := m.Update(key, val, ebpf.UpdateExist)
	if err == nil {
		t.Fatal("Update(UpdateExist) on missing key must return an error")
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("expected ebpf.ErrKeyNotExist, got %v", err)
	}
}

// Put (= UpdateAny) must overwrite without error — used by xdrop for
// config-map / devmap writes where upsert is the intended semantics.
func TestInsertSemantics_PutOverwritesSilently(t *testing.T) {
	m := newHashMapForSemantics(t)

	key := uint32(7)
	if err := m.Put(key, uint32(1)); err != nil {
		t.Fatalf("initial Put failed: %v", err)
	}
	if err := m.Put(key, uint32(2)); err != nil {
		t.Fatalf("overwrite Put must succeed, got: %v", err)
	}

	var got uint32
	if err := m.Lookup(key, &got); err != nil {
		t.Fatalf("Lookup after Put: %v", err)
	}
	if got != 2 {
		t.Errorf("Put did not overwrite: got %d, want 2", got)
	}
}
