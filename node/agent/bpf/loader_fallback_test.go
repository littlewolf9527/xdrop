//go:build linux && integration

// NEW-UT-04 (§8.1.2): when the chosen pin directory doesn't live on a
// bpf-typed filesystem, the `auto` policy must fall back to a non-pinned
// load with a WARN log instead of crashing the agent; the `require`
// policy must fail loudly; the `disable` policy must skip pinning
// entirely. Run via `go test -tags=integration -race ./bpf/...` on a
// Linux host with CAP_BPF.
//
// We build the collection spec in-process (no xdrop.elf needed) so the
// test is hermetic and doesn't depend on a checked-in BPF object file.
package bpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// newTestSpec produces a minimal 2-map spec that cilium/ebpf can load
// on any kernel ≥ 4.x, so the test exercises the loader's pin plumbing
// rather than the BPF verifier.
func newTestSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"ut04_a": {
				Name:       "ut04_a",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 4,
			},
			"ut04_b": {
				Name:       "ut04_b",
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 4,
			},
		},
	}
}

// TestLoad_AutoFallbackOnNonBPFFS asserts that pointing the pin root at
// a non-bpffs directory (e.g. a plain tmpfs path under /tmp) causes the
// `auto` policy to fall back to a non-pinned load. The returned
// Collection is functional; the Result reports the fallback reason for
// operator-facing logs.
func TestLoad_AutoFallbackOnNonBPFFS(t *testing.T) {
	spec := newTestSpec(t)

	// /tmp is a normal tmpfs on the lab; its statfs magic is not
	// BPF_FS_MAGIC so probeBPFFS fails and Auto falls back.
	coll, res, err := loadFromSpec(spec, Options{
		PinRoot: t.TempDir(), // guaranteed tmpfs on typical hosts
		Mode:    ModeAuto,
	})
	if err != nil {
		t.Fatalf("Load returned error, expected silent fallback: %v", err)
	}
	defer coll.Close()

	if res.EffectiveMode != ModeDisable {
		t.Errorf("EffectiveMode=%q, expected %q", res.EffectiveMode, ModeDisable)
	}
	if res.FallbackReason == "" {
		t.Error("FallbackReason must be populated on bpffs probe failure")
	}
	if res.PinPath != "" {
		t.Errorf("PinPath=%q, expected empty on fallback", res.PinPath)
	}
	// Collection should still be usable.
	if _, ok := coll.Maps["ut04_a"]; !ok {
		t.Error("map ut04_a missing from Collection after fallback")
	}
}

// TestLoad_RequireFailsOnNonBPFFS is the strict-mode counterpart: under
// `require`, the same non-bpffs condition must fail startup with a
// clear error that mentions "require".
func TestLoad_RequireFailsOnNonBPFFS(t *testing.T) {
	spec := newTestSpec(t)

	_, _, err := loadFromSpec(spec, Options{
		PinRoot: t.TempDir(),
		Mode:    ModeRequire,
	})
	if err == nil {
		t.Fatal("Load with Mode=require must return error when bpffs probe fails")
	}
	if !strings.Contains(err.Error(), "require") {
		t.Errorf("error message should reference require mode, got: %v", err)
	}
}

// TestLoad_DisableSkipsProbe proves the `disable` mode never calls the
// bpffs probe — it goes straight to NewCollection, which succeeds
// regardless of the PinRoot filesystem type.
func TestLoad_DisableSkipsProbe(t *testing.T) {
	spec := newTestSpec(t)

	coll, res, err := loadFromSpec(spec, Options{
		PinRoot: "/this/path/never/exists/intentionally",
		Mode:    ModeDisable,
	})
	if err != nil {
		t.Fatalf("Load with Mode=disable returned error: %v", err)
	}
	defer coll.Close()

	if res.EffectiveMode != ModeDisable {
		t.Errorf("EffectiveMode=%q, expected %q", res.EffectiveMode, ModeDisable)
	}
	if res.PinPath != "" {
		t.Errorf("PinPath=%q, expected empty under disable mode", res.PinPath)
	}
	if !strings.Contains(res.FallbackReason, "disable") {
		t.Errorf("FallbackReason should mention disable, got %q", res.FallbackReason)
	}
}

// TestProbeBPFFS_Bpffs confirms the real lab bpffs mount returns no
// error when probed. This is a positive control; without it, a typo in
// probeBPFFS that always returned error would let the fallback tests
// above silently pass for the wrong reason.
func TestProbeBPFFS_Bpffs(t *testing.T) {
	if err := probeBPFFS("/sys/fs/bpf"); err != nil {
		t.Fatalf("probe on /sys/fs/bpf (should be bpffs on lab): %v", err)
	}
}

// TestCompareMapSchema_Mismatches locks in the schema comparator used
// by reconcilePinnedMaps. Each case perturbs one field; "" return means
// no mismatch; any other string means caller should unlink + recreate.
func TestCompareMapSchema_Mismatches(t *testing.T) {
	base := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  16,
		MaxEntries: 100,
		Flags:      0,
	}
	info := &ebpf.MapInfo{
		Type:       base.Type,
		KeySize:    base.KeySize,
		ValueSize:  base.ValueSize,
		MaxEntries: base.MaxEntries,
		Flags:      base.Flags,
	}
	if got := compareMapSchema(info, base); got != "" {
		t.Fatalf("identical schemas should not mismatch, got %q", got)
	}

	cases := []struct {
		name   string
		mutate func(*ebpf.MapInfo)
		want   string
	}{
		{"type drift", func(i *ebpf.MapInfo) { i.Type = ebpf.Array }, "type"},
		{"key drift", func(i *ebpf.MapInfo) { i.KeySize = 4 }, "key_size"},
		{"value drift", func(i *ebpf.MapInfo) { i.ValueSize = 32 }, "value_size"},
		{"entries drift", func(i *ebpf.MapInfo) { i.MaxEntries = 200 }, "max_entries"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mutated := *info
			tc.mutate(&mutated)
			got := compareMapSchema(&mutated, base)
			if got == "" || !strings.Contains(got, tc.want) {
				t.Errorf("mismatch msg %q should mention %q", got, tc.want)
			}
		})
	}
}

// TestCompareMapSchema_FlagsSubsetSemantics locks in the "info must be
// a superset of spec flags" rule, which exists so kernel-auto-added
// bits (DEVMAP's BPF_F_RDONLY_PROG = 0x80 etc.) don't false-positive
// as drift on the second boot. Real drift is when the pinned map is
// MISSING a flag the new spec requires (e.g. operator added
// BPF_F_NO_PREALLOC but the old pin was made without it).
func TestCompareMapSchema_FlagsSubsetSemantics(t *testing.T) {
	specNoPrealloc := &ebpf.MapSpec{
		Type: ebpf.LPMTrie, KeySize: 8, ValueSize: 4, MaxEntries: 100,
		Flags: 0x1, // BPF_F_NO_PREALLOC
	}

	// info has spec's bit + extra kernel-injected bits → match.
	superset := &ebpf.MapInfo{
		Type: specNoPrealloc.Type, KeySize: specNoPrealloc.KeySize,
		ValueSize: specNoPrealloc.ValueSize, MaxEntries: specNoPrealloc.MaxEntries,
		Flags: 0x1 | 0x80, // spec flag + kernel-auto flag
	}
	if got := compareMapSchema(superset, specNoPrealloc); got != "" {
		t.Errorf("kernel-extra bits must not be flagged as drift, got %q", got)
	}

	// info missing the bit spec requires → real drift.
	subset := *superset
	subset.Flags = 0x80 // only kernel bit, missing spec's 0x1
	if got := compareMapSchema(&subset, specNoPrealloc); got == "" {
		t.Error("missing a spec-required flag bit must be reported as drift")
	}

	// Real DEVMAP reproduction: spec=0, kernel reports 0x80 → match.
	devmapSpec := &ebpf.MapSpec{Type: ebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 16, Flags: 0}
	devmapInfo := &ebpf.MapInfo{
		Type: ebpf.DevMap, KeySize: 4, ValueSize: 4, MaxEntries: 16,
		Flags: 0x80,
	}
	if got := compareMapSchema(devmapInfo, devmapSpec); got != "" {
		t.Errorf("DEVMAP first-restart must not be flagged as drift (regression of LT-X5 finding), got %q", got)
	}
}

// TestClearDataMaps_EmptiesPopulatedHashMap exercises the pin-reuse
// reconcile path: after a previous agent life leaves N entries in a
// pinned data map, the next agent must clear them all before the
// controller re-sync fires Update(UpdateNoExist) — otherwise every
// rule would trip ErrKeyExist. Integration-gated because it needs
// CAP_BPF to create a real ebpf.Map.
func TestClearDataMaps_EmptiesPopulatedHashMap(t *testing.T) {
	// Build a Collection with one hash map and populate it.
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"ut04_data": {
				Name:       "ut04_data",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 16,
			},
		},
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Skipf("NewCollection (need CAP_BPF): %v", err)
	}
	defer coll.Close()

	m := coll.Maps["ut04_data"]
	for i := uint32(0); i < 5; i++ {
		if err := m.Put(i, i*7); err != nil {
			t.Fatalf("populate key %d: %v", i, err)
		}
	}

	// Sanity check: 5 entries present before clear.
	beforeCount := 0
	it := m.Iterate()
	var k, v uint32
	for it.Next(&k, &v) {
		beforeCount++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("pre-clear iter err: %v", err)
	}
	if beforeCount != 5 {
		t.Fatalf("population setup wrong: got %d entries, want 5", beforeCount)
	}

	if err := ClearDataMaps(coll, []string{"ut04_data"}); err != nil {
		t.Fatalf("ClearDataMaps: %v", err)
	}

	// Every entry must be gone.
	afterCount := 0
	it2 := m.Iterate()
	for it2.Next(&k, &v) {
		afterCount++
	}
	if err := it2.Err(); err != nil {
		t.Fatalf("post-clear iter err: %v", err)
	}
	if afterCount != 0 {
		t.Errorf("ClearDataMaps left %d entries behind, want 0", afterCount)
	}
}

// TestClearDataMaps_IgnoresMissingNames documents the intentional
// behaviour that a name not present in the Collection is silently
// skipped — useful because main.go passes the full xdrop data-map list
// and some entries may not exist under test-harness specs that build
// only a subset.
func TestClearDataMaps_IgnoresMissingNames(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"present": {
				Name:       "present",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 4,
			},
		},
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Skipf("NewCollection (need CAP_BPF): %v", err)
	}
	defer coll.Close()

	// Mix of a real map and two that don't exist — must not error.
	if err := ClearDataMaps(coll, []string{"absent1", "present", "absent2"}); err != nil {
		t.Errorf("ClearDataMaps with missing names should not error, got %v", err)
	}
}
