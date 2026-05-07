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
	"fmt"
	"os"
	"path/filepath"
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

// T52: ModeDisable + MapReplacements — gate must use the replacement map,
// not create its own copy. Verifies P1-1 fix: newColl() passes MapReplacements
// even in disable mode.
func TestLoad_DisableWithMapReplacements(t *testing.T) {
	// Create "main" collection with a shared map
	mainSpec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"shared_map": {
				Name:       "shared_map",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 4,
			},
		},
	}
	mainColl, err := ebpf.NewCollection(mainSpec)
	if err != nil {
		t.Skipf("NewCollection (need CAP_BPF): %v", err)
	}
	defer mainColl.Close()

	sharedMap := mainColl.Maps["shared_map"]
	if sharedMap == nil {
		t.Fatal("shared_map not found in mainColl")
	}

	// Write a marker value to the shared map
	key := uint32(42)
	val := uint32(99)
	if err := sharedMap.Update(key, val, ebpf.UpdateNoExist); err != nil {
		t.Fatalf("write marker to shared_map: %v", err)
	}

	// Create "gate" spec that also declares shared_map — it will be replaced
	gateSpec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"shared_map": {
				Name:       "shared_map",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 4,
			},
			"gate_only": {
				Name:       "gate_only",
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 4,
			},
		},
	}

	gateColl, res, err := loadFromSpec(gateSpec, Options{
		Mode: ModeDisable,
		MapReplacements: map[string]*ebpf.Map{
			"shared_map": sharedMap,
		},
	})
	if err != nil {
		t.Fatalf("Load gate with disable+MapReplacements: %v", err)
	}
	defer gateColl.Close()

	if res.EffectiveMode != ModeDisable {
		t.Errorf("EffectiveMode=%q, want disable", res.EffectiveMode)
	}

	// The critical check: gate's "shared_map" must be the SAME kernel map as main's.
	// If MapReplacements was dropped, gate would have its own empty copy.
	gateShared := gateColl.Maps["shared_map"]
	if gateShared == nil {
		t.Fatal("shared_map not in gateColl")
	}

	var readVal uint32
	if err := gateShared.Lookup(key, &readVal); err != nil {
		t.Fatalf("lookup marker in gate's shared_map: %v — MapReplacements likely not applied", err)
	}
	if readVal != val {
		t.Errorf("gate shared_map[%d]=%d, want %d — MapReplacements not sharing kernel map", key, readVal, val)
	}
}

// T53: ModeAuto + non-bpffs PinRoot + MapReplacements preservation.
// Verifies the bpffs-probe-fallback path (loader.go:162-167) calls newColl
// with MapReplacements, so the gate collection references mainColl's kernel
// map rather than creating its own private copy.
func TestLoad_AutoFallbackWithMapReplacements(t *testing.T) {
	mainSpec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"t53_shared": {
				Name: "t53_shared", Type: ebpf.Hash,
				KeySize: 4, ValueSize: 4, MaxEntries: 4,
			},
		},
	}
	mainColl, err := ebpf.NewCollection(mainSpec)
	if err != nil {
		t.Skipf("NewCollection (need CAP_BPF): %v", err)
	}
	defer mainColl.Close()

	sharedMap := mainColl.Maps["t53_shared"]
	key := uint32(100)
	val := uint32(200)
	if err := sharedMap.Update(key, val, ebpf.UpdateNoExist); err != nil {
		t.Fatalf("write marker to t53_shared: %v", err)
	}

	gateSpec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"t53_shared": {
				Name: "t53_shared", Type: ebpf.Hash,
				KeySize: 4, ValueSize: 4, MaxEntries: 4,
			},
			"t53_gate": {
				Name: "t53_gate", Type: ebpf.Hash,
				KeySize: 4, ValueSize: 4, MaxEntries: 4,
			},
		},
	}

	// t.TempDir() is tmpfs — probeBPFFS fails, Auto falls back.
	gateColl, res, err := loadFromSpec(gateSpec, Options{
		PinRoot: t.TempDir(),
		Mode:    ModeAuto,
		MapReplacements: map[string]*ebpf.Map{
			"t53_shared": sharedMap,
		},
	})
	if err != nil {
		t.Fatalf("Auto+non-bpffs must fall back silently, not error: %v", err)
	}
	defer gateColl.Close()

	if res.EffectiveMode != ModeDisable {
		t.Errorf("EffectiveMode=%q, want disable (bpffs-fallback)", res.EffectiveMode)
	}
	if res.FallbackReason == "" {
		t.Error("FallbackReason must be set when bpffs probe fails")
	}
	if res.PinPath != "" {
		t.Errorf("PinPath=%q, want empty on fallback", res.PinPath)
	}

	// Critical: MapReplacements must be applied even in the fallback path,
	// so gate and main share the same kernel map (no split-brain).
	gateShared := gateColl.Maps["t53_shared"]
	if gateShared == nil {
		t.Fatal("t53_shared not found in gateColl after Auto fallback")
	}
	var readVal uint32
	if err := gateShared.Lookup(key, &readVal); err != nil {
		t.Fatalf("lookup marker in gate t53_shared: %v — MapReplacements not applied in bpffs fallback", err)
	}
	if readVal != val {
		t.Errorf("gate t53_shared[%d]=%d, want %d — split-brain: MapReplacements dropped on fallback", key, readVal, val)
	}
}

// T54: ModeAuto + real bpffs PinRoot + MapReplacements, pinning succeeds.
// Verifies newCollPinned (loader.go:138-145) also applies MapReplacements.
// The pin-retry-fallback path (loader.go:235-239) calls the same newColl
// helper as T52/T53; this test closes the newCollPinned gap and also
// validates the P3-1 fix: EffectiveMode returns the input mode (ModeAuto),
// not a hardcoded constant.
func TestLoad_AutoSucceedsWithMapReplacements(t *testing.T) {
	if err := probeBPFFS("/sys/fs/bpf"); err != nil {
		t.Skipf("bpffs not available (need /sys/fs/bpf): %v", err)
	}

	pinRoot := filepath.Join("/sys/fs/bpf", fmt.Sprintf("xdrop-t54-%d", os.Getpid()))
	t.Cleanup(func() {
		os.Remove(filepath.Join(pinRoot, "t54_gate"))
		os.Remove(pinRoot)
	})

	mainSpec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"t54_shared": {
				Name: "t54_shared", Type: ebpf.Hash,
				KeySize: 4, ValueSize: 4, MaxEntries: 4,
			},
		},
	}
	mainColl, err := ebpf.NewCollection(mainSpec)
	if err != nil {
		t.Skipf("NewCollection (need CAP_BPF): %v", err)
	}
	defer mainColl.Close()

	sharedMap := mainColl.Maps["t54_shared"]
	key := uint32(200)
	val := uint32(300)
	if err := sharedMap.Update(key, val, ebpf.UpdateNoExist); err != nil {
		t.Fatalf("write marker to t54_shared: %v", err)
	}

	gateSpec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"t54_shared": {
				Name: "t54_shared", Type: ebpf.Hash,
				KeySize: 4, ValueSize: 4, MaxEntries: 4,
			},
			"t54_gate": {
				Name: "t54_gate", Type: ebpf.Hash,
				KeySize: 4, ValueSize: 4, MaxEntries: 4,
			},
		},
	}

	// t54_shared is in MapReplacements → PinNone (gate doesn't own it).
	// t54_gate is gate-owned → PinByName under pinRoot.
	gateColl, res, err := loadFromSpec(gateSpec, Options{
		PinRoot: pinRoot,
		Mode:    ModeAuto,
		MapReplacements: map[string]*ebpf.Map{
			"t54_shared": sharedMap,
		},
	})
	if err != nil {
		t.Fatalf("Auto+bpffs load: %v", err)
	}
	defer gateColl.Close()

	// Pinning should have succeeded.
	if res.PinPath != pinRoot {
		t.Errorf("PinPath=%q, want %q", res.PinPath, pinRoot)
	}
	// P3-1 fix: EffectiveMode must reflect actual opts.Mode (ModeAuto), not
	// a hardcoded constant — this would fail pre-fix with ModeRequire input.
	if res.EffectiveMode != ModeAuto {
		t.Errorf("EffectiveMode=%q, want auto (pinning succeeded)", res.EffectiveMode)
	}

	// Critical: newCollPinned must apply MapReplacements via collOpts.
	gateShared := gateColl.Maps["t54_shared"]
	if gateShared == nil {
		t.Fatal("t54_shared not found in gateColl")
	}
	var readVal uint32
	if err := gateShared.Lookup(key, &readVal); err != nil {
		t.Fatalf("lookup marker in gate t54_shared: %v — MapReplacements not applied in pinned load", err)
	}
	if readVal != val {
		t.Errorf("gate t54_shared[%d]=%d, want %d — MapReplacements not sharing kernel map on success path", key, readVal, val)
	}

	// Verify t54_gate is actually pinned (the gate-owned map).
	pinFile := filepath.Join(pinRoot, "t54_gate")
	if _, err := os.Stat(pinFile); err != nil {
		t.Errorf("pin file %q not found — t54_gate was not pinned: %v", pinFile, err)
	}
}

// T55 full: GetStats reads tailcall_fail_stats PERCPU_ARRAY and sums per-CPU
// values. Exercises the real kernel PERCPU_ARRAY path used by api/stats.go:61-71.
// The existing T55 in validate_test.go only checks JSON field existence; this
// test verifies the BPF map read-and-sum behaviour on a real kernel map.
func TestGetStats_TailcallFailPercpuSum(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"t55_fail_stats": {
				Name:       "t55_fail_stats",
				Type:       ebpf.PerCPUArray,
				KeySize:    4,
				ValueSize:  8, // uint64
				MaxEntries: 1,
			},
		},
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Skipf("NewCollection (need CAP_BPF): %v", err)
	}
	defer coll.Close()

	m := coll.Maps["t55_fail_stats"]

	// Write distinct per-CPU values so the sum is predictable.
	cpuCount, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	perCPUWrite := make([]uint64, cpuCount)
	var want uint64
	for i := range perCPUWrite {
		perCPUWrite[i] = uint64(i + 1) // 1, 2, 3, ...
		want += uint64(i + 1)
	}
	if err := m.Put(uint32(0), perCPUWrite); err != nil {
		t.Fatalf("Put per-CPU values: %v", err)
	}

	// Read using the identical pattern from stats.go GetStats.
	tcKey := make([]byte, 4) // key = 0, little-endian zero
	var tcPerCPU []uint64
	if err := m.Lookup(tcKey, &tcPerCPU); err != nil {
		t.Fatalf("Lookup tailcall_fail_stats: %v — check stats.go Lookup pattern", err)
	}

	var got uint64
	for _, v := range tcPerCPU {
		got += v
	}

	if got != want {
		t.Errorf("PERCPU_ARRAY sum = %d, want %d (per-CPU values lost)", got, want)
	}
	if len(tcPerCPU) != cpuCount {
		t.Errorf("Lookup returned %d CPU slots, want %d (PossibleCPU)", len(tcPerCPU), cpuCount)
	}
}
