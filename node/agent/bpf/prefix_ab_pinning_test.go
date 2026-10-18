package bpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestPrefixABDotMapsNeverPinned(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		".rodata": {Pinning: ebpf.PinByName}, "custom.data": {Pinning: ebpf.PinByName},
		"policy": {}, "shared": {}, "private": {},
	}}
	tagPinnedMaps(spec, map[string]bool{"shared": true}, map[string]bool{"private": true})
	for name, m := range spec.Maps {
		want := ebpf.PinNone
		if name == "policy" {
			want = ebpf.PinByName
		}
		if m.Pinning != want {
			t.Fatalf("pin tag %s=%v want=%v", name, m.Pinning, want)
		}
	}
	// A file as the parent makes any attempted stat below it fail with ENOTDIR.
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("positive control"), 0600); err != nil {
		t.Fatal(err)
	}
	dots := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{".rodata": {}, "custom.data": {}}}
	if wiped, err := reconcilePinnedMaps(dots, root, nil); err != nil || len(wiped) != 0 {
		t.Fatalf("dot names reached reconciliation: wiped=%v err=%v", wiped, err)
	}
	if _, err := reconcilePinnedMaps(&ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"policy": {}}}, root, nil); err == nil {
		t.Fatal("ordinary map positive control did not attempt stat")
	}
	t.Log("CLOSEOUT_TD093_DOTS skipped_reconcile=2 pin_none=2 normal_pin_control=1 normal_stat_control=1")
}
