//go:build linux && integration

package bpf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func TestCut54PinnedUpgrade(t *testing.T) {
	parent := os.Getenv("XDROP_CUT54_BPFFS_DIR")
	if parent == "" {
		t.Fatal("XDROP_CUT54_BPFFS_DIR must name a private lab bpffs directory")
	}
	var fs unix.Statfs_t
	if e := unix.Statfs(parent, &fs); e != nil || uint64(fs.Type) != 0xcafe4a11 {
		t.Fatalf("private pin directory must be bpffs: %v type=%x", e, fs.Type)
	}
	dir, e := os.MkdirTemp(parent, "cut54-upgrade-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(dir); e != nil {
			t.Error(e)
		}
	})
	source, e := os.ReadFile("../main.go")
	if e != nil {
		t.Fatal(e)
	}
	stale, e := cut54StartupContract(source)
	if e != nil {
		t.Fatal(e)
	}
	spec, e := ebpf.LoadCollectionSpec(os.Getenv("XDROP_CUT54_BASE_MAIN_ELF"))
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"tail_stash", "rl_states", "cidr_rl_states"} {
		ms := spec.Maps[name]
		if ms == nil {
			t.Fatalf("baseline ELF missing retired map %s", name)
		}
		small := ms.Copy()
		if small.MaxEntries > 16 {
			small.MaxEntries = 16
		}
		m, e := ebpf.NewMap(small)
		if e != nil {
			t.Fatal(e)
		}
		if e = m.Pin(filepath.Join(dir, name)); e != nil {
			m.Close()
			t.Fatal(e)
		}
		m.Close()
	}
	tail, e := ebpf.NewMap(&ebpf.MapSpec{Name: "cut54_tail", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 2})
	if e != nil {
		t.Fatal(e)
	}
	if e = ClearRetiredTailSlot(tail); e != nil {
		tail.Close()
		t.Fatalf("new map empty slot must permit startup: %v", e)
	}
	old, e := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "cut54_old", Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()}})
	if e != nil {
		tail.Close()
		t.Fatal(e)
	}
	defer old.Close()
	if e = tail.Put(uint32(0), uint32(old.FD())); e != nil {
		tail.Close()
		t.Fatal(e)
	}
	if e = tail.Pin(filepath.Join(dir, "prog_tail_map")); e != nil {
		tail.Close()
		t.Fatal(e)
	}
	tail.Close()
	reopened, e := ebpf.LoadPinnedMap(filepath.Join(dir, "prog_tail_map"), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	var id uint32
	if e = reopened.Lookup(uint32(0), &id); e != nil || id == 0 {
		t.Fatalf("pin fixture lacks residual slot 0: id=%d err=%v", id, e)
	}
	if e = CleanStalePins(dir, stale); e != nil {
		t.Fatal(e)
	}
	if e = ClearRetiredTailSlot(reopened); e != nil {
		t.Fatal(e)
	}
	if e = reopened.Lookup(uint32(0), &id); !errors.Is(e, ebpf.ErrKeyNotExist) {
		t.Fatalf("startup retained pinned retired slot 0: %v", e)
	}
	for _, name := range []string{"tail_stash", "rl_states", "cidr_rl_states"} {
		if _, e = os.Stat(filepath.Join(dir, name)); !errors.Is(e, os.ErrNotExist) {
			t.Fatalf("orphan pin remains: %s %v", name, e)
		}
	}
	t.Log("CUT54_PIN_UPGRADE fresh_empty=1 old_slot_present=1 reopened_empty=1 removed_orphan_pins=3 retired_required=0")
}
