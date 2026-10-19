//go:build linux && integration

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
	xdropbpf "github.com/littlewolf9527/xdrop/node/agent/bpf"
)

func TestTD149Upgrade(t *testing.T) {
	ns, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || os.Getenv("TD149_HOST_MOUNT_NS") == "" || ns == os.Getenv("TD149_HOST_MOUNT_NS") {
		t.Fatal("private mount namespace required")
	}
	root := os.Getenv("TD149_PRIVATE_BPFFS")
	if root != "/sys/fs/bpf/k8b" {
		t.Fatal("private bpffs path required")
	}
	path, err := os.MkdirTemp(root, "upgrade-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	base, err := ebpf.LoadCollectionSpec(os.Getenv("XDROP_BASE_BPF_ELF"))
	if err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]uint32{"config_a": 12, "config_b": 12, "stats": 9} {
		if base.Maps[name] == nil || base.Maps[name].MaxEntries != size {
			t.Fatal("baseline pin schema " + name)
		}
		m, err := ebpf.NewMap(base.Maps[name])
		if err != nil {
			t.Fatal(err)
		}
		err = m.Pin(filepath.Join(path, name))
		m.Close()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			t.Fatal("old pin missing: " + name)
		}
	}
	main, result, err := xdropbpf.Load(xdropbpf.Options{SpecPath: os.Getenv("XDROP_BPF_ELF"), PinRoot: path, Mode: xdropbpf.ModeRequire})
	if err != nil {
		t.Fatal(err)
	}
	defer main.Close()
	sort.Strings(result.Wiped)
	if result.EffectiveMode != xdropbpf.ModeRequire || result.PinPath != path || result.FallbackReason != "" || !reflect.DeepEqual(result.Wiped, []string{"config_a", "config_b", "stats"}) {
		t.Fatalf("upgrade result=%+v", result)
	}
	for name, size := range map[string]uint32{"config_a": 13, "config_b": 13, "stats": 10} {
		if main.Maps[name].MaxEntries() != size {
			t.Fatal("rebuilt schema " + name)
		}
	}
	check := func(want uint64) {
		for _, name := range []string{"config_a", "config_b"} {
			var value uint64
			if err := main.Maps[name].Lookup(uint32(12), &value); err != nil || value != want {
				t.Fatalf("%s slot12=%d want=%d err=%v", name, value, want, err)
			}
		}
	}
	check(0)
	for _, pass := range []bool{true, false} {
		if err := configureIPv6DeepChain(main.Maps["config_a"], main.Maps["config_b"], pass); err != nil {
			t.Fatal(err)
		}
		want := uint64(0)
		if pass {
			want = 1
		}
		check(want)
	}
	t.Log("TD149_UPGRADE old_pins=3 wiped=config_a,config_b,stats config=13 stats=10 initial_slot12=0 write_readback=1")
}
