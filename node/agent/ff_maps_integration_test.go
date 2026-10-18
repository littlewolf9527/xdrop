//go:build linux && integration

package main

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
)

func TestClearFastForwardSlots(t *testing.T) {
	var maps []*ebpf.Map
	for i := 0; i < 2; i++ {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: api.ConfigMapEntries})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		maps = append(maps, m)
		for slot := uint32(0); slot < api.ConfigMapEntries; slot++ {
			value := uint64(99)
			if slot == api.ConfigFastForwardEnabled {
				value = 1
			}
			if slot == api.ConfigFilterIfindex {
				value = 7
			}
			if err := m.Put(slot, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := clearFastForwardSlots(maps[0], maps[1]); err != nil {
		t.Fatal(err)
	}
	for i, m := range maps {
		for slot := uint32(0); slot < api.ConfigMapEntries; slot++ {
			var got uint64
			if err := m.Lookup(slot, &got); err != nil {
				t.Fatal(err)
			}
			want := uint64(99)
			if slot == api.ConfigFastForwardEnabled || slot == api.ConfigFilterIfindex {
				want = 0
			}
			if got != want {
				t.Errorf("map=%d slot=%d got=%d want=%d", i, slot, got, want)
			}
		}
	}
}

func TestFFDevmapReconcile(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.DevMapHash, KeySize: 4, ValueSize: 4, MaxEntries: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, key := range []uint32{40, 41} {
		if int(key) == lo.Index {
			t.Fatal("dirty key overlaps lo")
		}
		if err := m.Put(key, uint32(lo.Index)); err != nil {
			t.Fatal(err)
		}
	}
	if err := setupDevmap(m, lo.Index, lo.Index); err != nil {
		t.Fatal(err)
	}
	keys := map[uint32]uint32{}
	var key, value uint32
	it := m.Iterate()
	for it.Next(&key, &value) {
		keys[key] = value
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[uint32(lo.Index)] != uint32(lo.Index) {
		t.Errorf("reconciled keys=%v want only lo->lo", keys)
	}
	if err := m.Update(uint32(42), uint32(lo.Index), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(uint32(42), &value); err != nil || value != uint32(lo.Index) {
		t.Errorf("high key value=%d err=%v", value, err)
	}
}
