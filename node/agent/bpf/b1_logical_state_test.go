//go:build linux && integration

package bpf

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"golang.org/x/sys/unix"
)

type b1Bucket struct{ Tokens, Last uint64 }

func b1LogicalLoad(t *testing.T, small string) *ebpf.Collection {
	t.Helper()
	path := os.Getenv("XDROP_BPF_ELF")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{SpecPath: path, Mode: ModeDisable}
	var c *ebpf.Collection
	var result Result
	if small == "" {
		c, result, err = Load(opts)
	} else {
		spec, e := ebpf.LoadCollectionSpec(path)
		if e != nil {
			t.Fatal(e)
		}
		// Only the load-time capacity changes. Production ELF bytes and map type,
		// flags, key and value sizes remain unchanged.
		ms := spec.Maps[small]
		ms.MaxEntries = 1
		replacement, e := ebpf.NewMap(ms)
		if e != nil {
			t.Fatal(e)
		}
		defer replacement.Close()
		opts.MapReplacements = map[string]*ebpf.Map{small: replacement}
		c, result, err = loadFromSpec(spec, opts)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if result.PinPath != "" || result.EffectiveMode != ModeDisable {
		t.Fatalf("unexpected loader result %+v", result)
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(raw) != sha256.Sum256(after) {
		t.Fatal("production ELF changed")
	}
	t.Logf("B1_LOGICAL_LOADER sha256=%x small=%q pin=0", sha256.Sum256(raw), small)
	return c
}
func b1LogicalPacket(ttl byte) []byte {
	p := make([]byte, 54)
	binary.BigEndian.PutUint16(p[12:], 0x0800)
	p[14] = 0x45
	binary.BigEndian.PutUint16(p[16:], 40)
	p[22] = ttl
	p[23] = 6
	copy(p[26:], []byte{10, 0, 0, 1})
	copy(p[30:], []byte{10, 1, 0, 1})
	binary.BigEndian.PutUint16(p[34:], 12345)
	binary.BigEndian.PutUint16(p[36:], 80)
	p[46] = 0x50
	p[47] = 2
	return p
}
func b1RunCPU(t *testing.T, c *ebpf.Collection, p []byte, repeat, want uint32) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var cpus unix.CPUSet
	if err := unix.SchedGetaffinity(0, &cpus); err != nil {
		t.Fatal(err)
	}
	cpu := 0
	for !cpus.IsSet(cpu) {
		cpu++
	}
	var one unix.CPUSet
	one.Set(cpu)
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.SchedSetaffinity(0, &cpus); err != nil {
			t.Error(err)
		}
	}()
	// Repeat > 1 can replay map side effects after EINTR. Exhaustion cases
	// consume the burst with PASS packets before the final expected verdict.
	var got uint32
	var err error
	for i := uint32(0); i < repeat; i++ {
		got, err = c.Programs["xdp_firewall_main"].Run(&ebpf.RunOptions{Data: p, Repeat: 1})
		packetWant := want
		if i+1 < repeat {
			packetWant = srcXDPPass
		}
		if err != nil || got != packetWant {
			t.Fatalf("B1_LOGICAL packet=%d/%d verdict got=%d want=%d err=%v", i+1, repeat, got, packetWant, err)
		}
	}
	if err != nil || got != want {
		t.Fatalf("B1_LOGICAL verdict got=%d want=%d repeat=%d err=%v", got, want, repeat, err)
	}
}
func b1LogicalCounts(t *testing.T, c *ebpf.Collection, id uint32) api.LogicalRuleCounters {
	t.Helper()
	v, err := api.ReadLogicalRuleCounters(c.Maps["id_counts"], id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func b1LogicalBucket(t *testing.T, c *ebpf.Collection, id uint32) b1Bucket {
	t.Helper()
	var values []b1Bucket
	if err := c.Maps["id_rl_states"].Lookup(id, &values); err != nil {
		t.Fatalf("B1_LOGICAL bucket id=%d: %v", id, err)
	}
	var out b1Bucket
	seen := 0
	for _, v := range values {
		if v.Last != 0 {
			out = v
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("B1_LOGICAL initialized CPUs=%d want=1", seen)
	}
	return out
}
func b1LogicalReset(t *testing.T, c *ebpf.Collection, cidr bool, slot, sel uint64) {
	t.Helper()
	if err := ClearDataMaps(c, []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b", "cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_counts", "id_rl_states"} {
		if _, err := ClearMapKeys(c.Maps[name]); err != nil {
			t.Fatal(err)
		}
	}
	b1Config(t, c, cidr, slot, sel)
	for _, name := range []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b"} {
		b1Put(t, c, name, make([]byte, 8), uint32(7))
	}
}
func b1AssertLogicalAccounting(t *testing.T, c *ebpf.Collection, cidr bool, sel uint64, id uint32, match, drop uint64) {
	t.Helper()
	got := b1LogicalCounts(t, c, id)
	want := api.LogicalRuleCounters{Match: match, Drop: drop}
	if got.Match != want.Match || got.Drop != want.Drop {
		t.Fatalf("B1_LOGICAL winner id=%d got=%+v want=%+v", id, got, want)
	}
	if match == 0 {
		if got != (api.LogicalRuleCounters{}) {
			t.Fatal("allocation failure must leave counters zero")
		}
	} else if got.MatchBytes != match*uint64(len(b1LogicalPacket(64))) || got.DropBytes != drop*uint64(len(b1LogicalPacket(64))) || got.LastHitNS == 0 || got.LastHitNS < nsAccountingStart || got.LastHitNS > nsCoarse(t) {
		t.Fatalf("B1_LOGICAL byte/time accounting: %+v", got)
	}
	r, _, _, _ := b1Maps(cidr, sel)
	var old api.RuleValue
	if err := c.Maps[r].Lookup(b1Key(cidr, 6, true), &old); err != nil {
		t.Fatal(err)
	}
	if old.LogicalID == 0 || old.LogicalReserved != ([12]byte{}) {
		t.Fatalf("B1_LOGICAL row identity/reserved invalid: %+v", old)
	}
}
func TestB1LogicalStateELF(t *testing.T) {
	c := b1LogicalLoad(t, "")
	packets := 0
	for _, cidr := range []bool{false, true} {
		for _, asm := range srcAssemblies {
			t.Run(fmt.Sprintf("cidr=%v/%s", cidr, asm.name), func(t *testing.T) {
				t.Run("distinct-IDs-distinct-rates", func(t *testing.T) {
					b1LogicalReset(t, c, cidr, asm.slot, asm.sel)
					row := b1OpenRow(3)
					row.Tab[0] = [128]byte{}
					row.Tab[0][32] = 0x21 // TTL 64 -> candidate 0, 65 -> candidate 1
					row.RuleID = [4]uint32{101, 202}
					row.Rate = [4]uint32{1, 3}
					row.Action = [4]uint8{api.ActionRateLimit, api.ActionRateLimit}
					b1SetRow(t, c, cidr, asm.sel, 6, row)
					for i, rate := range []uint32{1, 3} {
						n := 2*rate + 1
						b1RunCPU(t, c, b1LogicalPacket(byte(64+i)), n, srcXDPDrop)
						packets += int(n)
						b1AssertLogicalAccounting(t, c, cidr, asm.sel, row.RuleID[i], uint64(n), 1)
						if state := b1LogicalBucket(t, c, row.RuleID[i]); state.Tokens != 0 {
							t.Fatalf("B1_LOGICAL separate rate=%d tokens=%d want=0", rate, state.Tokens)
						}
					}
				})
				t.Run("split-candidates-one-bucket", func(t *testing.T) {
					b1LogicalReset(t, c, cidr, asm.slot, asm.sel)
					row := b1OpenRow(3)
					row.Tab[0] = [128]byte{}
					row.Tab[0][32] = 0x21
					row.RuleID = [4]uint32{303, 303}
					row.Rate = [4]uint32{17, 17}
					row.Action = [4]uint8{2, 2}
					b1SetRow(t, c, cidr, asm.sel, 6, row)
					b1RunCPU(t, c, b1LogicalPacket(64), 1, srcXDPPass)
					packets++
					before := b1LogicalBucket(t, c, 303)
					if before.Tokens != 33 {
						t.Fatalf("B1_LOGICAL initial split tokens=%d want=33", before.Tokens)
					}
					b1RunCPU(t, c, b1LogicalPacket(65), 1, srcXDPPass)
					packets++
					after := b1LogicalBucket(t, c, 303)
					// Derive refill from bucket timestamps; no wall-clock timing threshold.
					want := before.Tokens + (after.Last-before.Last)*17/1000000000
					if want > 34 {
						want = 34
					}
					want--
					if after.Tokens != want {
						t.Fatalf("B1_LOGICAL shared bucket tokens=%d want=%d", after.Tokens, want)
					}
					b1AssertLogicalAccounting(t, c, cidr, asm.sel, 303, 2, 0)
					var key uint32
					var values []b1Bucket
					it := c.Maps["id_rl_states"].Iterate()
					rows := 0
					for it.Next(&key, &values) {
						rows++
						if key != 303 {
							t.Fatalf("B1_LOGICAL physical bucket key=%d want=303", key)
						}
					}
					if err := it.Err(); err != nil {
						t.Fatal(err)
					}
					if rows != 1 {
						t.Fatalf("B1_LOGICAL split buckets=%d want=1", rows)
					}
				})
				t.Run("winner-once", func(t *testing.T) {
					b1LogicalReset(t, c, cidr, asm.slot, asm.sel)
					row := b1OpenRow(3)
					row.RuleID = [4]uint32{404, 505}
					row.Action = [4]uint8{1, 1}
					b1SetRow(t, c, cidr, asm.sel, 6, row)
					b1RunCPU(t, c, b1LogicalPacket(64), 1, srcXDPDrop)
					packets++
					b1AssertLogicalAccounting(t, c, cidr, asm.sel, 404, 1, 1)
					if got := b1LogicalCounts(t, c, 505); got != (api.LogicalRuleCounters{}) {
						t.Fatalf("B1_LOGICAL loser counted %+v", got)
					}
				})
			})
		}
	}
	if t.Failed() {
		t.Fatal("B1_LOGICAL failed assertions")
	}
	t.Logf("B1_LOGICAL paths=2 assemblies=4 packets=%d red=0", packets)
}
func TestB1LogicalAllocationFailureELF(t *testing.T) {
	for _, small := range []string{"id_rl_states", "id_counts"} {
		t.Run(small, func(t *testing.T) {
			c := b1LogicalLoad(t, small)
			for _, cidr := range []bool{false, true} {
				t.Run(fmt.Sprint(cidr), func(t *testing.T) {
					b1LogicalReset(t, c, cidr, 0, 0)
					b1Put(t, c, small, uint32(999), nsLogicalBuffer(small, mustPossibleCPUs(t)).Interface())
					row := b1OpenRow(1)
					row.RuleID[0] = 606
					row.Action[0] = api.ActionRateLimit
					row.Rate[0] = 17
					b1SetRow(t, c, cidr, 0, 6, row)
					want := srcXDPDrop
					if small == "id_counts" {
						want = srcXDPPass
					}
					b1RunCPU(t, c, b1LogicalPacket(64), 1, want)
					values := nsLogicalBuffer(small, mustPossibleCPUs(t))
					err := c.Maps[small].Lookup(uint32(606), values.Interface())
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("B1_LOGICAL full map unexpectedly inserted: %v", err)
					}
					if small == "id_rl_states" {
						b1AssertLogicalAccounting(t, c, cidr, 0, 606, 1, 1)
					} else {
						b1AssertLogicalAccounting(t, c, cidr, 0, 606, 0, 0)
						if v := b1LogicalBucket(t, c, 606); v.Tokens != 33 {
							t.Fatalf("counter failure changed bucket %+v", v)
						}
					}
					t.Logf("B1_LOGICAL_ALLOC map=%s cidr=%v decision=%d production_elf_unchanged=1", small, cidr, want)
				})
			}
		})
	}
}
func TestB1LogicalMapMemory(t *testing.T) {
	spec, _, _ := loadMainELF(t)
	for _, name := range []string{"id_counts", "id_rl_states"} {
		m, err := ebpf.NewMap(spec.Maps[name])
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer m.Close()
			for _, rows := range []int{0, 32} {
				for id := uint32(1); id <= uint32(rows); id++ {
					if err := m.Put(id, nsLogicalBuffer(name, mustPossibleCPUs(t)).Interface()); err != nil {
						t.Fatal(err)
					}
				}
				raw, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
				if err != nil {
					t.Fatal(err)
				}
				found := regexp.MustCompile(`(?m)^memlock:\s*(\d+)$`).FindSubmatch(raw)
				if len(found) != 2 {
					t.Fatalf("memlock missing: %s", raw)
				}
				n, err := strconv.ParseUint(string(found[1]), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("B1_LOGICAL_MEMORY map=%s rows=%d possible_cpus=%d max_entries=%d source=fdinfo memlock_bytes=%d", name, rows, mustPossibleCPUs(t), m.MaxEntries(), n)
			}
		}()
	}
}
