//go:build linux && integration

package eval

// This file is a lab-only calibration harness. It is never run by local smoke.
// A future lab session must first run TestCalibrateLab with -lab-prepare, then
// compile only xdrop_main.elf / xdrop_gate.elf from the verified /tmp source root
// with an outer timeout and make -j1. Run this one precompiled test again without
// -lab-prepare, supplying the recorded compiler version and exact build command.
// The test binary itself is built separately with -p=1. Never run integration
// ./...; the repository has other loaders with production-sized maps.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

const authorityBaseline = "bd686710e3fd9fbb54bf889b2cc1d197873af906"

var (
	labPrepare      = flag.Bool("lab-prepare", false, "record the resident/health baseline BEFORE compilation; does not load BPF")
	labRecord       = flag.String("lab-record", "", "absolute /tmp evidence record path; prepare creates it exclusively")
	labSource       = flag.String("lab-source-root", "", "absolute /tmp root of copied baseline BPF sources")
	labController   = flag.String("lab-controller-health", "", "existing controller /health URL")
	labAgent        = flag.String("lab-agent-health", "", "existing agent /api/v1/health URL")
	labPins         = flag.String("lab-pins", "", "explicit JSON array of {Kind:map|prog,Path:absolute pin path}")
	labBuildCommand = flag.String("lab-build-command", "", "exact completed, separately timed make -j1 command")
	labCompiler     = flag.String("lab-compiler-version", "", "captured compiler --version output for that build")
)

type residentPin struct{ Kind, Path string }
type residentState struct {
	Programs, Maps map[string]json.RawMessage
	Net            json.RawMessage
	Pins           map[string]json.RawMessage
}
type preparation struct {
	Baseline, SourceRoot, TestBinarySHA256 string
	Created                                time.Time
	SourceHashes                           map[string]string
	Resident                               residentState
	Pins                                   []residentPin
	ControllerURL, AgentURL                string
	Health                                 map[string]json.RawMessage
	Environment                            map[string]string
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	must(t, err)
	return b
}
func command(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %q: %v\n%s", name, args, err, out)
	}
	return out
}
func tmpPath(t *testing.T, p string) string {
	t.Helper()
	if !filepath.IsAbs(p) {
		t.Fatalf("absolute /tmp path required: %q", p)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(p))
	must(t, err)
	if parent != "/tmp" && !strings.HasPrefix(parent, "/tmp/") {
		t.Fatalf("outside /tmp: %s", p)
	}
	return filepath.Join(parent, filepath.Base(p))
}
func sourceHashes(t *testing.T) map[string]string {
	out := map[string]string{}
	for p, want := range baselineBPFHashes {
		b, err := sourceFile(*labSource, p)
		must(t, err)
		got := digest(b)
		if got != want {
			t.Fatalf("baseline source %s: got=%s want=%s", p, got, want)
		}
		out[p] = got
	}
	if len(out) != 10 {
		t.Fatalf("baseline source inventory=%d, want 10", len(out))
	}
	return out
}
func readHealth(urls ...string) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, url := range urls {
		if url == "" {
			return nil, fmt.Errorf("explicit existing health URL required")
		}
		resp, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		closeErr := resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		var parsed struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(b, &parsed); err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 || parsed.Status != "healthy" {
			return nil, fmt.Errorf("health %s HTTP=%d body=%s", url, resp.StatusCode, b)
		}
		out[url] = b
	}
	return out, nil
}
func health(t *testing.T, urls ...string) map[string]json.RawMessage {
	t.Helper()
	out, err := readHealth(urls...)
	must(t, err)
	return out
}

func rawObjects(t *testing.T, kind string) []map[string]json.RawMessage {
	var out []map[string]json.RawMessage
	must(t, json.Unmarshal(command(t, "bpftool", "-j", kind, "show"), &out))
	return out
}

// kindIsProg reports whether this field set is the program one. All maps in the
// recorded lab inventory had names; this harness still requires them for maps.
func kindIsProg(fields []string) bool {
	for _, f := range fields {
		if f == "map_ids" {
			return true
		}
	}
	return false
}

func selected(t *testing.T, obj map[string]json.RawMessage, fields []string) json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, k := range fields {
		v, ok := obj[k]
		// bpftool can omit name on unnamed programs and map_ids on map-free ones.
		// The lab inventory recorded on 2026-09-15 covered every field this harness
		// reads: of 20 resident programs, name was absent on 2
		// (unnamed cgroup_device) and map_ids on 16 (systemd sd_fw_*/sd_devices);
		// id and tag were never absent, and all 7 map fields were present on all 22
		// maps. Positive control: xdrop's own 3 programs and 19 maps carry every
		// field, xdp_firewall_main included with its 18 map ids.
		// An internal bpftool query for map IDs can also fail and omit map_ids; this
		// JSON normalization alone cannot distinguish that failure from no maps.
		//
		// Record each absence as an explicit empty value instead of skipping the
		// field, so a resident object that later GAINS a name or a map still shows
		// up as a difference in sameResident. Everything else fails closed — an
		// absent id or tag really is a schema break.
		if !ok {
			switch k {
			case "map_ids":
				v, ok = []byte("[]"), true
			case "name":
				if kindIsProg(fields) {
					v, ok = []byte(`""`), true
				}
			}
		}
		if !ok || bytes.Equal(v, []byte("null")) {
			t.Fatalf("bpftool schema missing %s: %v", k, obj)
		}
		if k == "map_ids" {
			var ids []uint32
			must(t, json.Unmarshal(v, &ids))
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			b, err := json.Marshal(ids)
			must(t, err)
			v = b
		}
		out[k] = v
	}
	b, err := json.Marshal(out)
	must(t, err)
	return b
}
func objectsByID(t *testing.T, kind string) map[string]json.RawMessage {
	fields := []string{"id", "tag", "name", "map_ids"}
	if kind == "map" {
		fields = []string{"id", "type", "bytes_key", "bytes_value", "max_entries", "flags", "name"}
	}
	out := map[string]json.RawMessage{}
	for _, obj := range rawObjects(t, kind) {
		value := selected(t, obj, fields)
		var id uint32
		must(t, json.Unmarshal(obj["id"], &id))
		if id == 0 {
			t.Fatal("zero object ID")
		}
		key := strconv.FormatUint(uint64(id), 10)
		if _, ok := out[key]; ok {
			t.Fatal("duplicate object ID")
		}
		out[key] = value
	}
	return out
}
func snapshot(t *testing.T, pins []residentPin) residentState {
	s := residentState{Programs: objectsByID(t, "prog"), Maps: objectsByID(t, "map"), Pins: map[string]json.RawMessage{}}
	var net []map[string]json.RawMessage
	must(t, json.Unmarshal(command(t, "bpftool", "-j", "net", "show"), &net))
	var links []json.RawMessage
	for _, ns := range net {
		raw, ok := ns["xdp"]
		if !ok {
			t.Fatal("bpftool net schema missing xdp")
		}
		var entries []map[string]json.RawMessage
		must(t, json.Unmarshal(raw, &entries))
		for _, entry := range entries {
			links = append(links, selected(t, entry, []string{"devname", "ifindex", "id", "mode"}))
		}
	}
	if len(net) == 0 {
		t.Fatal("bpftool net returned no namespace record")
	}
	sort.Slice(links, func(i, j int) bool { return string(links[i]) < string(links[j]) })
	b, err := json.Marshal(links)
	must(t, err)
	s.Net = b
	for _, p := range pins {
		if p.Kind != "map" && p.Kind != "prog" || !filepath.IsAbs(p.Path) {
			t.Fatalf("invalid explicit pin %+v", p)
		}
		var obj map[string]json.RawMessage
		must(t, json.Unmarshal(command(t, "bpftool", "-j", p.Kind, "show", "pinned", p.Path), &obj))
		s.Pins[p.Kind+":"+p.Path] = selected(t, obj, []string{"id"})
	}
	return s
}

// compactJSON normalises whitespace so the baseline survives its own storage
// format. The preparation record is written with json.MarshalIndent, which
// re-indents every embedded json.RawMessage; a snapshot taken later is compact.
// Comparing those byte-for-byte reported every resident pin as "changed" while
// got and want held the same id (lab, 2026-09-15). Compacting compares content
// and still fails on any real difference — an id that actually moves differs
// after compaction too.
func compactJSON(t *testing.T, b []byte) string {
	t.Helper()
	var buf bytes.Buffer
	must(t, json.Compact(&buf, b))
	return buf.String()
}

func sameResident(t *testing.T, before, after residentState) {
	for kind, pair := range map[string][2]map[string]json.RawMessage{"prog": {before.Programs, after.Programs}, "map": {before.Maps, after.Maps}, "pin": {before.Pins, after.Pins}} {
		for id, want := range pair[0] {
			got, ok := pair[1][id]
			if !ok || compactJSON(t, got) != compactJSON(t, want) {
				t.Errorf("resident %s %s changed: got=%s want=%s", kind, id, got, want)
			}
		}
	}
	if compactJSON(t, before.Net) != compactJSON(t, after.Net) {
		t.Errorf("resident attachments changed: got=%s want=%s", after.Net, before.Net)
	}
}

var capacityMaps = []string{"rl_states", "cidr_rl_states", "blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b", "whitelist", "whitelist_b", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie"}

func privateSpec(t *testing.T, path string) *ebpf.CollectionSpec {
	spec, err := ebpf.LoadCollectionSpec(path)
	must(t, err)
	original := spec.Copy()
	if spec.ByteOrder != binary.LittleEndian {
		t.Fatal("ELF is not little endian")
	}
	for name, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
		for _, allowed := range capacityMaps {
			if name == allowed {
				m.MaxEntries = 256
			}
		}
		check := m.Copy()
		check.Pinning = original.Maps[name].Pinning
		check.MaxEntries = original.Maps[name].MaxEntries
		if !reflect.DeepEqual(check, original.Maps[name]) {
			t.Fatalf("unapproved map spec change: %s", name)
		}
	}
	if !reflect.DeepEqual(spec.Programs, original.Programs) {
		t.Fatal("program instructions changed")
	}
	return spec
}
func requireMap(t *testing.T, c *ebpf.Collection, name string) *ebpf.Map {
	t.Helper()
	m := c.Maps[name]
	if m == nil {
		t.Fatalf("missing private map %s", name)
	}
	return m
}
func mapID(t *testing.T, m *ebpf.Map) uint32 {
	info, err := m.Info()
	must(t, err)
	id, ok := info.ID()
	if !ok {
		t.Fatal("map ID unavailable")
	}
	return uint32(id)
}
func progID(t *testing.T, p *ebpf.Program) uint32 {
	if p == nil {
		t.Fatal("missing private program")
	}
	info, err := p.Info()
	must(t, err)
	id, ok := info.ID()
	if !ok {
		t.Fatal("program ID unavailable")
	}
	return uint32(id)
}

// Known loader/kernel flag additions, with source and lab evidence kept separate:
//
//	BPF_F_MMAPABLE — cilium/ebpf v0.21.0 loadMap adds it when MapSpec.Name
//	    matches isDataSection (.bss, .data*, .rodata*) and the kernel supports it.
//	    The lab observed .rodata changing from 0x80 to 0x480 on 2026-09-15.
//	BPF_F_RDONLY_PROG — Linux 6.12.57 dev_map_init_map adds it for DEVMAP and
//	    DEVMAP_HASH. The lab's bare DEVMAP created without flags and resident
//	    DEVMAP both reported 0x80; DEVMAP_HASH has source evidence here.
//
// The check stays closed in both directions that matter: a flag the spec asked
// for and the kernel did not honour still fails, and so does any extra bit
// outside this narrow per-map-class allowance.
const (
	flagRdonlyProg = uint32(1) << 7
	flagMmapable   = uint32(1) << 10
)

func loaderAddedFlags(name string, t ebpf.MapType) uint32 {
	switch {
	case t == ebpf.Array && (name == ".bss" || strings.HasPrefix(name, ".data") || strings.HasPrefix(name, ".rodata")):
		return flagMmapable
	case t == ebpf.DevMap || t == ebpf.DevMapHash:
		return flagRdonlyProg
	}
	return 0
}

func verifyMapInfo(t *testing.T, s *ebpf.CollectionSpec, c *ebpf.Collection) {
	for name, want := range s.Maps {
		m := requireMap(t, c, name)
		got, err := m.Info()
		must(t, err)
		missing := want.Flags &^ got.Flags
		extra := (got.Flags &^ want.Flags) &^ loaderAddedFlags(want.Name, want.Type)
		if got.Type != want.Type || got.KeySize != want.KeySize || got.ValueSize != want.ValueSize || missing != 0 || extra != 0 || got.MaxEntries != want.MaxEntries || want.Pinning != ebpf.PinNone {
			// Report every mismatching map, not just the first: stopping at the
			// first one hides whether the cause is one map or the whole set.
			t.Errorf("private MapInfo mismatch %s: got=%+v want=%+v (flags missing=%#x unexpected-extra=%#x)", name, got, want, missing, extra)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}
func putRead(t *testing.T, m *ebpf.Map, key, value, want []byte) {
	t.Helper()
	must(t, m.Put(key, value))
	got, err := m.LookupBytes(key)
	must(t, err)
	if !bytes.Equal(got, want) {
		t.Fatalf("map bytes key=%x got=%x want=%x", key, got, want)
	}
}
func u32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func u64(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

// clearProgArray empties a PROG_ARRAY. clearMap cannot do this: a PROG_ARRAY is
// an array, so NextKey walks every index up to max_entries whether or not a slot
// was ever filled, and deleting an empty slot returns ENOENT. Walk the indices
// directly and treat a missing slot as already clear — the goal is only that no
// slot still references a program by the time the collections are closed.
func clearProgArray(t *testing.T, m *ebpf.Map) {
	t.Helper()
	for i := uint32(0); i < m.MaxEntries(); i++ {
		if err := m.Delete(u32(i)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Errorf("clear prog_tail_map slot %d: %v", i, err)
		}
	}
}

func clearMap(t *testing.T, m *ebpf.Map) {
	for {
		key, err := m.NextKeyBytes(nil)
		must(t, err)
		if key == nil {
			break
		}
		must(t, m.Delete(key))
	}
	key, err := m.NextKeyBytes(nil)
	must(t, err)
	if key != nil {
		t.Fatal("map not empty after reset")
	}
}
func emptyPrune(t *testing.T, main *ebpf.Collection) {
	key, err := requireMap(t, main, "verifier_prune_map").NextKeyBytes(nil)
	must(t, err)
	if key != nil {
		t.Fatal("private prune map is not empty")
	}
}
func constants(t *testing.T) map[string]uint32 {
	b, err := sourceFile(*labSource, "node/bpf/xdrop.h")
	must(t, err)
	// Consume the same numeric definitions as C, then independently check slots.
	out := map[string]uint32{}
	for _, line := range strings.Split(cleanC(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != "#define" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 10, 32)
		if err == nil {
			out[f[1]] = uint32(v)
		}
	}
	want := map[string]uint32{"CONFIG_BLACKLIST_COUNT": 0, "CONFIG_WHITELIST_COUNT": 1, "CONFIG_RULE_BITMAP": 2, "CONFIG_WL_BITMAP": 3, "CONFIG_FAST_FORWARD_ENABLED": 4, "CONFIG_FILTER_IFINDEX": 5, "CONFIG_CIDR_RULE_COUNT": 6, "CONFIG_CIDR_BITMAP": 7, "CONFIG_WL_MAP_SELECTOR": 8, "CONFIG_RULE_MAP_SELECTOR": 9, "CONFIG_ANOMALY_RULE_COUNT": 10, "CONFIG_RL_CPU_DIVISOR": 11, "CONFIG_MAP_ENTRIES": 12, "TAIL_SLOT_ANOMALY_VERIFY": 0, "TAIL_SLOT_FIREWALL_MAIN": 1, "STATS_WHITELISTED": 3}
	for name, v := range want {
		got, ok := out[name]
		if !ok || got != v {
			t.Fatalf("header constant %s got=%d present=%v want=%d", name, got, ok, v)
		}
	}
	return out
}
func resetFixture(t *testing.T, main, gate *ebpf.Collection, f fixture, c map[string]uint32, ncpu int) {
	for _, name := range capacityMaps {
		collection := main
		if name == "whitelist_b" {
			collection = gate
		}
		clearMap(t, requireMap(t, collection, name))
	}
	emptyPrune(t, main)
	for _, name := range []string{"config_a", "config_b"} {
		m := requireMap(t, main, name)
		for i := uint32(0); i < c["CONFIG_MAP_ENTRIES"]; i++ {
			putRead(t, m, u32(i), u64(0), make([]byte, 8))
		}
	}
	putRead(t, requireMap(t, main, "active_config"), u32(0), u64(0), make([]byte, 8))
	for _, name := range []string{"stats", "tail_stash"} {
		m := requireMap(t, main, name)
		info, err := m.Info()
		must(t, err)
		for i := uint32(0); i < info.MaxEntries; i++ {
			zeros := make([][]byte, ncpu)
			for j := range zeros {
				zeros[j] = make([]byte, info.ValueSize)
			}
			must(t, m.Put(i, zeros))
			got, err := m.LookupBytes(i)
			must(t, err)
			if len(got) == 0 || !bytes.Equal(got, make([]byte, len(got))) {
				t.Fatalf("%s reset readback", name)
			}
		}
	}
	for stage, rs := range map[Stage][]Rule{Whitelist: f.Rules.Whitelist, Exact: f.Rules.Exact, CIDR: f.Rules.CIDR} {
		if len(rs) > 256 {
			t.Fatal("fixture exceeds private capacity")
		}
		for _, r := range rs {
			gold, ok := wireGoldens[r.ID]
			if !ok {
				t.Fatalf("missing independent vector %s", r.ID)
			}
			key, value := encodeTuple(r.Key), encodeValue(r)
			if stage == Whitelist {
				value = []byte{1}
			}
			if stage == CIDR {
				key = encodeCIDR(r.CIDRKey)
			}
			if !bytes.Equal(key, unhex(gold.Key)) || !bytes.Equal(value, unhex(gold.Value)) {
				t.Fatalf("encoder vs independent vector %s", r.ID)
			}
			putRead(t, requireMap(t, main, gold.Map), key, value, unhex(gold.Value))
		}
	}
	for name, ps := range map[string][]Prefix{"sv4_cidr_trie": f.Rules.SrcPrefixes, "dv4_cidr_trie": f.Rules.DstPrefixes} {
		if len(ps) > 256 {
			t.Fatal("prefix capacity exceeded")
		}
		for _, p := range ps {
			want := fmt.Sprintf("%02x%02x%02x%02x", byte(p.ID), byte(p.ID>>8), byte(p.ID>>16), byte(p.ID>>24))
			putRead(t, requireMap(t, main, name), encodePrefix(p), u32(p.ID), unhex(want))
		}
	}
	anomaly := uint64(0)
	for _, rs := range [][]Rule{f.Rules.Exact, f.Rules.CIDR} {
		for _, r := range rs {
			if r.Anomaly != 0 {
				anomaly++
			}
		}
	}
	values := map[string]uint64{"CONFIG_BLACKLIST_COUNT": uint64(len(f.Rules.Exact)), "CONFIG_WHITELIST_COUNT": uint64(len(f.Rules.Whitelist)), "CONFIG_RULE_BITMAP": f.Rules.ExactBitmap, "CONFIG_WL_BITMAP": f.Rules.WhitelistBitmap, "CONFIG_CIDR_RULE_COUNT": uint64(len(f.Rules.CIDR)), "CONFIG_CIDR_BITMAP": f.Rules.CIDRBitmap, "CONFIG_ANOMALY_RULE_COUNT": anomaly, "CONFIG_RL_CPU_DIVISOR": 1, "CONFIG_FAST_FORWARD_ENABLED": 0, "CONFIG_FILTER_IFINDEX": 0, "CONFIG_WL_MAP_SELECTOR": 0, "CONFIG_RULE_MAP_SELECTOR": 0}
	if len(values) != int(c["CONFIG_MAP_ENTRIES"]) {
		t.Fatal("incomplete configuration inventory")
	}
	for _, name := range []string{"config_a", "config_b"} {
		for symbol, value := range values {
			// Independent reference bytes, not a common encoder/decoder round trip.
			want := make([]byte, 8)
			for j := range want {
				want[j] = byte(value >> (8 * j))
			}
			putRead(t, requireMap(t, main, name), u32(c[symbol]), u64(value), want)
		}
	}
}
func counters(t *testing.T, main *ebpf.Collection, f fixture) map[string]uint64 {
	out := map[string]uint64{}
	for _, rs := range [][]Rule{f.Rules.Exact, f.Rules.CIDR} {
		for _, r := range rs {
			gold := wireGoldens[r.ID]
			b, err := requireMap(t, main, gold.Map).LookupBytes(unhex(gold.Key))
			must(t, err)
			if len(b) != 32 {
				t.Fatalf("candidate missing: %s", r.ID)
			}
			out[r.ID] = binary.LittleEndian.Uint64(b[8:16])
		}
	}
	return out
}
func stats(t *testing.T, main *ebpf.Collection, ncpu int) [5]uint64 {
	var sums [5]uint64
	for i := range sums {
		values := make([]uint64, ncpu)
		must(t, requireMap(t, main, "stats").Lookup(uint32(i), &values))
		if len(values) != ncpu {
			t.Fatal("per-CPU stats length mismatch")
		}
		for _, v := range values {
			sums[i] += v
		}
	}
	return sums
}

type observation struct {
	Decision       Decision
	Return         uint32
	Deltas         map[string]uint64
	WhitelistDelta uint64
}

func observe(t *testing.T, main, gate *ebpf.Collection, f fixture, ncpu int) observation {
	before, bs := counters(t, main, f), stats(t, main, ncpu)
	// Exactly one ordinary Test call. No map/config changes between baselines and
	// immediate readback, no sleep, no parallel tests, no token-bucket prediction.
	ret, _, err := gate.Programs["xdp_whitelist_gate"].Test(makePacket(f.Packet))
	must(t, err)
	after, as := counters(t, main, f), stats(t, main, ncpu)
	obs := observation{Decision: Decision{None, -1, "", "pass_no_match"}, Return: ret, Deltas: map[string]uint64{}}
	if as[3] < bs[3] {
		t.Fatal("whitelist counter decreased")
	}
	obs.WhitelistDelta = as[3] - bs[3]
	hits := 0
	for _, rs := range [][]Rule{f.Rules.Exact, f.Rules.CIDR} {
		for _, r := range rs {
			if after[r.ID] < before[r.ID] {
				t.Fatalf("candidate counter decreased %s", r.ID)
			}
			delta := after[r.ID] - before[r.ID]
			obs.Deltas[r.ID] = delta
			if delta > 1 {
				t.Fatalf("candidate delta=%d want <=1", delta)
			}
			if delta == 0 {
				continue
			}
			hits++
			gold := wireGoldens[r.ID]
			stage := Exact
			if gold.Map == "cidr_blacklist" {
				stage = CIDR
			}
			if r.Anomaly != 0 {
				if stage == Exact {
					stage = AnomalyExact
				} else {
					stage = AnomalyCIDR
				}
			}
			action := "drop"
			b := unhex(gold.Value)
			if b[0] == 2 && r.Anomaly == 0 {
				action = fmt.Sprintf("rate_limit@%d", binary.LittleEndian.Uint32(b[4:8]))
			}
			obs.Decision = Decision{stage, f.Combos[r.ID], r.ID, action}
		}
	}
	if obs.WhitelistDelta > 1 || hits > 1 || obs.WhitelistDelta != 0 && hits != 0 {
		t.Fatalf("ambiguous observations: %+v", obs)
	}
	if obs.WhitelistDelta == 1 {
		if len(f.Rules.Whitelist) != 1 {
			t.Fatal("overlapping whitelist identity is not observable")
		}
		r := f.Rules.Whitelist[0]
		obs.Decision = Decision{Whitelist, f.Combos[r.ID], r.ID, "pass_whitelist"}
	}
	emptyPrune(t, main)
	return obs
}
func calibrationMismatch(obs observation, want Decision) error {
	if obs.Decision != want {
		return fmt.Errorf("identity: got=%+v want=%+v", obs.Decision, want)
	}
	switch {
	case want.Action == "drop":
		if obs.Return != 1 {
			return fmt.Errorf("return: got=%d want XDP_DROP", obs.Return)
		}
	case strings.HasPrefix(want.Action, "rate_limit@"):
		if obs.Return != 1 && obs.Return != 2 {
			return fmt.Errorf("return: invalid rate branch code %d", obs.Return)
		}
	default:
		if obs.Return != 2 {
			return fmt.Errorf("return: got=%d want XDP_PASS", obs.Return)
		}
	}
	return nil
}
func setSlot(t *testing.T, main *ebpf.Collection, slot uint32, p *ebpf.Program) {
	m := requireMap(t, main, "prog_tail_map")
	must(t, m.Put(slot, uint32(p.FD())))
	var id uint32
	must(t, m.Lookup(slot, &id))
	if id != progID(t, p) {
		t.Fatalf("tail slot %d got=%d want=%d", slot, id, progID(t, p))
	}
}

func TestCalibrateLab(t *testing.T) {
	// Historical lab authority remains pre-S2a. New table calibration needs an
	// explicitly authorized contract/authority update, never a shape-based switch.
	if *evalContract != string(PreS2a) {
		t.Fatal("historical calibration requires -eval-contract=pre-s2a")
	}
	if *labSource == "" || *labRecord == "" {
		t.Fatal("explicit lab source root and evidence record required")
	}
	*labSource = tmpPath(t, *labSource)
	recordPath := tmpPath(t, *labRecord)
	source := sourceHashes(t)
	binaryPath, err := os.Executable()
	must(t, err)
	binaryHash := digest(readFile(t, binaryPath))
	ncpu, err := ebpf.PossibleCPU()
	must(t, err)
	if ncpu < 1 {
		t.Fatal("empty possible CPU set")
	}
	if *labPrepare {
		var pins []residentPin
		must(t, json.Unmarshal([]byte(*labPins), &pins))
		if len(pins) == 0 {
			t.Fatal("explicit resident pin inventory required")
		}
		p := preparation{Baseline: authorityBaseline, SourceRoot: *labSource, TestBinarySHA256: binaryHash, Created: time.Now(), SourceHashes: source, Pins: pins, ControllerURL: *labController, AgentURL: *labAgent}
		p.Environment = map[string]string{"nproc": string(command(t, "nproc")), "possible": string(readFile(t, "/sys/devices/system/cpu/possible")), "free_m": string(command(t, "free", "-m")), "possible_cpu_count": strconv.Itoa(ncpu), "go": runtime.Version(), "arch": runtime.GOARCH, "kernel": string(command(t, "uname", "-a"))}
		if !strings.Contains(p.Environment["free_m"], "available") {
			t.Fatal("free -m lacks available column")
		}
		for _, sync := range []struct{ path, body string }{{"atomic", `{"rules":[]}`}, {"whitelist", `{"entries":[]}`}} {
			endpoint := strings.TrimSuffix(p.AgentURL, "/health") + "/sync/" + sync.path
			req, err := http.NewRequest("POST", endpoint, strings.NewReader(sync.body))
			must(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-API-Key", os.Getenv("XDROP_LAB_NODE_API_KEY"))
			client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := client.Do(req)
			must(t, err)
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			must(t, err)
			if resp.StatusCode != 200 {
				t.Fatalf("calibration full sync %s HTTP=%d body=%s", sync.path, resp.StatusCode, body)
			}
		}
		p.Health = health(t, p.ControllerURL, p.AgentURL)
		p.Resident = snapshot(t, pins)
		if len(p.Resident.Programs) == 0 || len(p.Resident.Maps) == 0 {
			t.Fatal("empty resident object baseline")
		}
		for _, name := range []string{"xdrop_main.elf", "xdrop_gate.elf"} {
			if _, err := os.Stat(filepath.Join(*labSource, "node/bpf", name)); !os.IsNotExist(err) {
				t.Fatalf("prepare requires no old ELF %s: %v", name, err)
			}
		}
		b, err := json.MarshalIndent(p, "", "  ")
		must(t, err)
		f, err := os.OpenFile(recordPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		must(t, err)
		_, err = f.Write(b)
		closeErr := f.Close()
		must(t, err)
		must(t, closeErr)
		t.Logf("PREPARED_ONLY record=%s environment=%s", recordPath, mustJSON(t, p.Environment))
		return
	}
	var prep preparation
	must(t, json.Unmarshal(readFile(t, recordPath), &prep))
	if prep.Baseline != authorityBaseline || prep.SourceRoot != *labSource || prep.TestBinarySHA256 != binaryHash || !reflect.DeepEqual(prep.SourceHashes, source) || len(prep.Pins) == 0 || len(prep.Health) != 2 || prep.Created.IsZero() {
		t.Fatal("precompile baseline identity incomplete/mismatched")
	}
	if len(prep.Resident.Programs) == 0 || len(prep.Resident.Maps) == 0 {
		t.Fatal("empty resident object baseline")
	}
	for url, raw := range prep.Health {
		var h struct {
			Status string `json:"status"`
		}
		must(t, json.Unmarshal(raw, &h))
		if h.Status != "healthy" {
			t.Fatalf("saved precompile health %s is not healthy", url)
		}
	}
	if *labBuildCommand == "" || *labCompiler == "" {
		t.Fatal("separately captured compile command and compiler version are required")
	}
	health(t, prep.ControllerURL, prep.AgentURL)
	sameResident(t, prep.Resident, snapshot(t, prep.Pins))
	if t.Failed() {
		return
	}
	TestSourceContract(t)
	TestFixtureContract(t)
	TestWireVectors(t)
	TestPacketVectors(t)
	if t.Failed() {
		return
	}
	for _, f := range fixtures() {
		if f.Want.Stage == AnomalyExact || f.Want.Stage == AnomalyCIDR {
			if f.Want.Action != "drop" {
				t.Fatal("anomaly calibration fixture must use DROP")
			}
		}
	}
	var main, gate *ebpf.Collection
	privatePrograms, privateMaps := map[string]bool{}, map[string]bool{}
	t.Cleanup(func() {
		// Deferred checks still run if object-disappearance queries terminate this
		// cleanup. No subtests are started during testing.T cleanup.
		defer func() {
			if _, err := readHealth(prep.ControllerURL, prep.AgentURL); err != nil {
				t.Error(err)
			}
			sameResident(t, prep.Resident, snapshot(t, prep.Pins))
		}()
		// Clear tail-call references before closing the collections. On the lab
		// 2026-09-15, a private prog_tail_map (0 elements, no process holding an fd)
		// remained visible minutes after a disconnect/restore run, while every
		// private program had gone. Clearing slots before close avoided new
		// leftovers in subsequent runs. The cause of the original residual map
		// was not established by those observations.
		if main != nil {
			if m, ok := main.Maps["prog_tail_map"]; ok && m != nil {
				clearProgArray(t, m)
			}
		}
		if gate != nil {
			gate.Close()
		}
		if main != nil {
			main.Close()
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			// Each query gets its own budget. Sharing the loop's absolute deadline
			// meant that once it passed, bpftool was cancelled mid-run and the
			// leak surfaced as "private-object query prog: context deadline
			// exceeded" — a tooling error where the real finding is "objects are
			// still alive". The loop deadline below is what decides that.
			ps, ms := liveIDs(t, "prog"), liveIDs(t, "map")
			left := 0
			for id := range privatePrograms {
				if _, ok := ps[id]; ok {
					left++
				}
			}
			for id := range privateMaps {
				if _, ok := ms[id]; ok {
					left++
				}
			}
			if left == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("private objects still visible after 10s: %d", left)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

	})
	paths := []string{filepath.Join(*labSource, "node/bpf/xdrop_main.elf"), filepath.Join(*labSource, "node/bpf/xdrop_gate.elf")}
	for _, p := range paths {
		info, err := os.Stat(p)
		must(t, err)
		if !info.ModTime().After(prep.Created) {
			t.Fatalf("ELF predates preparation: %s", p)
		}
		t.Logf("ELF path=%s sha256=%s", p, digest(readFile(t, p)))
	}
	t.Logf("authority=%s source_root=%s test_binary_sha256=%s compiler=%q command=%q", authorityBaseline, *labSource, binaryHash, *labCompiler, *labBuildCommand)
	ms, gs := privateSpec(t, paths[0]), privateSpec(t, paths[1])
	if len(ms.Programs) != 2 || len(gs.Programs) != 1 {
		t.Fatal("unexpected business program inventory")
	}
	for _, name := range capacityMaps {
		if ms.Maps[name] == nil && gs.Maps[name] == nil {
			t.Fatalf("missing capacity map %s", name)
		}
	}
	options := ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogDisabled: true}}
	main, err = ebpf.NewCollectionWithOptions(ms, options)
	must(t, err)
	remember := func(c *ebpf.Collection) {
		for _, m := range c.Maps {
			privateMaps[strconv.FormatUint(uint64(mapID(t, m)), 10)] = true
		}
		for _, p := range c.Programs {
			privatePrograms[strconv.FormatUint(uint64(progID(t, p)), 10)] = true
		}
	}
	remember(main)
	verifyMapInfo(t, ms, main)
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{"whitelist", "stats", "config_a", "config_b", "active_config", "prog_tail_map"} {
		replacements[name] = requireMap(t, main, name)
	}
	if main.Maps["devmap"] != nil {
		replacements["devmap"] = main.Maps["devmap"]
	}
	options.MapReplacements = replacements
	gate, err = ebpf.NewCollectionWithOptions(gs, options)
	must(t, err)
	remember(gate)
	verifyMapInfo(t, gs, gate)
	for name, m := range replacements {
		other := requireMap(t, gate, name)
		if mapID(t, m) != mapID(t, other) {
			t.Fatalf("shared map ID differs %s", name)
		}
		t.Logf("shared map=%s id=%d", name, mapID(t, m))
	}
	c := constants(t)
	setSlot(t, main, c["TAIL_SLOT_FIREWALL_MAIN"], main.Programs["xdp_firewall_main"])
	setSlot(t, main, c["TAIL_SLOT_ANOMALY_VERIFY"], main.Programs["xdp_anomaly_verify"])
	if gate.Programs["xdp_whitelist_gate"] == nil {
		t.Fatal("gate entry absent")
	}
	for _, f := range fixtures() {
		ok := t.Run(f.Name, func(t *testing.T) {
			resetFixture(t, main, gate, f, c, ncpu)
			obs := observe(t, main, gate, f, ncpu)
			t.Logf("observation=%s evidence_channels=%s", mustJSON(t, obs), mustJSON(t, f.Evidence))
			must(t, calibrationMismatch(obs, f.Want))
			got, err := Evaluate(testTables(t), f.Rules, f.Packet)
			must(t, err)
			checkDecision(t, got, f.Want)
		})
		if !ok {
			return
		}
	}
	// Reuse existing DROP probes; expected failure must be an identity mismatch,
	// never a loading, map I/O or Test error. Restore each private slot immediately.
	for _, control := range []struct {
		slot          uint32
		program, name string
	}{{c["TAIL_SLOT_FIREWALL_MAIN"], "xdp_firewall_main", "1-priority"}, {c["TAIL_SLOT_ANOMALY_VERIFY"], "xdp_anomaly_verify", "5-anomaly-exact"}} {
		var f fixture
		for _, candidate := range fixtures() {
			if candidate.Name == control.name {
				f = candidate
			}
		}
		if f.Name == "" {
			t.Fatal("missing named tail control fixture")
		}
		ok := t.Run("disconnect-"+control.program, func(t *testing.T) {
			slot := requireMap(t, main, "prog_tail_map")
			must(t, slot.Delete(control.slot))
			defer setSlot(t, main, control.slot, main.Programs[control.program])
			raw, err := slot.LookupBytes(control.slot)
			must(t, err)
			if raw != nil {
				t.Fatal("tail slot remains populated")
			}
			resetFixture(t, main, gate, f, c, ncpu)
			obs := observe(t, main, gate, f, ncpu)
			mismatch := calibrationMismatch(obs, f.Want)
			if mismatch == nil || !strings.HasPrefix(mismatch.Error(), "identity:") {
				t.Fatalf("wrong broken-slot failure: %v", mismatch)
			}
			t.Logf("expected calibration failure: %v; observation=%s", mismatch, mustJSON(t, obs))
		})
		if !ok {
			return
		}
		resetFixture(t, main, gate, f, c, ncpu)
		obs := observe(t, main, gate, f, ncpu)
		must(t, calibrationMismatch(obs, f.Want))
		t.Logf("restored %s observation=%s", control.program, mustJSON(t, obs))
	}
}

// liveIDs gives each query its own timeout, independent of the cleanup retry deadline.
func liveIDs(t *testing.T, kind string) map[string]bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "bpftool", "-j", kind, "show").CombinedOutput()
	if err != nil {
		t.Fatalf("private-object query %s: %v; %s", kind, err, out)
	}
	var objects []map[string]json.RawMessage
	must(t, json.Unmarshal(out, &objects))
	ids := map[string]bool{}
	for _, obj := range objects {
		raw, ok := obj["id"]
		if !ok || bytes.Equal(raw, []byte("null")) {
			t.Fatal("object query lacks id")
		}
		var id uint32
		must(t, json.Unmarshal(raw, &id))
		if id == 0 {
			t.Fatal("object id is zero")
		}
		ids[strconv.FormatUint(uint64(id), 10)] = true
	}
	return ids
}
func mustJSON(t *testing.T, v any) string { b, err := json.Marshal(v); must(t, err); return string(b) }

// Frozen source provenance from the explicitly authorized commit, not HEAD.
var baselineBPFHashes = map[string]string{
	"node/bpf/Makefile":                          "be83e5a238950554e9d5638e05119783d9b4089964cbfa334e412abeb0eaf837",
	"node/bpf/combo_masks.h":                     "9cfa30722183816b4cc860b7822827a34e2da2c1f8daf17a167de95997e1de3c",
	"node/bpf/headers/bpf_helpers.h":             "ac22dae8c99e5702073d8ecd9fc75beb9fc29c67a2a1face4211cca579ba2d13",
	"node/bpf/tools/combo_masks_pre_m1.json":     "dfc9d788cc2ec4a87521711cf6e84bde51dcd64f2865f252f806197c42f72dc6",
	"node/bpf/tools/extract_combo_masks.py":      "3242f104b9fe8644d4f8c10d81d472e9584ff72b335aad337310fbd5acf65683",
	"node/bpf/tools/m1_verify.sh":                "95274f0832a39a74345404f70cbbb4053eb886c8579db211d5856351ef0f6597",
	"node/bpf/tools/test_extract_combo_masks.py": "137b8f4e7d79048a7b80c3a91add0c83472f5d0ea2343f39f052d95045c7a4b1",
	"node/bpf/xdrop.h":                           "5beb7825c01f141f054981cbd810cb08b7ca9721765219e447583ecca1cb62cf",
	"node/bpf/xdrop_gate.c":                      "a15a6d1081d82c7d815d18a0918198876240d69be0ba843e67c4f28ac5f58199",
	"node/bpf/xdrop_main.c":                      "3fb5f0fd31e6e6ec5ba0164dd77e167473d9e542bb6a0a3527a0a33dbbdcd02e",
}
