//go:build linux && integration

package sync

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	stdsync "sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"golang.org/x/sys/unix"
)

// Read-only agent-owned map observer (supports auto fallback without pins), invoked by track B's persistent supervisor.
func TestCloseoutPinnedSnapshot(t *testing.T) {
	out := os.Getenv("XDROP_CLOSEOUT_PIN_SNAPSHOT")
	if out == "" {
		return
	}
	id, err := strconv.ParseUint(os.Getenv("XDROP_CLOSEOUT_PIN_ID"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	var m *ebpf.Map
	if pid := os.Getenv("XDROP_CLOSEOUT_AGENT_PID"); pid != "" {
		// /proc/<agent>/fdinfo scopes IDs to this agent, never a host-wide map
		// name search. Opening by ID borrows an observer FD; this helper never writes maps.
		if _, err := strconv.ParseUint(pid, 10, 32); err != nil {
			t.Fatal(err)
		}
		files, e := os.ReadDir(filepath.Join("/proc", pid, "fdinfo"))
		if e != nil {
			t.Fatal(e)
		}
		seen := map[ebpf.MapID]bool{}
		for _, f := range files {
			raw, e := os.ReadFile(filepath.Join("/proc", pid, "fdinfo", f.Name()))
			if os.IsNotExist(e) {
				continue
			} // An unrelated socket FD may close during observation.
			if e != nil {
				t.Fatal(e)
			}
			for _, line := range strings.Split(string(raw), "\n") {
				if !strings.HasPrefix(line, "map_id:") {
					continue
				}
				n, e := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "map_id:")), 10, 32)
				if e != nil {
					t.Fatal(e)
				}
				id := ebpf.MapID(n)
				if seen[id] {
					continue
				}
				seen[id] = true
				candidate, e := ebpf.NewMapFromID(id)
				if e != nil {
					t.Fatal(e)
				}
				info, e := candidate.Info()
				if e != nil {
					candidate.Close()
					t.Fatal(e)
				}
				if info.Name == "id_rl_states" {
					if m != nil {
						candidate.Close()
						m.Close()
						t.Fatal("ambiguous agent id_rl_states")
					}
					m = candidate
				} else {
					candidate.Close()
				}
			}
		}
		if m == nil {
			t.Fatal("agent id_rl_states map missing")
		}
	} else {
		m, err = ebpf.LoadPinnedMap("/sys/fs/bpf/xdrop/id_rl_states", nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	slots := make([][16]byte, cpus)
	row := map[string]interface{}{"present": false}
	err = m.Lookup(uint32(id), &slots)
	if err == nil {
		values := make([]map[string]interface{}, cpus)
		for i, slot := range slots {
			values[i] = map[string]interface{}{"cpu": i, "tokens": binary.LittleEndian.Uint64(slot[:8]), "last_update_present": binary.LittleEndian.Uint64(slot[8:]) != 0}
		}
		row["present"], row["slots"] = true, values
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatal(err)
	}
	data, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(out, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("CLOSEOUT_PIN_SNAPSHOT logical_id=%d present=%v", id, row["present"])
}

type closeoutPacket struct {
	Name, Frame string
	FrameLength int
	SeedEmpty   bool
}
type closeoutStep struct {
	Name, Method, Path, Fault, SourceFault string
	Requests                               []closeoutStep
	Body                                   json.RawMessage
	Packets                                []closeoutPacket
	Witnesses                              []string
	Hits                                   []bool
	RateLimits                             map[string]uint64
}
type closeoutScene struct {
	Family, Name, Source string
	Steps                []closeoutStep
	NoRefillNS           int64
}
type closeoutData struct {
	Judgments []struct {
		Leaf     string
		Body     json.RawMessage
		Expected map[string]interface{}
	}
	Characterizations []struct {
		Leaf, TD, Track, Method, Path, Registration string
		Body                                        json.RawMessage
		Expected                                    map[string]interface{}
		Evidence                                    []string
	}
	Scenes           []closeoutScene
	Counts           map[string][3]int
	HistoricalCounts map[string][3]int
	Concurrent       struct {
		Single, Commits []closeoutStep
		Full, Whitelist closeoutStep
		Packets         []closeoutPacket
		ExpectedPackets []interface{}
		Legal           []struct {
			I, J     int
			Terminal map[string]interface{}
			Replies  []map[string]interface{}
		}
	}
}
type closeoutFixture struct {
	*cut5ReplayFixture
	gate    *ebpf.Collection
	manager *cidr.Manager
	writers []*closeoutTrie
}
type closeoutTrie struct {
	*ebpf.Map
	beforeDelete     func(interface{})
	failDelete       atomic.Bool
	entered, release chan struct{}
	blockKey         []byte
	once             stdsync.Once
}

func (w *closeoutTrie) Delete(key interface{}) error {
	if w.beforeDelete != nil {
		w.beforeDelete(key)
	}
	if w.failDelete.Load() {
		return errors.New("injected closeout trie delete")
	}
	return w.Map.Delete(key)
}
func (w *closeoutTrie) Put(key, value interface{}) error {
	if err := w.Map.Put(key, value); err != nil {
		return err
	}
	if w.entered != nil {
		var b bytes.Buffer
		if err := binary.Write(&b, binary.LittleEndian, key); err != nil {
			return err
		}
		if bytes.Equal(b.Bytes(), w.blockKey) {
			w.once.Do(func() { close(w.entered) })
			<-w.release
		}
	}
	return nil
}

// Separate fixture: gate and main share their kernel maps, with main in slot 1.
func closeoutOpen(t *testing.T) *closeoutFixture {
	t.Helper()
	load := func(path string) *ebpf.CollectionSpec {
		if path == "" {
			t.Fatal("CLOSEOUT_FIXTURE main and gate ELF paths required")
		}
		s, e := ebpf.LoadCollectionSpec(path)
		if e != nil {
			t.Fatal(e)
		}
		for name, m := range s.Maps {
			if m.Pinning != ebpf.PinNone {
				t.Fatalf("CLOSEOUT_FIXTURE unexpected pin %s", name)
			}
			if (m.Type == ebpf.Hash || m.Type == ebpf.PerCPUHash || m.Type == ebpf.LPMTrie) && m.MaxEntries > 256 {
				m.MaxEntries = 256
			}
		}
		return s
	}
	mainSpec := load(os.Getenv("XDROP_BPF_ELF"))
	main, e := ebpf.NewCollection(mainSpec)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(main.Close)
	gateSpec := load(os.Getenv("XDROP_GATE_ELF"))
	replacements := map[string]*ebpf.Map{}
	for name := range gateSpec.Maps {
		if m := main.Maps[name]; m != nil {
			replacements[name] = m
		}
	}
	gate, e := ebpf.NewCollectionWithOptions(gateSpec, ebpf.CollectionOptions{MapReplacements: replacements})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(gate.Close)
	m, g := main.Maps, gate.Maps
	if main.Programs["xdp_firewall_main"] == nil || gate.Programs["xdp_whitelist_gate"] == nil {
		t.Fatal("CLOSEOUT_FIXTURE required program absent")
	}
	if e = m["prog_tail_map"].Put(uint32(1), uint32(main.Programs["xdp_firewall_main"].FD())); e != nil {
		t.Fatal(e)
	}
	var fd uint32
	if e = g["prog_tail_map"].Lookup(uint32(1), &fd); e != nil {
		t.Fatal("CLOSEOUT_FIXTURE gate tail slot absent: ", e)
	}
	writers := []*closeoutTrie{}
	for _, name := range []string{"sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b"} {
		writers = append(writers, &closeoutTrie{Map: m[name]})
	}
	mgr := cidr.NewManager(writers[0], writers[1], writers[2], writers[3], writers[4], writers[5], writers[6], writers[7])
	if os.Getenv("XDROP_CLOSEOUT_STARTUP_CHILD") == "1" {
		// Exhaust the child's descriptor allowance only after loading the fixture.
		// The next real operation is NewHandlers' receipt creation, which must fail.
		var limit unix.Rlimit
		if e = unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); e != nil {
			t.Fatal(e)
		}
		limit.Cur = 0
		if e = unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); e != nil {
			t.Fatal(e)
		}
	}
	h := api.NewHandlers(m["blacklist"], m["whitelist"], g["whitelist_b"], m["stats"], m["config_a"], m["config_b"], m["active_config"], m["cidr_blacklist"], mgr, m["blacklist_b"], m["cidr_blist_b"], g["tailcall_fail_stats"], m["id_counts"], m["cond_a"], m["cond_b"], m["cidr_cond_a"], m["cidr_cond_b"], m["id_rl_states"], m["cond_row_missing"])
	t.Cleanup(h.Shutdown)
	for _, name := range []string{"config_a", "config_b"} {
		if e = m[name].Put(uint32(api.ConfigRLCPUDivisor), uint64(1)); e != nil {
			t.Fatal(e)
		}
	}
	r := gin.New()
	handlers := map[string]gin.HandlerFunc{
		"GET /": h.Welcome, "GET /api/v1/health": h.Health,
		"GET /api/v1/rules/hits": h.Hits,
		"GET /api/v1/rules":      h.ListRules, "POST /api/v1/rules/commit": h.CommitRules,
		"GET /api/v1/whitelist": h.ListWhitelist, "POST /api/v1/sync/atomic": h.AtomicSync,
		"POST /api/v1/sync/whitelist": h.SyncWhitelistHandler, "GET /api/v1/stats": h.GetStats,
		"GET /api/v1/stats/cpu": h.GetCPUStats,
	}

	var routes []struct {
		Method, Path string
		Auth         bool
	}
	closeoutRead(t, closeoutPath("routes.json"), &routes)
	if len(routes) != 10 || len(handlers) != 10 {
		t.Fatal("CLOSEOUT_FIXTURE route count mismatch")
	}
	for _, route := range routes {
		fn, ok := handlers[route.Method+" "+route.Path]
		if !ok {
			t.Fatalf("CLOSEOUT_FIXTURE unknown route %+v", route)
		}
		r.Handle(route.Method, route.Path, fn)
	}
	f := &cut5ReplayFixture{h: h, coll: main, wl: g["whitelist_b"], router: r}
	return &closeoutFixture{f, gate, mgr, writers}
}
func closeoutPath(name string) string {
	if root := os.Getenv("XDROP_CLOSEOUT_DIR"); root != "" {
		return filepath.Join(root, name)
	}
	return filepath.Join("closeout", name)
}
func closeoutRead(t *testing.T, path string, v interface{}) {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, v); e != nil {
		t.Fatal(e)
	}
}
func closeoutHTTP(t *testing.T, f *closeoutFixture, method, path string, body []byte) (int, interface{}) {
	t.Helper()
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
	var v interface{}
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		if w.Code == 404 && w.Body.String() == "404 page not found" && closeoutDeleted(method, path) {
			return w.Code, w.Body.String()
		}
		t.Fatalf("CLOSEOUT_FIXTURE invalid JSON status=%d body=%s", w.Code, w.Body.String())
	}
	return w.Code, v
}
func closeoutGet(t *testing.T, f *closeoutFixture, path string) interface{} {
	s, b := closeoutHTTP(t, f, "GET", path, nil)
	if s != 200 {
		t.Fatalf("CLOSEOUT_FIXTURE readback %s status=%d body=%v", path, s, b)
	}
	return b
}
func closeoutCPU(t *testing.T, f *closeoutFixture, stats interface{}) interface{} {
	t.Helper()
	var cpu api.CPUStatsResponse
	value := closeoutGet(t, f, "/api/v1/stats/cpu")
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &cpu); e != nil {
		t.Fatal(e)
	}
	var total api.Stats
	raw, e = json.Marshal(stats)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &total); e != nil {
		t.Fatal(e)
	}
	got := [5]uint64{}
	seen := map[int]bool{}
	for _, c := range cpu.PerCPU {
		if seen[c.CPU] {
			t.Fatal("CLOSEOUT_WITNESS S5 duplicate CPU")
		}
		seen[c.CPU] = true
		got[0] += c.TotalPackets
		got[1] += c.DroppedPackets
		got[2] += c.PassedPackets
		got[3] += c.WhitelistedPackets
		got[4] += c.RateLimitedPackets
	}
	want := [5]uint64{total.TotalPackets, total.DroppedPackets, total.PassedPackets, total.WhitelistedPackets, total.RateLimitedPackets}
	if len(seen) == 0 || got != want {
		t.Errorf("CLOSEOUT_WITNESS S5 cpu_sum got=%v want=%v slots=%d", got, want, len(seen))
	}
	if cpu.DivisorInMap == nil || *cpu.DivisorInMap != 1 || cpu.DivisorInMapError != "" {
		t.Fatalf("CLOSEOUT_FIXTURE divisor readback=%+v", cpu)
	}
	return value
}
func closeoutPinCPU(t *testing.T) int {
	t.Helper()
	runtime.LockOSThread()
	var old unix.CPUSet
	if e := unix.SchedGetaffinity(0, &old); e != nil {
		t.Fatal(e)
	}
	cpu := 0
	for !old.IsSet(cpu) {
		cpu++
	}
	var one unix.CPUSet
	one.Set(cpu)
	if e := unix.SchedSetaffinity(0, &one); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := unix.SchedSetaffinity(0, &old); e != nil {
			t.Error(e)
		}
		runtime.UnlockOSThread()
	})
	return cpu
}
func closeoutProbe(t *testing.T, f *closeoutFixture, p closeoutPacket) interface{} {
	t.Helper()
	frame, e := hex.DecodeString(p.Frame)
	if e != nil || len(frame) != p.FrameLength || len(frame) < 34 {
		t.Fatalf("CLOSEOUT_FIXTURE frame %s invalid", p.Name)
	}
	before := cut5ReplayCounters(t, f.cut5ReplayFixture)
	verdict, _, e := f.gate.Programs["xdp_whitelist_gate"].Test(frame)
	if e != nil {
		t.Fatal(e)
	}
	if verdict != 1 && verdict != 2 {
		t.Fatalf("CLOSEOUT_FIXTURE parsed frame %s verdict=%d (ABORTED excluded)", p.Name, verdict)
	}
	after := cut5ReplayCounters(t, f.cut5ReplayFixture)
	delta := map[string]uint64{}
	for key, v := range after {
		if v != before[key] {
			delta[key] = v - before[key]
		}
	}
	return map[string]interface{}{"packet": p.Name, "verdict": verdict, "counter_delta": delta}
}
func closeoutFault(t *testing.T, f *closeoutFixture, fault string, observed *int) func() {
	if fault == "trie_delete" {
		for _, w := range f.writers {
			w.failDelete.Store(true)
		}
		return func() {
			for _, w := range f.writers {
				w.failDelete.Store(false)
			}
		}
	}
	return cut5ReplayFault(t, f.cut5ReplayFixture, fault, observed)
}
func closeoutDeleted(method, path string) bool {
	if method == "POST" {
		return path == "/api/v1/rules" || path == "/api/v1/rules/batch" || path == "/api/v1/whitelist" || path == "/api/v1/whitelist/batch"
	}
	return (method == "PUT" && strings.HasPrefix(path, "/api/v1/rules/")) || (method == "DELETE" && (strings.HasPrefix(path, "/api/v1/rules/") || strings.HasPrefix(path, "/api/v1/whitelist/")))
}
func closeoutStartup(t *testing.T, f *closeoutFixture, step closeoutStep) (*closeoutFixture, interface{}) {
	t.Helper()
	f.h.Shutdown()
	f.coll.Close()
	f.gate.Close()
	f = closeoutOpen(t)
	if len(step.Requests) != 2 || step.Requests[0].Path != "/api/v1/sync/atomic" || step.Requests[1].Path != "/api/v1/sync/whitelist" {
		t.Fatal("CLOSEOUT_FIXTURE restart requires atomic then empty whitelist")
	}
	replies := []interface{}{}
	for _, request := range step.Requests {
		status, body := closeoutHTTP(t, f, request.Method, request.Path, request.Body)
		replies = append(replies, map[string]interface{}{"status": status, "body": body})
	}
	return f, map[string]interface{}{"startup_success": true, "replies": replies}
}
func closeoutWrite(t *testing.T, path string, v interface{}) {
	t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}

type closeoutIntentRule struct {
	Want                  map[string]json.RawMessage
	Absent                []string
	WhitelistEmpty, Whole bool
	Exemptions            []string
}

func closeoutIntent(t *testing.T, cell string, installed, whitelist interface{}, intents map[string]closeoutIntentRule) {
	t.Helper()
	intent, selected := intents[cell]
	if !selected {
		return
	}
	// ONLY stats is excluded. Unknown fields, duplicates and object shape count.
	rows := installed.(map[string]interface{})["rules"].([]interface{})
	got := map[string]interface{}{}
	ok := true
	for _, row := range rows {
		r := row.(map[string]interface{})
		id := r["id"].(string)
		if _, dup := got[id]; dup {
			ok = false
		}
		obj := map[string]interface{}{}
		for k, v := range r {
			if k != "stats" {
				obj[k] = v
			}
		}
		got[id] = obj
	}
	for id, raw := range intent.Want {
		var want interface{}
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got[id], want) {
			ok = false
			t.Logf("intent object cell=%s id=%s actual=%v expected=%v", cell, id, got[id], want)
		}
	}
	for _, id := range intent.Absent {
		if _, present := got[id]; present {
			ok = false
		}
	}
	if intent.Whole && len(got) != len(intent.Want) {
		ok = false
	}
	if intent.WhitelistEmpty && len(whitelist.(map[string]interface{})["entries"].([]interface{})) != 0 {
		ok = false
	}
	if strings.HasSuffix(cell, "/pure_exact/update") || strings.HasSuffix(cell, "/pure_cidr/update") {
		if len(intent.Want) != 1 {
			t.Fatal("CLOSEOUT_FIXTURE pure-update source intent")
		}
		for _, raw := range intent.Want {
			checked, err := cut5ReplayCheckPureUpdate(cell, cut5ReplayStep{Method: "PUT", Body: raw}, installed)
			if !checked || err != nil {
				ok = false
				t.Logf("pure_updates cell=%s error=%v", cell, err)
			}
		}
	}
	n := 0
	if ok {
		n = 1
	}
	t.Logf("CLOSEOUT_INTENT cell=%s ok=%d", cell, n)
	if !ok {
		t.Errorf("CLOSEOUT_WITNESS intent cell=%s", cell)
	}
}

func TestCloseoutTrackA(t *testing.T) {
	if os.Getenv("XDROP_CLOSEOUT_STARTUP_CHILD") == "1" {
		closeoutOpen(t)
		t.Fatal("receipt creation unexpectedly succeeded")
		return
	}
	gin.SetMode(gin.TestMode)
	var data closeoutData
	closeoutRead(t, closeoutPath("scenarios_closeout.json"), &data)
	if len(data.Scenes) == 0 {
		t.Fatal("CLOSEOUT_FIXTURE no scenarios")
	}
	var intents map[string]closeoutIntentRule
	closeoutRead(t, closeoutPath("intents.json"), &intents)
	if len(intents) == 0 {
		t.Fatal("CLOSEOUT_FIXTURE independent intents absent")
	}
	requests := 0
	records := map[string]interface{}{}
	cpuRecords := map[string]interface{}{}
	counts := map[string][3]int{}
	history := map[string][3]int{}
	for _, scene := range data.Scenes {
		scene := scene
		t.Run(scene.Name, func(t *testing.T) {
			cpu := closeoutPinCPU(t)
			f := closeoutOpen(t)
			rateStarted := map[string]time.Time{}
			row := counts[scene.Family]
			row[0]++
			counts[scene.Family] = row
			hr := history[scene.Source]
			if scene.Source != "" {
				hr[0]++
			}
			for _, step := range scene.Steps {
				caseName := scene.Name + "/" + step.Name
				if scene.Family == "S8" {
					if step.Method == "RESTART" {
						requests += len(step.Requests)
					} else {
						requests++
					}
				}
				var status interface{}
				var body interface{}
				observed := 0
				paymentBefore := cut5ReplayField(f.h, "logicalPaymentFailures").Uint()
				switch step.Method {
				case "STARTUP_FAILURE":
					c := exec.Command(os.Args[0], "-test.run=^TestCloseoutTrackA$")
					c.Env = append(os.Environ(), "XDROP_CLOSEOUT_STARTUP_CHILD=1")
					out, e := c.CombinedOutput()
					var exit *exec.ExitError
					if !errors.As(e, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("Failed to create quiescence receipt")) {
						t.Fatalf("CLOSEOUT_FIXTURE startup failure witness: %v %s", e, out)
					}
					body = map[string]interface{}{"startup_refused": true}
				case "STARTUP_CLEAR_FAILURE":
					body = map[string]interface{}{"startup_refused": cut5ReplayStartupClearFailure(t, f.cut5ReplayFixture)}
				case "RESTART":
					f, body = closeoutStartup(t, f, step)
				default:
					restore := closeoutFault(t, f, step.Fault, &observed)
					if step.Fault == "zero_logical_id" {
						var v struct {
							Rules []api.Rule `json:"rules"`
						}
						if e := json.Unmarshal(step.Body, &v); e != nil {
							t.Fatal(e)
						}
						if len(v.Rules) != 1 || v.Rules[0].LogicalID == 0 {
							t.Fatal("CLOSEOUT_FIXTURE zero ID precondition")
						}
						observed++
						v.Rules[0].LogicalID = 0
						step.Body, _ = json.Marshal(v)
					}
					code, b := closeoutHTTP(t, f, step.Method, step.Path, step.Body)
					restore()
					status, body = code, b
					if step.SourceFault == "capacity_one_payment_failure" {
						observed = int(cut5ReplayField(f.h, "logicalPaymentFailures").Uint() - paymentBefore)
					}
					if step.SourceFault == "capacity_one" && closeoutCapacityRejected(step.Path, code, b) {
						observed++
					}
					if caseName == "scenarios_commit_p5/I15_failure_9a/retire" {
						reply, ok := b.(map[string]interface{})
						pending := cut5ReplayField(f.h, "pendingLogicalIDs")
						if !ok || reply["code"] != "committed" || reply["receipt"] != "deferred" || pending.Len() == 0 || observed == 0 {
							t.Fatal("CLOSEOUT_WITNESS I15-9a pending/deferred/Rc")
						}
						t.Logf("CLOSEOUT_I159A_RETIRE pending=%d deferred=1 receipts=%d", pending.Len(), observed)
					}
					if step.Path == "/" {
						body = map[string]interface{}{"sync_protocol": b.(map[string]interface{})["sync_protocol"]}
					}
				}
				rec := map[string]interface{}{"family": scene.Family, "path": step.Path, "status": status, "body": body, "installed": closeoutGet(t, f, "/api/v1/rules"), "whitelist": closeoutGet(t, f, "/api/v1/whitelist")}
				closeoutIntent(t, caseName, rec["installed"], rec["whitelist"], intents)
				probes := []interface{}{}
				seeded := false
				for id := range rateStarted {
					if step.RateLimits[id] == 0 {
						delete(rateStarted, id)
					}
				}
				started := time.Now()
				for _, p := range step.Packets {
					if p.SeedEmpty && !seeded {
						cut5ReplayRateInitial(t, f.cut5ReplayFixture)
						seeded = true
						started = time.Now()
						rateStarted = map[string]time.Time{}
					}
					beforeProbe := time.Now()
					probe := closeoutProbe(t, f, p)
					probes = append(probes, probe)
					for key := range probe.(map[string]interface{})["counter_delta"].(map[string]uint64) {
						parts := strings.Split(key, "/")
						if len(parts) != 3 || parts[0] != "id_counts" || parts[2] != "match" {
							continue
						}
						b, err := hex.DecodeString(parts[1])
						if err != nil || len(b) != 4 {
							t.Fatal("counter key")
						}
						id := strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b)), 10)
						rate := step.RateLimits[id]
						if rate == 0 {
							continue
						}
						if rateStarted[id].IsZero() {
							rateStarted[id] = beforeProbe
						}
						// divisor=1: floor(elapsed*rate/NS) must remain zero, across steps.
						window := time.Duration(1000000000 / rate)
						if time.Since(rateStarted[id]) >= window {
							t.Fatalf("CLOSEOUT_FIXTURE rate window id=%s rate=%d limit_ns=%d", id, rate, window)
						}
					}
				}
				if scene.NoRefillNS > 0 && time.Since(started) >= time.Duration(scene.NoRefillNS) {
					t.Fatalf("CLOSEOUT_FIXTURE zero refill witness exceeded ns=%d", scene.NoRefillNS)
				}
				if seeded && time.Since(started) >= 500*time.Millisecond {
					t.Fatal("CLOSEOUT_FIXTURE historical empty-bucket window exceeded")
				}
				rec["packets"], rec["installed_after"], rec["stats"] = probes, closeoutGet(t, f, "/api/v1/rules"), closeoutGet(t, f, "/api/v1/stats")
				if step.SourceFault != "" {
					if step.SourceFault == "rt_no_tail" {
						var id uint32
						err := f.coll.Maps["prog_tail_map"].Lookup(uint32(0), &id)
						anomalyExecuted := 0
						for i, packet := range step.Packets {
							if packet.Name == "invalid_tcp" && i < len(probes) {
								anomalyExecuted++
							}
						}
						if !errors.Is(err, ebpf.ErrKeyNotExist) || anomalyExecuted != 1 {
							t.Fatal("CLOSEOUT_WITNESS rt_no_tail environment")
						}
						observed = anomalyExecuted
					}
					t.Logf("CLOSEOUT_FAULT_EXEC cell=%s fault=%s observed=%d", caseName, step.SourceFault, observed)
					if observed == 0 {
						t.Errorf("CLOSEOUT_WITNESS fault not executed cell=%s fault=%s", caseName, step.SourceFault)
					}
				}
				cpuRecords[caseName] = closeoutCPU(t, f, rec["stats"])
				records[caseName] = rec
				row := counts[scene.Family]
				row[1]++
				row[2] += len(step.Packets)
				counts[scene.Family] = row
				if scene.Source != "" {
					hr[1]++
					hr[2] += len(step.Packets)
				}
				for _, w := range step.Witnesses {
					if w == "S5" {
						r := counts[w]
						r[0]++
						r[1]++
						r[2] += len(step.Packets)
						counts[w] = r
						s := rec["stats"].(map[string]interface{})
						if s["dropped_packets"] == s["passed_packets"] {
							t.Errorf("CLOSEOUT_FIXTURE S5 unequal-counter precondition case=%s", caseName)
						}
					}
				}
				t.Logf("CLOSEOUT_CELL_EXEC family=%s case=%s steps=1 packets=%d cpu=%d", scene.Family, caseName, len(step.Packets), cpu)
			}
			if scene.Source != "" {
				history[scene.Source] = hr
			}
		})
	}
	names := []string{}
	for family := range counts {
		names = append(names, family)
	}
	sort.Strings(names)
	for _, family := range names {
		got, want := counts[family], data.Counts[family]
		if got != want || got[0] == 0 || got[1] == 0 || got[2] == 0 {
			t.Errorf("CLOSEOUT_EXECUTION family=%s got=%v want=%v", family, got, want)
		}
		t.Logf("CLOSEOUT_FAMILY family=%s scenes=%d steps=%d packets=%d", family, got[0], got[1], got[2])
	}
	if !reflect.DeepEqual(history, data.HistoricalCounts) {
		t.Errorf("CLOSEOUT_EXECUTION S8 files got=%v want=%v", history, data.HistoricalCounts)
	}
	for _, file := range []string{"scenarios.json", "scenarios_p3.json", "scenarios_p4.json", "scenarios_commit_p5.json", "scenarios_p6.json"} {
		r := history[file]
		t.Logf("CLOSEOUT_S8_FILE file=%s scenes=%d steps=%d packets=%d", file, r[0], r[1], r[2])
	}
	scale := counts["S8"]
	if scale[0] < 160 || scale[1] < 354 || scale[2] < 633 {
		t.Fatal("CLOSEOUT_EXECUTION S8 source scale")
	}
	t.Logf("CLOSEOUT_S8_SCALE scenes=%d steps=%d packets=%d requests=%d", scale[0], scale[1], scale[2], requests)
	out := os.Getenv("XDROP_CLOSEOUT_OUT")
	if out == "" {
		t.Fatal("XDROP_CLOSEOUT_OUT required")
	}
	closeoutWrite(t, out, records)
	closeoutWrite(t, out+".cpu.json", cpuRecords)
	expected := os.Getenv("XDROP_CLOSEOUT_EXPECTED")
	if expected == "" {
		t.Fatal("XDROP_CLOSEOUT_EXPECTED required")
	}
	cmd := exec.Command("python3", closeoutPath("compare_closeout.py"), out, expected, "--output", out+".comparison.json")
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	b, e := cmd.CombinedOutput()
	t.Log(string(b))
	if e != nil {
		t.Errorf("CLOSEOUT_WITNESS absolute comparison: %v", e)
	}
	t.Logf("CLOSEOUT_TRACK_A scenes=%d records=%d", len(data.Scenes), len(records))
}

func closeoutCanonical(t *testing.T, v interface{}) interface{} {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var out interface{}
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	if m, ok := out.(map[string]interface{}); ok {
		for _, name := range []string{"rules", "entries"} {
			if rows, ok := m[name].([]interface{}); ok {
				if name == "entries" {
					sort.SliceStable(rows, func(i, j int) bool {
						return rows[i].(map[string]interface{})["id"].(string) < rows[j].(map[string]interface{})["id"].(string)
					})
				}
				if name == "rules" {
					for _, r := range rows {
						if s, ok := r.(map[string]interface{})["stats"].(map[string]interface{}); ok {
							delete(s, "drop_pps")
							delete(s, "match_bytes")
							delete(s, "drop_bytes")
						}
					}
				}
			}
		}
	}
	return out
}
func closeoutMirror(t *testing.T, f *closeoutFixture) {
	t.Helper()
	ready := cut5ReplayField(f.h, "mirrorReady").Bool()
	if !ready {
		t.Log("CLOSEOUT_MIRROR ready=0 contract=full_alignment_required")
		return
	}
	maps := cut5ReplayMaps(t, f.cut5ReplayFixture)
	slot := cut5ReplayField(f.h, "activeRuleSlot")
	_ = slot // Read the selector through the kernel, not atomic.Int32 internals.
	var conf, side uint64
	if e := f.coll.Maps["active_config"].Lookup(uint32(0), &conf); e != nil {
		t.Fatal(e)
	}
	if e := f.coll.Maps[[]string{"config_a", "config_b"}[conf]].Lookup(uint32(api.ConfigRuleMapSelector), &side); e != nil {
		t.Fatal(e)
	}
	pairs := [][2]string{{"blacklist", "blacklist_b"}, {"cidr_blacklist", "cidr_blist_b"}, {"cond_a", "cond_b"}, {"cidr_cond_a", "cidr_cond_b"}}
	for kind, names := range pairs {
		debt := map[string]bool{}
		for _, field := range []string{"mirrorDirty", "mirrorDebt"} {
			v := cut5ReplayField(f.h, field).Index(kind)
			for _, k := range v.MapKeys() {
				debt[hex.EncodeToString([]byte(k.String()))] = true
			}
		}
		active := maps[names[side]].(map[string]interface{})
		shadow := maps[names[1-side]].(map[string]interface{})
		keys := map[string]bool{}
		for k := range active {
			keys[k] = true
		}
		for k := range shadow {
			keys[k] = true
		}
		for key := range keys {
			if !debt[key] && !reflect.DeepEqual(active[key], shadow[key]) {
				t.Errorf("CLOSEOUT_WITNESS S7 mirror kind=%d key=%s outside_dirty_debt", kind, key)
			}
		}
	}
	t.Log("CLOSEOUT_MIRROR ready=1 tables=4 contract=equal_outside_dirty_debt")
}
func TestCloseoutConcurrent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var data closeoutData
	closeoutRead(t, closeoutPath("scenarios_closeout.json"), &data)
	if len(data.Concurrent.Single) != 2 || len(data.Concurrent.Commits) != 2 || len(data.Concurrent.Legal) != 4 {
		t.Fatal("CLOSEOUT_FIXTURE S7 fixed writer inventory")
	}
	closeoutPinCPU(t)
	f := closeoutOpen(t)
	firstA, firstC := make(chan struct{}), make(chan struct{})
	replies := map[string]interface{}{}
	var mutex stdsync.Mutex
	var wg stdsync.WaitGroup
	request := func(name string, s closeoutStep) {
		status, body := closeoutHTTP(t, f, s.Method, s.Path, s.Body)
		mutex.Lock()
		replies[name] = []interface{}{status, body}
		mutex.Unlock()
	}
	for _, writer := range []struct {
		name  string
		steps []closeoutStep
		first chan struct{}
	}{{"A", data.Concurrent.Single, firstA}, {"C", data.Concurrent.Commits, firstC}} {
		writer := writer
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, s := range writer.steps {
				request(fmt.Sprintf("%s%d", writer.name, i), s)
				if i == 0 {
					close(writer.first)
				}
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); <-firstA; <-firstC; request("F", data.Concurrent.Full) }()
	wg.Add(1)
	go func() { defer wg.Done(); request("W", data.Concurrent.Whitelist) }()
	wg.Wait()
	actualRules := closeoutCanonical(t, closeoutGet(t, f, "/api/v1/rules"))
	actualWL := closeoutCanonical(t, closeoutGet(t, f, "/api/v1/whitelist"))
	matches := 0
	i, j := 0, 0
	for _, candidate := range data.Concurrent.Legal {
		if !reflect.DeepEqual(actualRules, closeoutCanonical(t, candidate.Terminal["installed"])) || !reflect.DeepEqual(actualWL, closeoutCanonical(t, candidate.Terminal["whitelist"])) {
			continue
		}
		for _, serial := range candidate.Replies {
			if reflect.DeepEqual(closeoutCanonical(t, replies), closeoutCanonical(t, serial)) {
				matches++
				i, j = candidate.I, candidate.J
				break
			}
		}
	}
	if matches == 0 {
		t.Fatalf("CLOSEOUT_WITNESS S7 legal_serial terminal=%v whitelist=%v replies=%v", actualRules, actualWL, replies)
	}
	for _, r := range actualRules.(map[string]interface{})["rules"].([]interface{}) {
		id := r.(map[string]interface{})["id"]
		if id == "a1" || id == "c1" {
			t.Fatal("CLOSEOUT_WITNESS S7 barrier first requests retained")
		}
	}
	closeoutMirror(t, f)
	if len(data.Concurrent.ExpectedPackets) != len(data.Concurrent.Packets) {
		t.Fatal("CLOSEOUT_FIXTURE S7 packet oracle count")
	}
	for index, p := range data.Concurrent.Packets {
		actual := closeoutProbe(t, f, p)
		if !reflect.DeepEqual(closeoutCanonical(t, actual), closeoutCanonical(t, data.Concurrent.ExpectedPackets[index])) {
			t.Errorf("CLOSEOUT_WITNESS S7 packet=%d actual=%v expected=%v", index, actual, data.Concurrent.ExpectedPackets[index])
		}
	}
	closeoutCPU(t, f, closeoutGet(t, f, "/api/v1/stats"))
	out := os.Getenv("XDROP_CLOSEOUT_OUT")
	if out == "" {
		t.Fatal("XDROP_CLOSEOUT_OUT required")
	}
	closeoutWrite(t, out+".s7.json", map[string]interface{}{"S7/concurrent": map[string]interface{}{"family": "S7", "legal_serial_pass": !t.Failed(), "ij": []int{i, j}, "terminal": actualRules, "replies": replies}})
	t.Logf("CLOSEOUT_S7 scenes=1 steps=6 packets=%d writers=4 barrier=2 pairs=4 legal_serial_pass=%t i=%d j=%d", len(data.Concurrent.Packets), !t.Failed(), i, j)
}

func closeoutCharacterWindow(t *testing.T, f *closeoutFixture, body json.RawMessage) map[string]interface{} {
	t.Helper()
	var input struct {
		Parent, Child string
		Probe         closeoutPacket
	}
	if e := json.Unmarshal(body, &input); e != nil {
		t.Fatal(e)
	}
	old := api.Rule{ID: "parent", LogicalID: 9039, SrcCIDR: input.Parent, Protocol: "tcp", Action: "drop"}
	child := api.Rule{ID: "child", LogicalID: 9040, SrcCIDR: input.Child, Protocol: "tcp", Action: "drop"}
	call := func(path string, value interface{}) (int, interface{}) {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		return closeoutHTTP(t, f, "POST", path, raw)
	}
	request := func(rules []api.Rule) (int, interface{}) { return call("/api/v1/sync/atomic", gin.H{"rules": rules}) }
	status, reply := call("/api/v1/rules/commit", gin.H{"groups": []interface{}{gin.H{"key": gin.H{"kind": "cidr", "src_cidr": input.Parent, "src_port": 0, "dst_port": 0, "protocol": "tcp"}, "rules": []api.Rule{old}}}})
	if status != 200 || reply.(map[string]interface{})["receipt"] != "confirmed" {
		t.Fatalf("CLOSEOUT_FIXTURE TD039 not_executed seed_confirmed=0 status=%d body=%v", status, reply)
	}
	parentKey := []byte{16, 0, 0, 0, 10, 90, 0, 0}
	var parentIDs [2]uint32
	for slot := 0; slot < 2; slot++ {
		if e := f.writers[slot*4].Lookup(parentKey, &parentIDs[slot]); e != nil || parentIDs[slot] == 0 {
			t.Fatalf("CLOSEOUT_FIXTURE TD039 not_executed parent_copy=%d error=%v", slot, e)
		}
	}
	if parentIDs[0] != parentIDs[1] {
		t.Fatal("CLOSEOUT_FIXTURE TD039 not_executed parent IDs differ")
	}
	status, reply = request([]api.Rule{old, child})
	if status != 409 || reply.(map[string]interface{})["code"] != "cidr_overlap" {
		t.Fatalf("CLOSEOUT_FIXTURE TD039 nested_guard status=%d body=%v", status, reply)
	}
	if p := closeoutProbe(t, f, input.Probe).(map[string]interface{}); p["verdict"] != uint32(1) {
		t.Fatalf("CLOSEOUT_FIXTURE TD039 parent verdict=%v", p)
	}
	var before, active uint64
	if e := f.coll.Maps["active_config"].Lookup(uint32(0), &before); e != nil {
		t.Fatal(e)
	}
	config := f.coll.Maps[[]string{"config_a", "config_b"}[before]]
	if e := config.Lookup(uint32(api.ConfigRuleMapSelector), &active); e != nil {
		t.Fatal(e)
	}

	hasOld := 0
	writer := f.writers[int(active)*4]
	writer.beforeDelete = func(k interface{}) {
		var b bytes.Buffer
		if err := binary.Write(&b, binary.LittleEndian, k); err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(b.Bytes(), parentKey) {
			return
		}
		var selector uint64
		var retained uint32
		e := f.coll.Maps["active_config"].Lookup(uint32(0), &selector)
		if e == nil && selector != before && writer.Lookup(parentKey, &retained) == nil && retained == parentIDs[active] {
			hasOld = 1
		}
		writer.beforeDelete = nil
	}
	defer func() { writer.beforeDelete = nil }()
	key := []byte{24, 0, 0, 0, 10, 90, 1, 0}
	for _, index := range []int{0, 4} {
		w := f.writers[index]
		w.blockKey = key
		w.entered = make(chan struct{})
		w.release = make(chan struct{})
	}
	var release stdsync.Once
	unblock := func() { release.Do(func() { close(f.writers[0].release); close(f.writers[4].release) }) }
	defer unblock()
	type result struct {
		status int
		body   interface{}
	}
	done := make(chan result, 1)
	go func() { status, body := request([]api.Rule{child}); done <- result{status, body} }()
	written := 0
	select {
	case <-f.writers[0].entered:
	case <-f.writers[4].entered:
		written = 1
	case <-time.After(10 * time.Second):
		t.Fatal("CLOSEOUT_FIXTURE TD039 not_executed child Put absent")
	}
	var prefixID uint32
	if e := f.writers[written*4].Lookup(key, &prefixID); e != nil || prefixID == 0 {
		t.Fatalf("CLOSEOUT_FIXTURE TD039 child_written id=%d error=%v", prefixID, e)
	}
	var during uint64
	if e := f.coll.Maps["active_config"].Lookup(uint32(0), &during); e != nil || during != before {
		t.Fatalf("CLOSEOUT_FIXTURE TD039 selector_unflipped before=%d during=%d error=%v", before, during, e)
	}
	probe := closeoutProbe(t, f, input.Probe).(map[string]interface{})
	copyName := "shadow"
	if written == int(active) {
		copyName = "active"
	}
	t.Log("CLOSEOUT_TD039_PRECONDITION seed_confirmed=1 parent_copies=2 parent_drop=1 child_written=1 selector_unflipped=1")
	t.Logf("CLOSEOUT_WITNESS TD039 written_copy=%s verdict=%v", copyName, probe["verdict"])
	if copyName != "shadow" || probe["verdict"] != uint32(1) {
		t.Errorf("CLOSEOUT_JUDGMENT TD039-window expected written_copy=shadow verdict=1")
	}
	// Both judgments are recorded before release; post-flip guards cannot steal AB-2.
	unblock()
	select {
	case r := <-done:
		want := gin.H{"success": true, "added": 1, "failed": 0, "rules": 0, "cidr_rules": 1, "rejected": []interface{}{}}
		if r.status != 200 || !reflect.DeepEqual(closeoutCanonical(t, r.body), closeoutCanonical(t, want)) {
			t.Fatalf("CLOSEOUT_FIXTURE TD039 completion status=%d body=%v", r.status, r.body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("CLOSEOUT_FIXTURE TD039 completion timeout")
	}
	t.Logf("CLOSEOUT_TD039_REVERSE old_copy_has_old=%d", hasOld)
	if hasOld != 1 {
		t.Errorf("CLOSEOUT_WITNESS TD039-reverse old parent must remain until post-flip old-side delete")
	}
	if after := closeoutProbe(t, f, input.Probe).(map[string]interface{}); after["verdict"] != uint32(1) {
		t.Errorf("CLOSEOUT_TD039_POST_FLIP verdict=%v expected=1", after["verdict"])
	}
	return map[string]interface{}{"written_copy": copyName, "verdict": probe["verdict"]}
}
func TestCloseoutPrefixAB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var data closeoutData
	closeoutRead(t, closeoutPath("scenarios_closeout.json"), &data)
	if len(data.Judgments) != 2 || data.Judgments[0].Leaf != "TD039-window" || data.Judgments[1].Leaf != "TD039-reverse" {
		t.Fatal("judgment manifest")
	}
	closeoutPinCPU(t)
	f := closeoutOpen(t)
	actual := closeoutCharacterWindow(t, f, data.Judgments[0].Body)
	if !reflect.DeepEqual(closeoutCanonical(t, actual), closeoutCanonical(t, data.Judgments[0].Expected)) {
		t.Errorf("CLOSEOUT_JUDGMENT TD039-window actual=%v expected=%v", actual, data.Judgments[0].Expected)
	}
	t.Log("CLOSEOUT_PREFIX_AB judgments=2 executed=2")
}
func TestCloseoutCharacterization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var data closeoutData
	closeoutRead(t, closeoutPath("scenarios_closeout.json"), &data)
	if len(data.Characterizations) != 6 {
		t.Fatal("CLOSEOUT_CHARACTER leaf manifest must contain six cells")
	}
	records := map[string]interface{}{}
	leaves := 0
	for _, cell := range data.Characterizations {
		if cell.Track != "A" {
			continue
		}
		cell := cell
		t.Run(cell.Leaf, func(t *testing.T) {
			if len(cell.Evidence) == 0 || (cell.Registration != "predicted" && cell.Registration != "registered") {
				t.Fatal("CLOSEOUT_CHARACTER missing evidence/registration")
			}
			closeoutPinCPU(t)
			f := closeoutOpen(t)
			actual := map[string]interface{}{}
			if cell.Leaf == "TD039-window" {
				actual = closeoutCharacterWindow(t, f, cell.Body)
			} else {
				status, body := closeoutHTTP(t, f, cell.Method, cell.Path, cell.Body)
				m := body.(map[string]interface{})
				actual["http"], actual["code"] = status, m["code"]
				installed := closeoutGet(t, f, "/api/v1/rules").(map[string]interface{})
				if strings.HasPrefix(cell.Leaf, "TD064-") {
					actual["installed"] = installed["count"].(float64) > 0
				} else {
					var configSlot, ruleSlot uint64
					if err := f.coll.Maps["active_config"].Lookup(uint32(0), &configSlot); err != nil {
						t.Fatal(err)
					}
					if err := f.coll.Maps[[]string{"config_a", "config_b"}[configSlot]].Lookup(uint32(api.ConfigRuleMapSelector), &ruleSlot); err != nil {
						t.Fatal(err)
					}
					trie := f.writers[ruleSlot*4].Map
					var key [8]byte
					err := trie.NextKey(nil, &key)
					actual["published"] = err == nil
					if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatal(err)
					}
					var length interface{}
					if err == nil {
						length = binary.LittleEndian.Uint32(key[:4])
					}
					actual["prefix_len"] = length
				}
			}
			records[cell.Leaf] = actual
			leaves++
			if !reflect.DeepEqual(closeoutCanonical(t, actual), closeoutCanonical(t, cell.Expected)) {
				t.Errorf("CLOSEOUT_WITNESS %s actual=%v predicted=%v registration=%s", cell.Leaf, actual, cell.Expected, cell.Registration)
			}
			t.Logf("CLOSEOUT_CHARACTER leaf=%s executed=1 registration=%s actual=%v", cell.Leaf, cell.Registration, actual)
		})
	}
	if leaves != 4 {
		t.Errorf("CLOSEOUT_CHARACTER A leaves=%d expected=4", leaves)
	}
	out := os.Getenv("XDROP_CLOSEOUT_OUT")
	if out == "" {
		t.Fatal("XDROP_CLOSEOUT_OUT required")
	}
	closeoutWrite(t, out+".character.json", records)
	t.Logf("CLOSEOUT_CHARACTER_A leaves=%d manifest=%d", leaves, len(data.Characterizations))
}
