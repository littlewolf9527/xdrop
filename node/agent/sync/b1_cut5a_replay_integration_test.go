//go:build linux && integration

package sync

// This driver is copied byte-for-byte to the archived baseline. All requests,
// exported HTTP handlers and ELF map names exist at cd89372. Optional fixture
// hooks use reflection so this same driver also compiles on the older tree.
import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/api"
	"github.com/littlewolf9527/xdrop/node/agent/bpf"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
	"golang.org/x/sys/unix"
)

type cut5ReplayStep struct {
	Name, Method, Path, Fault              string
	Expect                                 string
	ExpectP2, ExpectP3, ExpectP4, ExpectP6 string
	HitsP3, HitsP4, HitsP6                 []bool
	Body                                   json.RawMessage
	Packets                                []string
}
type cut5ReplayScene struct {
	Name      string
	Authority string
	Steps     []cut5ReplayStep
}
type cut5ReplayFixture struct {
	h      *api.Handlers
	coll   *ebpf.Collection
	wl     *ebpf.Map
	router *gin.Engine
}

func cut5ReplayOpen(t *testing.T) *cut5ReplayFixture {
	t.Helper()
	path := os.Getenv("XDROP_BPF_ELF")
	if path == "" {
		t.Fatal("XDROP_BPF_ELF required")
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			t.Fatalf("unexpected pin: %s", name)
		}
		// Identical bounded private-map capacity on both sides. No program,
		// value schema, selector, array capacity or map name is changed.
		if (m.Type == ebpf.Hash || m.Type == ebpf.PerCPUHash || m.Type == ebpf.LPMTrie) && m.MaxEntries > 256 {
			m.MaxEntries = 256
		}
	}
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	m := c.Maps
	wl, err := ebpf.NewMap(spec.Maps["whitelist"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wl.Close() })
	mgr := cidr.NewManager(m["sv4_cidr_trie"], m["dv4_cidr_trie"], m["sv6_cidr_trie"], m["dv6_cidr_trie"], m["sv4_cidr_trie_b"], m["dv4_cidr_trie_b"], m["sv6_cidr_trie_b"], m["dv6_cidr_trie_b"])
	args := []interface{}{m["blacklist"], m["whitelist"], wl, m["stats"], m["config_a"], m["config_b"], m["active_config"], m["rl_states"], m["cidr_blacklist"], m["cidr_rl_states"], mgr, m["blacklist_b"], m["cidr_blist_b"], (*ebpf.Map)(nil), m["id_counts"]}
	constructor := reflect.ValueOf(api.NewHandlers)
	if constructor.Type().NumIn() == 19 {
		args = []interface{}{m["blacklist"], m["whitelist"], wl, m["stats"], m["config_a"], m["config_b"], m["active_config"], m["cidr_blacklist"], mgr, m["blacklist_b"], m["cidr_blist_b"], (*ebpf.Map)(nil), m["id_counts"]}
		for _, name := range []string{"cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b", "id_rl_states", "cond_row_missing"} {
			args = append(args, m[name])
		}
	} else if constructor.Type().NumIn() == 20 {
		for _, name := range []string{"cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b", "id_rl_states"} {
			args = append(args, m[name])
		}
	}
	if len(args) != constructor.Type().NumIn() {
		t.Fatalf("unknown constructor arity %d", constructor.Type().NumIn())
	}
	values := make([]reflect.Value, len(args))
	for i, arg := range args {
		values[i] = reflect.ValueOf(arg)
	}
	h := constructor.Call(values)[0].Interface().(*api.Handlers)
	t.Cleanup(h.Shutdown)
	if cut5ReplayLogicalProtocol(api.SyncProtocol) {
		if c.Programs["xdp_anomaly_verify"] != nil {
			t.Fatal("protocol 4 retained retired program")
		}
		if err := m["prog_tail_map"].Delete(uint32(0)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
	} else {
		program := c.Programs["xdp_anomaly_verify"]
		if program == nil {
			t.Fatal("protocol 3 missing required anomaly program")
		}
		if err := m["prog_tail_map"].Put(uint32(0), uint32(program.FD())); err != nil {
			t.Fatal(err)
		}
	}
	r := gin.New()
	r.GET("/", h.Welcome)
	if commit := reflect.ValueOf(h).MethodByName("CommitRules"); commit.IsValid() {
		r.POST("/api/v1/rules/commit", func(c *gin.Context) { commit.Call([]reflect.Value{reflect.ValueOf(c)}) })
	}
	r.POST("/api/v1/sync/atomic", h.AtomicSync)
	r.POST("/api/v1/sync/whitelist", h.SyncWhitelistHandler)
	r.GET("/api/v1/rules", h.ListRules)
	return &cut5ReplayFixture{h, c, wl, r}
}

func cut5ReplayNormalize(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		for _, key := range []string{"stats", "drop_pps", "timestamp", "last_updated", "created_at", "updated_at"} {
			delete(x, key)
		}
		for key, value := range x {
			x[key] = cut5ReplayNormalize(value)
		}
		return x
	case []interface{}:
		for i := range x {
			x[i] = cut5ReplayNormalize(x[i])
		}
		if len(x) > 0 {
			if m, ok := x[0].(map[string]interface{}); ok && m["id"] != nil {
				sort.SliceStable(x, func(i, j int) bool {
					return fmt.Sprint(x[i].(map[string]interface{})["id"]) < fmt.Sprint(x[j].(map[string]interface{})["id"])
				})
			}
		}
		return x
	}
	return v
}

func cut5ReplayHTTP(t *testing.T, f *cut5ReplayFixture, method, path string, body []byte) (int, interface{}) {
	t.Helper()
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
	var value interface{}
	dec := json.NewDecoder(bytes.NewReader(w.Body.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("response %d is not JSON: %s", w.Code, w.Body.String())
	}
	return w.Code, cut5ReplayNormalize(value)
}

func cut5ReplayLogicalProtocol(protocol int) bool { return protocol >= 4 }

func cut5ReplayEffectiveExpect(step cut5ReplayStep, protocol int) string {
	if protocol >= 6 && step.ExpectP6 != "" {
		return step.ExpectP6
	}
	if protocol == 2 && step.ExpectP2 != "" {
		return step.ExpectP2
	}
	if cut5ReplayLogicalProtocol(protocol) && step.ExpectP4 != "" {
		return step.ExpectP4
	}
	if protocol >= 3 && step.ExpectP3 != "" {
		return step.ExpectP3
	}
	return step.Expect
}

// Independent expectations prevent two equally rejected requests from passing
// the cross-tree equality gate. The caller resolves each HTTP step's intent.
func cut5ReplayCheckResponse(step cut5ReplayStep, status int, body interface{}) error {
	m, ok := body.(map[string]interface{})
	if !ok {
		return fmt.Errorf("response is not an object: %v", body)
	}
	switch step.Expect {
	case "committed", "unchanged", "deferred":
		expected := step.Expect
		if expected == "deferred" {
			expected = "committed"
		}
		if status != 200 || m["code"] != expected {
			return fmt.Errorf("commit response: %d %v", status, body)
		}
		if step.Expect == "unchanged" {
			if _, exists := m["receipt"]; exists {
				return fmt.Errorf("unchanged has receipt")
			}
		} else {
			receipt := "confirmed"
			if step.Expect == "deferred" {
				receipt = "deferred"
			}
			if m["receipt"] != receipt {
				return fmt.Errorf("commit receipt: %v", body)
			}
		}
	case "commit_failed", "quiescence_failed", "withdrawal_pending":
		if status != 500 || m["code"] != step.Expect {
			return fmt.Errorf("commit failure: %d %v", status, body)
		}
	case "welcome":
		if status != 200 || m["sync_protocol"] != json.Number(fmt.Sprint(api.SyncProtocol)) {
			return fmt.Errorf("welcome version witness failed: %d %v", status, body)
		}
	case "condition_group_required", "condition_group_invalid", "duplicate_key", "table_full", "group_undeclared", "duplicate_id", "cidr_overlap", "condition_capacity":
		if status != 409 || m["code"] != step.Expect {
			return fmt.Errorf("expected 409 %s: got %d %v", step.Expect, status, body)
		}
	case "partial_rejection":
		if status != 200 || m["success"] != true || m["failed"] == json.Number("0") {
			return fmt.Errorf("expected explicit partial rejection: %d %v", status, body)
		}
	case "invalid":
		if status != 400 || m["code"] != "validation_rejected" {
			return fmt.Errorf("expected 400 invalid: %d %v", status, body)
		}
	case "missing":
		if status != 404 || m["code"] != "rule_not_found" {
			return fmt.Errorf("expected 404 missing: %d %v", status, body)
		}
	case "publish_failure":
		if status != 500 {
			return fmt.Errorf("expected publish failure: %d %v", status, body)
		}
	case "success":
		if status < 200 || status >= 300 {
			return fmt.Errorf("successful write must be 2xx: got=%d body=%v", status, body)
		}
		if m["success"] != true {
			return fmt.Errorf("successful write did not report success: %v", body)
		}
		if failed, exists := m["failed"]; exists && failed != json.Number("0") {
			return fmt.Errorf("successful write has failed items: %v", body)
		}
	case "content_different":
		if status != http.StatusConflict || m["code"] != "content_different" {
			return fmt.Errorf("content replay must reach content_different: status=%d body=%v", status, body)
		}
	case "logical_id_replay", "duplicate_logical_id":
		// These are the explicit I3/I1 cross-version differences. The finite
		// allowed.json table still requires each exact old/new field value.
		if status != http.StatusOK && status != http.StatusConflict {
			return fmt.Errorf("logical ID witness rejected before identity check: status=%d body=%v", status, body)
		}
	default:
		return fmt.Errorf("HTTP step lacks a known expectation: %q", step.Expect)
	}
	return nil
}

func cut5ReplayCheckPureUpdate(prefix string, step cut5ReplayStep, installed interface{}) (bool, error) {
	if !strings.HasSuffix(prefix, "/pure_exact/update") && !strings.HasSuffix(prefix, "/pure_cidr/update") {
		return false, nil
	}
	var want api.Rule
	if err := json.Unmarshal(step.Body, &want); err != nil {
		return false, err
	}
	if step.Method != http.MethodPut || want.Action != "rate_limit" || want.RateLimit != 1 {
		return false, fmt.Errorf("pure tuple update script must change drop to rate_limit(1)")
	}
	raw, err := json.Marshal(installed)
	if err != nil {
		return false, err
	}
	var got struct{ Rules []api.Rule }
	if err := json.Unmarshal(raw, &got); err != nil {
		return false, err
	}
	if len(got.Rules) != 1 {
		return false, fmt.Errorf("pure tuple update installed count=%d want=1", len(got.Rules))
	}
	r := got.Rules[0]
	if r.ID != want.ID || r.LogicalID != want.LogicalID || r.Action != want.Action || r.RateLimit != want.RateLimit || r.Protocol != want.Protocol || r.SrcIP != want.SrcIP || r.DstIP != want.DstIP || r.SrcCIDR != want.SrcCIDR || r.DstCIDR != want.DstCIDR || r.SrcPort != want.SrcPort || r.DstPort != want.DstPort {
		return false, fmt.Errorf("pure tuple update installed value differs: got=%+v want=%+v", r, want)
	}
	return true, nil
}

func cut5ReplayMaps(t *testing.T, f *cut5ReplayFixture) map[string]interface{} {
	t.Helper()
	out := map[string]interface{}{}
	names := []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b", "cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b", "config_a", "config_b", "active_config", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "id_counts", "id_rl_states", "stats"}
	if api.SyncProtocol >= 8 {
		names = append(names, "sv4_cidr_trie_b", "dv4_cidr_trie_b", "sv6_cidr_trie_b", "dv6_cidr_trie_b")
	}
	if cut5ReplayLogicalProtocol(api.SyncProtocol) {
		if f.coll.Maps["cond_row_missing"] == nil {
			t.Fatal("protocol 4 missing diagnostic map")
		}
	} else {
		names = append(names, "rl_states", "cidr_rl_states")
	}
	for _, name := range names {
		m := f.coll.Maps[name]
		if m == nil {
			t.Fatalf("required shared map missing: %s", name)
		}
		rows := map[string]interface{}{}
		var cursor interface{}
		for {
			key := make([]byte, m.KeySize())
			if err := m.NextKey(cursor, &key); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					break
				}
				t.Fatal(err)
			}
			if name == "stats" && binary.LittleEndian.Uint32(key) >= 6 {
				cursor = append([]byte(nil), key...)
				continue
			}
			label := hex.EncodeToString(key)
			if m.Type() == ebpf.PerCPUHash || m.Type() == ebpf.PerCPUArray {
				cpus, err := ebpf.PossibleCPU()
				if err != nil {
					t.Fatal(err)
				}
				v := make([][]byte, cpus)
				if name == "id_counts" && m.ValueSize() == 40 {
					slots := make([][40]byte, cpus)
					if err := m.Lookup(key, &slots); err != nil {
						t.Fatal(err)
					}
					for i := range slots {
						v[i] = append([]byte(nil), slots[i][:]...)
					}
				} else if m.ValueSize() == 16 {
					slots := make([][16]byte, cpus)
					if err := m.Lookup(key, &slots); err != nil {
						t.Fatal(err)
					}
					for i := range slots {
						v[i] = append([]byte(nil), slots[i][:]...)
					}
				} else {
					slots := make([]uint64, cpus)
					if err := m.Lookup(key, &slots); err != nil {
						t.Fatal(err)
					}
					for i, value := range slots {
						v[i] = make([]byte, 8)
						binary.LittleEndian.PutUint64(v[i], value)
					}
				}
				if strings.Contains(name, "rl_states") {
					tokens := []uint64{}
					timeSet := []bool{}
					for _, cpu := range v {
						tokens = append(tokens, binary.LittleEndian.Uint64(cpu))
						timeSet = append(timeSet, binary.LittleEndian.Uint64(cpu[8:]) != 0)
					}
					rows[label] = map[string]interface{}{"tokens": tokens, "last_update_present": timeSet}
				} else {
					width := m.ValueSize() / 8
					if name == "id_counts" {
						width = 2
					}
					sums := make([]uint64, width)
					for _, cpu := range v {
						for i := range sums {
							sums[i] += binary.LittleEndian.Uint64(cpu[i*8:])
						}
					}
					rows[label] = sums
				}
			} else {
				v := make([]byte, m.ValueSize())
				if err := m.Lookup(key, &v); err != nil {
					t.Fatal(err)
				}
				rows[label] = hex.EncodeToString(v)
			}
			cursor = append([]byte(nil), key...)
		}
		out[name] = rows
	}
	return out
}

func cut5ReplayFrame(name string) []byte {
	p := make([]byte, 54)
	binary.BigEndian.PutUint16(p[12:], 0x0800)
	p[14] = 0x45
	binary.BigEndian.PutUint16(p[16:], 40)
	p[22] = 64
	p[23] = 6
	copy(p[26:30], []byte{192, 0, 2, 1})
	copy(p[30:34], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(p[34:], 1234)
	binary.BigEndian.PutUint16(p[36:], 80)
	p[46] = 0x50
	p[47] = 2
	switch name {
	case "miss":
		copy(p[26:30], []byte{203, 0, 113, 1})
	case "ack":
		p[47] = 16
	case "length400":
		p = append(p, make([]byte, 360)...)
		binary.BigEndian.PutUint16(p[16:], 400)
	case "bad_fragment":
		binary.BigEndian.PutUint16(p[20:], 0x2000)
	case "invalid_tcp":
		p[46] = 0x40
	case "icmp_zero":
		p[23], p[34], p[35] = 1, 0, 0
	case "length_mismatch":
		binary.BigEndian.PutUint16(p[16:], 60)
	case "length_mismatch_ack":
		binary.BigEndian.PutUint16(p[16:], 60)
		p[47] = 16
	case "offset_one":
		binary.BigEndian.PutUint16(p[20:], 1)
	case "syn", "rate":
	default:
		panic("unknown scripted packet " + name)
	}
	return p
}

func cut5ReplayCounters(t *testing.T, f *cut5ReplayFixture) map[string]uint64 {
	out := map[string]uint64{}
	inline := !cut5ReplayLogicalProtocol(api.SyncProtocol) || os.Getenv("XDROP_CUT54_INLINE_COUNTER_MUTANT") == "1"
	if inline {
		for _, name := range []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b"} {
			m := f.coll.Maps[name]
			iter := m.Iterate()
			key := make([]byte, m.KeySize())
			v := make([]byte, 32)
			for iter.Next(&key, &v) {
				out[name+"/"+hex.EncodeToString(key)+"/match"] = binary.LittleEndian.Uint64(v[8:])
				out[name+"/"+hex.EncodeToString(key)+"/drop"] = binary.LittleEndian.Uint64(v[16:])
			}
			if err := iter.Err(); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The mutant deliberately reads ONLY obsolete row counters on protocol 4.
	if cut5ReplayLogicalProtocol(api.SyncProtocol) && inline {
		return out
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	it := f.coll.Maps["id_counts"].Iterate()
	var id uint32
	values := make([][5]uint64, cpus)
	for it.Next(&id, &values) {
		var key [4]byte
		binary.LittleEndian.PutUint32(key[:], id)
		for _, v := range values {
			out["id_counts/"+hex.EncodeToString(key[:])+"/match"] += v[0]
			out["id_counts/"+hex.EncodeToString(key[:])+"/drop"] += v[1]
		}
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Private fixture injection never edits production state through a new HTTP
// route. The common driver also compiles against the baseline's private shape.
func cut5ReplayField(h *api.Handlers, name string) reflect.Value {
	f := reflect.ValueOf(h).Elem().FieldByName(name)
	if !f.IsValid() {
		return reflect.Value{}
	}
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
}

type cut55ReplayReceipt func() error

func (f cut55ReplayReceipt) Quiesce() error { return f() }

type cut55ReplayDeleteFault struct {
	*ebpf.Map
	hit func()
}

func (m cut55ReplayDeleteFault) Delete(interface{}) error {
	m.hit()
	return errors.New("injected full_step1_delete")
}

func (m cut55ReplayDeleteFault) BatchLookup(c *ebpf.MapBatchCursor, k, v interface{}, o *ebpf.BatchOptions) (int, error) {
	return m.Map.BatchLookup(c, k, v, o)
}
func (m cut55ReplayDeleteFault) BatchUpdate(k, v interface{}, o *ebpf.BatchOptions) (int, error) {
	return m.Map.BatchUpdate(k, v, o)
}
func (m cut55ReplayDeleteFault) BatchDelete(k interface{}, _ *ebpf.BatchOptions) (int, error) {
	if reflect.ValueOf(k).Len() == 0 {
		return 0, nil
	}
	return 0, m.Delete(nil)
}

type cut55ReplayLookupFault struct {
	*ebpf.Map
	hit func()
}

func (m cut55ReplayLookupFault) Lookup(key, value interface{}) error {
	m.hit()
	return errors.New("lookup: bad file descriptor")
}

func cut5ReplayFault(t *testing.T, f *cut5ReplayFixture, fault string, observed ...*int) func() {
	t.Helper()
	hit := func() {
		if len(observed) > 0 {
			*observed[0]++
		}
	}
	if fault == "capacity_one_payment_failure" {
		capacity := cut5ReplayField(f.h, "logicalStateCapacity")
		oldCap := capacity.Int()
		capacity.SetInt(1)
		receipt := cut5ReplayField(f.h, "quiescer")
		old := reflect.New(receipt.Type()).Elem()
		old.Set(receipt)
		receipt.Set(reflect.ValueOf(cut55ReplayReceipt(func() error { return errors.New("injected payment receipt") })))
		return func() { capacity.SetInt(oldCap); receipt.Set(old) }
	}
	if fault == "R0" || fault == "Rc" || fault == "1" {
		receipt := cut5ReplayField(f.h, "quiescer")
		old := reflect.New(receipt.Type()).Elem()
		old.Set(receipt)
		loadSlot := func() int64 {
			return cut5ReplayField(f.h, "activeRuleSlot").Addr().MethodByName("Load").Call(nil)[0].Int()
		}
		beforeSlot := loadSlot()
		receipt.Set(reflect.ValueOf(cut55ReplayReceipt(func() error {
			if fault == "R0" || loadSlot() != beforeSlot {
				hit()
				return errors.New("injected " + fault)
			}
			return old.Interface().(interface{ Quiesce() error }).Quiesce()
		})))
		flag := cut5ReplayField(f.h, "quiescenceConfirmed")
		confirmed := flag.Bool()
		if fault == "R0" {
			flag.SetBool(false)
		}
		return func() {
			receipt.Set(old)
			if fault == "R0" {
				flag.SetBool(confirmed)
			}
		}
	}
	if strings.HasPrefix(fault, "c-") {
		v := cut5ReplayField(f.h, "commitFaultTestHook")
		if !v.IsValid() {
			t.Fatal("commit fault requires commit implementation")
		}
		old := reflect.New(v.Type()).Elem()
		old.Set(v)
		v.Set(reflect.MakeFunc(v.Type(), func(args []reflect.Value) []reflect.Value {
			var err error
			if args[0].String() == fault {
				hit()
				err = errors.New("injected " + fault)
			}
			out := reflect.New(reflect.TypeOf((*error)(nil)).Elem()).Elem()
			if err != nil {
				out.Set(reflect.ValueOf(err))
			}
			return []reflect.Value{out}
		}))
		return func() { v.Set(old) }
	}
	if fault == "full_step1_delete" {
		fixture := cut5ReplayField(f.h, "mirrorTableFixture")
		if !fixture.IsValid() {
			t.Fatal("strict full fixture requires protocol 5")
		}
		old := reflect.New(fixture.Type()).Elem()
		old.Set(fixture)
		var config, slot uint64
		if err := f.coll.Maps["active_config"].Lookup(uint32(0), &config); err != nil {
			t.Fatal(err)
		}
		if err := f.coll.Maps[[]string{"config_a", "config_b"}[config]].Lookup(uint32(9), &slot); err != nil {
			t.Fatal(err)
		}
		orphan := make([]byte, 40)
		copy(orphan, []byte{0x20, 1, 0x0d, 0xb8})
		orphan[15] = 254
		table := f.coll.Maps[[]string{"blacklist", "blacklist_b"}[1-slot]]
		if err := table.Update(orphan, make([]byte, 32), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		fixture.Set(reflect.MakeFunc(fixture.Type(), func(args []reflect.Value) []reflect.Value {
			side, kind := int(args[0].Int()), int(args[1].Int())
			names := [2][4]string{{"blacklist", "cidr_blacklist", "cond_a", "cidr_cond_a"}, {"blacklist_b", "cidr_blist_b", "cond_b", "cidr_cond_b"}}
			m := f.coll.Maps[names[side][kind]]
			result := reflect.New(fixture.Type().Out(0)).Elem()
			if side != int(slot) && kind == 0 {
				result.Set(reflect.ValueOf(cut55ReplayDeleteFault{m, hit}))
			} else {
				result.Set(reflect.ValueOf(m))
			}
			return []reflect.Value{result}
		}))
		return func() { fixture.Set(old) }
	}
	switch fault {
	case "capacity_one":
		v := cut5ReplayField(f.h, "logicalStateCapacity")
		if v.IsValid() {
			old := v.Int()
			v.SetInt(1)
			return func() { v.SetInt(old) }
		}
	case "active_config_lookup":
		var slot uint64
		if err := f.coll.Maps["active_config"].Lookup(uint32(0), &slot); err != nil {
			t.Fatal(err)
		}
		v := cut5ReplayField(f.h, "configPublishFixture")
		old := reflect.New(v.Type()).Elem()
		old.Set(v)
		fixture := reflect.New(v.Type().Elem())
		values := []interface{}{f.coll.Maps[[]string{"config_b", "config_a"}[slot]], cut55ReplayLookupFault{f.coll.Maps[[]string{"config_a", "config_b"}[slot]], hit}, f.coll.Maps["active_config"]}
		for i, value := range values {
			field := fixture.Elem().Field(i)
			reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
		}
		v.Set(fixture)
		return func() { v.Set(old) }
	case "rt_no_tail":
		if err := f.coll.Maps["prog_tail_map"].Delete(uint32(0)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatal(err)
		}
	}
	return func() {}
}
func cut5ReplayStartupClearFailure(t *testing.T, f *cut5ReplayFixture) bool {
	t.Helper()
	m := f.coll.Maps["blacklist"]
	if err := m.Put(make([]byte, 40), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := m.Freeze(); err != nil {
		t.Fatal(err)
	}
	method := reflect.ValueOf(f.h).MethodByName("ReplayPinnedStartupForCut53")
	if method.IsValid() {
		gate := &ebpf.Collection{Maps: map[string]*ebpf.Map{"whitelist_b": f.wl}}
		v := method.Call([]reflect.Value{reflect.ValueOf(f.coll), reflect.ValueOf(gate)})
		if !v[0].IsNil() {
			if !strings.Contains(v[0].Interface().(error).Error(), "business blacklist") {
				t.Fatal(v[0].Interface())
			}
			return true
		}
		return false
	}
	// HEAD 7e405a7 main logs the ordinary clear error and continues startup.
	_ = bpf.ClearDataMaps(f.coll, []string{"blacklist", "blacklist_b", "whitelist", "cidr_blacklist", "cidr_blist_b", "cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b", "rl_states", "cidr_rl_states", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie"})
	for _, name := range []string{"id_counts", "id_rl_states"} {
		if _, err := bpf.ClearMapKeys(f.coll.Maps[name]); err != nil {
			t.Fatal(err)
		}
	}
	_ = bpf.ClearDataMaps(&ebpf.Collection{Maps: map[string]*ebpf.Map{"whitelist_b": f.wl}}, []string{"whitelist_b"})
	return false
}

// Absolute monotonic timestamps are deliberately not compared across processes.
// Their per-CPU update relation is recorded around every actual packet instead.
func cut5ReplayTimes(t *testing.T, f *cut5ReplayFixture) map[string][]uint64 {
	t.Helper()
	out := map[string][]uint64{}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"id_rl_states"}
	if !cut5ReplayLogicalProtocol(api.SyncProtocol) {
		names = append(names, "rl_states", "cidr_rl_states")
	}
	for _, name := range names {
		m := f.coll.Maps[name]
		it := m.Iterate()
		key := make([]byte, m.KeySize())
		values := make([][16]byte, cpus)
		for it.Next(&key, &values) {
			stamps := make([]uint64, cpus)
			for i := range values {
				stamps[i] = binary.LittleEndian.Uint64(values[i][8:])
			}
			out[name+"/"+hex.EncodeToString(key)] = stamps
		}
		if err := it.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func cut5ReplayTimeChanges(before, after map[string][]uint64) map[string][]bool {
	out := map[string][]bool{}
	for key, stamps := range after {
		changed := make([]bool, len(stamps))
		for i, stamp := range stamps {
			changed[i] = len(before[key]) <= i || before[key][i] != stamp
		}
		out[key] = changed
	}
	return out
}

func cut5ReplayMutateVerdict(t *testing.T, f *cut5ReplayFixture) {
	var slot uint64
	if err := f.coll.Maps["active_config"].Lookup(uint32(0), &slot); err != nil {
		t.Fatal(err)
	}
	config := "config_a"
	if slot == 1 {
		config = "config_b"
	}
	var selector uint64
	if err := f.coll.Maps[config].Lookup(uint32(api.ConfigRuleMapSelector), &selector); err != nil {
		t.Fatal(err)
	}
	name := "blacklist"
	if selector == 1 {
		name = "blacklist_b"
	}
	m := f.coll.Maps[name]
	key := make([]byte, 40)
	if err := m.NextKey(nil, &key); err != nil {
		t.Fatal(err)
	}
	v := make([]byte, 32)
	if err := m.Lookup(key, &v); err != nil {
		t.Fatal(err)
	}
	v[0] = api.ActionPass
	if err := m.Update(key, v, ebpf.UpdateExist); err != nil {
		t.Fatal(err)
	}
}

func cut5ReplayRateInitial(t *testing.T, f *cut5ReplayFixture) {
	t.Helper()
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config_a", "config_b"} {
		if err := f.coll.Maps[name].Put(uint32(api.ConfigRLCPUDivisor), uint64(1)); err != nil {
			t.Fatal(err)
		}
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"blacklist", "rl_states"}, {"blacklist_b", "rl_states"}, {"cidr_blacklist", "cidr_rl_states"}, {"cidr_blist_b", "cidr_rl_states"}} {
		m := f.coll.Maps[pair[0]]
		iter := m.Iterate()
		key := make([]byte, m.KeySize())
		v := make([]byte, 32)
		for iter.Next(&key, &v) {
			if v[0] != api.ActionRateLimit || v[28]&1 != 0 {
				continue
			}
			slots := make([][16]byte, cpus)
			for i := range slots {
				binary.LittleEndian.PutUint64(slots[i][8:], uint64(now.Nano())+uint64(time.Hour))
			}
			bucket, bucketKey := f.coll.Maps[pair[1]], key
			if cut5ReplayLogicalProtocol(api.SyncProtocol) {
				bucket, bucketKey = f.coll.Maps["id_rl_states"], v[8:12]
			}
			if err := bucket.Put(bucketKey, slots); err != nil {
				t.Fatal(err)
			}
		}
		if err := iter.Err(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"cond_a", "cond_b", "cidr_cond_a", "cidr_cond_b"} {
		m := f.coll.Maps[name]
		it := m.Iterate()
		key, v := make([]byte, m.KeySize()), make([]byte, 844)
		for it.Next(&key, &v) {
			for i := 0; i < 4; i++ {
				if v[840]&(1<<i) == 0 || v[804+i] != api.ActionRateLimit {
					continue
				}
				id := binary.LittleEndian.Uint32(v[824+i*4:])
				if id == 0 {
					t.Fatal("rate condition candidate has zero logical ID")
				}
				slots := make([][16]byte, cpus)
				for j := range slots {
					binary.LittleEndian.PutUint64(slots[j][8:], uint64(now.Nano())+uint64(time.Hour))
				}
				if err := f.coll.Maps["id_rl_states"].Put(id, slots); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := it.Err(); err != nil {
			t.Fatal(err)
		}
	}
}

type cut5RewriteTransport struct{ target *url.URL }

func (t cut5RewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	u := *r.URL
	u.Scheme, u.Host = t.target.Scheme, t.target.Host
	c.URL = &u
	return http.DefaultTransport.RoundTrip(c)
}
