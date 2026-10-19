//go:build linux && integration

package api

import (
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/cidr"
)

func b7Rule(isCIDR bool) Rule {
	r := Rule{LogicalID: 17, ID: "r", SrcIP: "10.0.0.1", Protocol: "tcp", Action: "drop"}
	if isCIDR {
		r.SrcIP = ""
		r.SrcCIDR = "10.0.0.0/24"
	}
	return r
}

func b7Code(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var v struct {
		Code string `json:"code"`
	}
	e := json.Unmarshal(w.Body.Bytes(), &v)
	if e != nil || w.Code != status || v.Code != code {
		t.Fatalf("want %d %s got %d %s", status, code, w.Code, w.Body.String())
	}
}
func b7Map(t *testing.T, typ ebpf.MapType, key, value uint32) *ebpf.Map {
	t.Helper()
	spec := &ebpf.MapSpec{Name: "b7_private", Type: typ, KeySize: key, ValueSize: value, MaxEntries: 256}
	if typ == ebpf.LPMTrie {
		spec.Flags = 1
	}
	m, e := ebpf.NewMap(spec)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close() })
	return m
}
func b7Handler(t *testing.T) (*Handlers, *gin.Engine, []*ebpf.Map) {
	h, r := jiaHandler(t)
	tries := []*ebpf.Map{b7Map(t, ebpf.LPMTrie, 8, 4), b7Map(t, ebpf.LPMTrie, 8, 4), b7Map(t, ebpf.LPMTrie, 20, 4), b7Map(t, ebpf.LPMTrie, 20, 4)}
	tries = append(tries, b7Map(t, ebpf.LPMTrie, 8, 4), b7Map(t, ebpf.LPMTrie, 8, 4), b7Map(t, ebpf.LPMTrie, 20, 4), b7Map(t, ebpf.LPMTrie, 20, 4))
	h.cidrMgr = cidr.NewManager(tries[0], tries[1], tries[2], tries[3], tries[4], tries[5], tries[6], tries[7])
	h.idRLStates = b7Map(t, ebpf.PerCPUHash, 4, 16)
	return h, r, tries
}
func b7Snapshot(t *testing.T, m *ebpf.Map) map[string]string {
	t.Helper()
	out := map[string]string{}
	k := make([]byte, m.KeySize())
	v := make([]byte, m.ValueSize())
	it := m.Iterate()
	for it.Next(&k, &v) {
		out[string(k)] = string(v)
	}
	if e := it.Err(); e != nil {
		t.Fatal(e)
	}
	return out
}
func b7Table(h *Handlers, isCIDR bool) (*ebpf.Map, []byte, *ebpf.Map) {
	if isCIDR {
		return p7ActiveCIDR(h), cidrRuleKeyToBytes(h.cidrRules["r"].Key), h.idRLStates
	}
	return p7ActiveBlacklist(h), ruleKeyToBytes(h.rules["r"].Key), h.idRLStates
}
func b7Read(t *testing.T, m *ebpf.Map, key []byte) []byte {
	t.Helper()
	v := make([]byte, m.ValueSize())
	if e := m.Lookup(key, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func b7Freeze(t *testing.T, m *ebpf.Map) {
	t.Helper()
	if e := m.Freeze(); e != nil {
		t.Fatal(e)
	}
}

func readCfg(t *testing.T, m *ebpf.Map, n uint32) uint64 {
	t.Helper()
	k := make([]byte, 4)
	binary.LittleEndian.PutUint32(k, n)
	return binary.LittleEndian.Uint64(b7Read(t, m, k))
}
