package api

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Execute the complete production GetStats text with a fake map on macOS.
// The public Stats type is imported unchanged; no production lookup seam is added.
func TestTD149Stats(t *testing.T) {
	raw, err := os.ReadFile("stats.go")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(raw), "package api", "package main", 1)
	source = strings.Replace(source, "import (", `import (
 "encoding/json"
 "net/http/httptest"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 api "github.com/littlewolf9527/xdrop/node/agent/api"
`, 1)
	source += `
type Stats = api.Stats
type fakeMap struct { reads9 int }
func (m *fakeMap) Lookup(key, out interface{}) error {
 k, ok := key.(uint32); if !ok { k = binary.LittleEndian.Uint32(key.([]byte)) }
 values := []uint64{0,0}; if k == 9 { m.reads9++; values = []uint64{17,25} }
 *out.(*[]uint64) = values; return nil
}
type Handlers struct {
 stats, tailcallFailStats, condRowMissing *fakeMap
 lastStats [6]uint64; lastStatsTime int64; statsMu sync.Mutex
 sysStatsCache *api.SystemStatsCache; xdpInfo *api.XDPInfo
 publishedCapacity atomic.Pointer[api.CapacityReport]
}
func (*Handlers) getAgentState() api.AgentState { return api.AgentState{} }
func getSystemStats(*api.SystemStatsCache) api.SystemStats { return api.SystemStats{} }
func TestExtractedGetStats(t *testing.T) {
 h := &Handlers{stats: &fakeMap{}}
 w := httptest.NewRecorder(); c,_ := gin.CreateTestContext(w); h.GetStats(c)
 var body map[string]json.RawMessage
 if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil { t.Fatal(err) }
 if w.Code != 200 || h.stats.reads9 != 1 || string(body["ipv6_deep_chain_dropped"]) != "42" { t.Fatalf("slot9=%d body=%s",h.stats.reads9,w.Body) }
 if !strings.Contains(w.Body.String(), "\"mapped_v6_dropped\":0,\"ipv6_deep_chain_dropped\":42,\"cond_row_missing\":0") { t.Fatal("JSON field order") }
 t.Log("TD149_STATS slot9_reads=1 cpu_values=17,25 json=42 position=after_mapped_v6_dropped")
}
`
	path := filepath.Join(t.TempDir(), "stats_test.go")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "test", "-count=1", "-v", path)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}
