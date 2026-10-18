//go:build linux && integration

package api

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
)

func TestAFE8PositiveELF(t *testing.T) {
	h, router := jiaHandler(t)
	for i, pair := range [][2]string{{"::192.0.2.1", ""}, {"0.0.0.0", "2001:db8::1"}, {"::", "192.0.2.1"}, {"192.0.2.1", "198.51.100.1"}, {"2001:db8::1", "2001:db8::2"}, {"192.0.2.1", "::"}, {"2001:db8::1", "0.0.0.0"}} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			entry := WhitelistEntry{ID: "w", SrcIP: pair[0], DstIP: pair[1], Protocol: "tcp"}
			w := cut53Request(t, router, "POST", "/api/v1/sync/whitelist", map[string]any{"entries": []WhitelistEntry{entry}})
			if w.Code != 200 || len(h.wlEntries) != 1 {
				t.Fatalf("AF whitelist positive: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAFE12(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "af_stats", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 6})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	n, err := ebpf.PossibleCPU()
	if err != nil || n < 1 {
		t.Fatalf("AF possible CPU: %d %v", n, err)
	}
	values := make([]uint64, n)
	values[0] = 37
	if err = m.Put(uint32(5), values); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{stats: m, sysStatsCache: &SystemStatsCache{}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/stats", h.GetStats)
	w := jiaCall(t, router, "GET", "/stats", "")
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(w.Body.Bytes(), &raw); err != nil || w.Code != 200 || string(raw["mapped_v6_dropped"]) != "37" {
		t.Fatalf("AF slot5 wiring: %d %s %v", w.Code, w.Body.String(), err)
	}
	cut53P3Golden(t, "stats_slot5_p11", t.Name(), w)
	t.Log("AF_STATS map_entries=6 slot=5 preset=37 json=37")
}
