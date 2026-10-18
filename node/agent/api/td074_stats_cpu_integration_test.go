//go:build linux && integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
	"golang.org/x/sys/unix"
)

func td074APIGet(t *testing.T, r *gin.Engine) CPUStatsResponse {
	t.Helper()
	w := jiaCall(t, r, "GET", "/api/v1/stats/cpu", "")
	if w.Code != 200 {
		t.Fatalf("TD074_CPU status=%d body=%s", w.Code, w.Body)
	}
	var got CPUStatsResponse
	if e := json.Unmarshal(w.Body.Bytes(), &got); e != nil {
		t.Fatal(e)
	}
	return got
}
func td074CPUValues(v CPUStats) [5]uint64 {
	return [5]uint64{v.TotalPackets, v.DroppedPackets, v.PassedPackets, v.WhitelistedPackets, v.RateLimitedPackets}
}
func TestTD074CPUStatsELF(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("TD074_PRECONDITION root required")
	}
	self, e := os.Readlink("/proc/self/ns/time")
	if e != nil {
		t.Fatal(e)
	}
	init, e := os.Readlink("/proc/1/ns/time")
	if e != nil || self != init {
		t.Fatalf("TD074_PRECONDITION initial time namespace required: %s/%s %v", self, init, e)
	}
	n, e := ebpf.PossibleCPU()
	if e != nil || n < 2 {
		t.Fatalf("TD074_PRECONDITION possible CPUs >=2 required: %d %v", n, e)
	}
	spec, e := ebpf.LoadCollectionSpec(os.Getenv("XDROP_BPF_ELF"))
	if e != nil {
		t.Fatal(e)
	}
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			t.Fatalf("unexpected pinning %s", name)
		}
	}
	c, e := ebpf.NewCollection(spec)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	h, r := jiaHandler(t)
	h.stats = c.Maps["stats"]
	h.configA = c.Maps["config_a"]
	h.configB = c.Maps["config_b"]
	h.activeConfig = c.Maps["active_config"]
	r.GET("/api/v1/stats/cpu", h.GetCPUStats)
	online, possible := 8, n
	snapshot := ratelimit.Snapshot{Divisor: 8, Source: "auto", OnlineCPUs: &online, PossibleCPUs: &possible}
	h.SetRateLimitSnapshot(snapshot)
	h.lastStats = [6]uint64{101, 102, 103, 104, 105}
	h.lastStatsTime = 7400
	baseline, lastTime := h.lastStats, h.lastStatsTime
	before := td074APIGet(t, r)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var available, one unix.CPUSet
	if e := unix.SchedGetaffinity(0, &available); e != nil {
		t.Fatal(e)
	}
	k := -1
	for i := 0; i < n && i < 1024; i++ {
		if available.IsSet(i) {
			k = i
			break
		}
	}
	if k < 0 {
		t.Fatal("no available CPU")
	}
	one.Set(k)
	if e := unix.SchedSetaffinity(0, &one); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := unix.SchedSetaffinity(0, &available); e != nil {
			t.Error(e)
		}
	}()
	packet := b7Packet()
	packet[46] = 0x50
	for i := 0; i < 3; i++ {
		got, e := c.Programs["xdp_firewall_main"].Run(&ebpf.RunOptions{Data: packet, Repeat: 1})
		if e != nil || got != 2 {
			t.Fatalf("TD074_CPU packet verdict=%d err=%v", got, e)
		}
	}
	// No sender remains active from here onward.
	after := td074APIGet(t, r)
	if len(before.PerCPU) != n || len(after.PerCPU) != n {
		t.Fatalf("TD074_CPU length before=%d after=%d want=%d", len(before.PerCPU), len(after.PerCPU), n)
	}
	var sums [5]uint64
	for cpu, row := range after.PerCPU {
		if row.CPU != cpu {
			t.Fatalf("TD074_CPU index=%d value.cpu=%d", cpu, row.CPU)
		}
		old, cur := td074CPUValues(before.PerCPU[cpu]), td074CPUValues(row)
		var delta [5]uint64
		for i := range delta {
			delta[i] = cur[i] - old[i]
			sums[i] += cur[i]
		}
		want := [5]uint64{}
		if cpu == k {
			// Phase 8 counts total only in xdp_whitelist_gate. These packets
			// run xdp_firewall_main directly, so only passed increases.
			want = [5]uint64{0, 0, 3, 0, 0}
		}
		if delta != want {
			t.Fatalf("TD074_CPU delta cpu=%d pinned=%d got=%v want=%v", cpu, k, delta, want)
		}
	}
	if !reflect.DeepEqual(after.RateLimit, snapshot) {
		t.Fatalf("TD074_CPU startup snapshot got=%+v want=%+v", after.RateLimit, snapshot)
	}
	if h.lastStats != baseline || h.lastStatsTime != lastTime {
		t.Fatalf("TD074_CPU PPS baseline changed got=%v/%d want=%v/%d", h.lastStats, h.lastStatsTime, baseline, lastTime)
	}
	oldResponse := jiaCall(t, r, "GET", "/api/v1/stats", "")
	var sum Stats
	if oldResponse.Code != 200 {
		t.Fatal(oldResponse.Body.String())
	}
	if e := json.Unmarshal(oldResponse.Body.Bytes(), &sum); e != nil {
		t.Fatal(e)
	}
	if got := ([5]uint64{sum.TotalPackets, sum.DroppedPackets, sum.PassedPackets, sum.WhitelistedPackets, sum.RateLimitedPackets}); got != sums {
		t.Fatalf("TD074_CPU sum=%v /stats=%v", sums, got)
	}
	t.Logf("TD074_CPU possible=%d pinned=%d per_cpu_delta=0/0/3/0/0 sum_equal=1 pps_unchanged=1", n, k)
	// Separately exercise nonzero total-to-CPU mapping after the packet trial.
	// Read-modify-write the per-CPU slot, preserving every CPU except k.
	const totalIncrement uint64 = 7
	var totals []uint64
	if e := h.stats.Lookup(uint32(0), &totals); e != nil {
		t.Fatal(e)
	}
	if len(totals) != n {
		t.Fatalf("TD074_CPU total slot length=%d want=%d", len(totals), n)
	}
	totals[k] += totalIncrement
	if e := h.stats.Update(uint32(0), totals, ebpf.UpdateAny); e != nil {
		t.Fatal(e)
	}
	ppsBefore, ppsTimeBefore := h.lastStats, h.lastStatsTime
	injected := td074APIGet(t, r)
	if len(injected.PerCPU) != n {
		t.Fatalf("TD074_CPU injected length=%d want=%d", len(injected.PerCPU), n)
	}
	for cpu, row := range injected.PerCPU {
		if row.CPU != cpu {
			t.Fatalf("TD074_CPU injected index=%d value.cpu=%d", cpu, row.CPU)
		}
		old, cur := td074CPUValues(after.PerCPU[cpu]), td074CPUValues(row)
		var delta [5]uint64
		for i := range delta {
			delta[i] = cur[i] - old[i]
		}
		want := [5]uint64{}
		if cpu == k {
			want[0] = totalIncrement
		}
		if delta != want {
			t.Fatalf("TD074_CPU injected-total delta cpu=%d pinned=%d got=%v want=%v", cpu, k, delta, want)
		}
	}
	if h.lastStats != ppsBefore || h.lastStatsTime != ppsTimeBefore {
		t.Fatal("TD074_CPU injected-total read changed PPS baseline")
	}
	t.Logf("TD074_CPU injected_total=%d pinned=%d other_cpu_delta=0 other_slots_delta=0 pps_unchanged=1", totalIncrement, k)
	// Poison both slots and flip the kernel selector without touching activeSlot.
	cache := h.activeSlot
	for _, m := range []struct {
		m     *ebpf.Map
		value uint64
	}{{h.configA, 7}, {h.configB, 9}} {
		if e := m.m.Put(uint32(ConfigRLCPUDivisor), m.value); e != nil {
			t.Fatal(e)
		}
	}
	for _, tc := range []struct{ slot, want uint64 }{{1, 9}, {0, 7}} {
		if e := h.activeConfig.Put(uint32(0), tc.slot); e != nil {
			t.Fatal(e)
		}
		got := td074APIGet(t, r)
		if got.DivisorInMap == nil || *got.DivisorInMap != tc.want || got.DivisorInMapError != "" || h.activeSlot != cache {
			var raw any
			if got.DivisorInMap != nil {
				raw = *got.DivisorInMap
			}
			t.Fatalf("TD074_CPU poison selector=%d got=%v error=%q want=%d cache=%d/%d", tc.slot, raw, got.DivisorInMapError, tc.want, h.activeSlot, cache)
		}
	}
	if e := h.configA.Put(uint32(ConfigRLCPUDivisor), uint64(0)); e != nil {
		t.Fatal(e)
	}
	if got := td074APIGet(t, r); got.DivisorInMap == nil || *got.DivisorInMap != 0 {
		t.Fatalf("TD074_CPU raw-zero got=%v", got.DivisorInMap)
	}
	t.Log("TD074_CPU poison=b:9/a:7/zero:0 cache_unchanged=1")
	// Selector/config failures are distinct from a successful raw zero read.
	for _, which := range []string{"selector", "config"} {
		old := h.activeConfig
		if which == "config" {
			old = h.configA
		}
		closed, e := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 12})
		if e != nil {
			t.Fatal(e)
		}
		closed.Close()
		if which == "selector" {
			h.activeConfig = closed
		} else {
			h.configA = closed
		}
		got := td074APIGet(t, r)
		if got.DivisorInMap != nil || got.DivisorInMapError == "" {
			t.Fatalf("TD074_CPU %s read failure disguised as zero: %+v", which, got)
		}
		if which == "selector" {
			h.activeConfig = old
		} else {
			h.configA = old
		}
	}
	// Every statistics slot must be required; the failing key varies 1..4.
	for entries := uint32(1); entries < 5; entries++ {
		small, e := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: entries})
		if e != nil {
			t.Fatal(e)
		}
		h.stats = small
		w := jiaCall(t, r, "GET", "/api/v1/stats/cpu", "")
		small.Close()
		var body map[string]json.RawMessage
		if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
			t.Fatal(e)
		}
		if w.Code != 500 || body["per_cpu"] != nil || string(body["code"]) != `"stats_read_failed"` || len(body["error"]) == 0 {
			t.Fatalf("TD074_CPU stats failure entries=%d status=%d body=%s", entries, w.Code, w.Body)
		}
	}
	t.Log("TD074_CPU error_slots=4 selector_error=1 config_error=1 partial_output=0")
}

func TestTD074CPUStatsAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handlers{}
	protected := r.Group("/api/v1")
	protected.Use(AuthMiddleware("td074-test-only-key"))
	protected.GET("/stats/cpu", h.GetCPUStats)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/stats/cpu", nil))
	if w.Code < 400 || !strings.Contains(w.Body.String(), "error") {
		t.Fatalf("TD074_CPU missing authentication accepted status=%d body=%s", w.Code, w.Body)
	}
}
