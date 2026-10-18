//go:build linux && integration

package api

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gin-gonic/gin"
	"golang.org/x/sys/unix"
)

func nsScaleCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("NS_CELL class=apparatus pass=false error=%q", err)
	}
}

func TestNSG6Server(t *testing.T) {
	root := os.Getenv("NS_G6_ROOT")
	if root == "" {
		t.Skip("child fixture only")
	}
	cpus, err := ebpf.PossibleCPU()
	nsScaleCheck(t, err)
	now, err := hitsClock()
	nsScaleCheck(t, err)
	h := &Handlers{idCounts: nsRealMap(t, 1000000), logicalOwners: map[uint32]string{}}
	hot := nsHotMap(t)
	h.SetHits(hot, 20)
	values := make([]LogicalRuleCounters, cpus)
	for id := uint32(1); id <= 500000; id++ {
		values[0] = LogicalRuleCounters{Match: 1, MatchBytes: 94, LastHitNS: 1}
		if id%500 == 0 {
			values[0].LastHitNS = now
		}
		nsScaleCheck(t, h.idCounts.Put(id, values))
		if id%500 == 0 || id <= 4008 {
			nsScaleCheck(t, hot.Put(id, values[0].LastHitNS))
		}
		h.logicalOwners[id] = fmt.Sprint("scale-", id)
	}
	rows, owners, recent := 0, 0, 0
	it := h.idCounts.Iterate()
	var id uint32
	var back []LogicalRuleCounters
	for it.Next(&id, &back) {
		rows++
		if h.logicalOwners[id] != "" {
			owners++
		}
		if back[0].LastHitNS == now {
			recent++
		}
	}
	nsScaleCheck(t, it.Err())
	if rows != 500000 || owners != rows || recent != 1000 {
		t.Fatal("NS_CELL class=apparatus pass=false seed_readback", rows, owners, recent)
	}
	hotRows := 0
	hotIt := hot.Iterate()
	var hotTime uint64
	for hotIt.Next(&id, &hotTime) {
		hotRows++
	}
	nsScaleCheck(t, hotIt.Err())
	if hotRows != 5000 {
		t.Fatal("NS_CELL class=apparatus pass=false hot_seed_readback", hotRows)
	}
	// The real gate forwards S while this child serves the real Hits handler.
	spec, err := ebpf.LoadCollectionSpec(os.Getenv("XDROP_GATE_ELF"))
	nsScaleCheck(t, err)
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	gate, err := ebpf.NewCollection(spec)
	nsScaleCheck(t, err)
	defer gate.Close()
	w, err := net.InterfaceByName("w0")
	nsScaleCheck(t, err)
	l, err := net.InterfaceByName("l0")
	nsScaleCheck(t, err)
	for _, name := range []string{"config_a", "config_b"} {
		nsScaleCheck(t, gate.Maps[name].Put(uint32(4), uint64(1)))
		nsScaleCheck(t, gate.Maps[name].Put(uint32(5), uint64(l.Index)))
	}
	nsScaleCheck(t, gate.Maps["devmap"].Put(uint32(w.Index), uint32(l.Index)))
	xdp, err := link.AttachXDP(link.XDPOptions{Program: gate.Programs["xdp_whitelist_gate"], Interface: w.Index, Flags: link.XDPGenericMode})
	nsScaleCheck(t, err)
	defer xdp.Close()
	var first, last, arrivals atomic.Int64
	router := gin.New()
	router.GET("/rules/hits", func(c *gin.Context) {
		if c.Query("phase") == "pressure" {
			now := time.Now().UnixNano()
			first.CompareAndSwap(0, now)
			for old := last.Load(); now > old && !last.CompareAndSwap(old, now); old = last.Load() {
			}
			arrivals.Add(1)
		}
		h.Hits(c)
	})
	router.GET("/arrivals", func(c *gin.Context) {
		c.JSON(200, map[string]int64{"first": first.Load(), "last": last.Load(), "count": arrivals.Load()})
	})
	server := httptest.NewServer(router)
	defer server.Close()
	ready, _ := json.Marshal(map[string]any{"url": server.URL, "since": now, "cpus": cpus, "rows": rows, "owners": owners, "recent": recent, "hot": hotRows})
	nsScaleCheck(t, os.WriteFile(filepath.Join(root, "ready.json"), ready, 0600))
	t.Logf("NS_CELL class=apparatus name=G6_seed cpus=%d rows=%d owners=%d recent=%d pass=%t", cpus, rows, owners, recent, rows == owners && recent == 1000)
	for {
		if _, err := os.Stat(filepath.Join(root, "stop")); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func nsProcess(pid int) (float64, int64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(string(b)[strings.LastIndex(string(b), ")")+1:])
	u, e := strconv.ParseFloat(fields[11], 64)
	if e != nil {
		return 0, 0, e
	}
	s, e := strconv.ParseFloat(fields[12], 64)
	if e != nil {
		return 0, 0, e
	}
	b, err = os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, 0, err
	}
	rss, err := strconv.ParseInt(strings.Fields(string(b))[1], 10, 64)
	return u + s, rss * int64(os.Getpagesize()), err
}

// Independent S socket and sequence/byte accounting; child CPU excludes sender.
func nsScaleStream(t *testing.T) func(time.Time, time.Time) {
	t.Helper()
	socket := func(name string) (int, int) {
		i, e := net.InterfaceByName(name)
		nsScaleCheck(t, e)
		fd, e := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0x0300)
		nsScaleCheck(t, e)
		nsScaleCheck(t, unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: i.Index, Protocol: 0x0300}))
		nsScaleCheck(t, unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 10000}))
		return fd, i.Index
	}
	tx, index := socket("w1")
	rx, _ := socket("l1")
	_, err := unix.GetsockoptTpacketStats(rx, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	nsScaleCheck(t, err)
	packet := make([]byte, 94)
	copy(packet[:12], []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
	packet[12], packet[13], packet[14], packet[23] = 8, 0, 0x45, 17
	copy(packet[26:34], []byte{10, 1, 0, 1, 10, 2, 0, 1})
	copy(packet[50:], []byte("NS-S-STREAM"))
	var sent []time.Time
	got := map[uint32]time.Time{}
	sendErrors, receiveErrors, bad, duplicates := 0, 0, 0, 0
	maxSend, maxReceive := time.Duration(0), time.Duration(0)
	stopTX, stopRX, doneTX, doneRX := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	start := time.Now()
	rxReady := make(chan struct{})
	go func() {
		defer close(doneTX)
		<-rxReady
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		previous := time.Now()
		for seq := uint32(0); ; seq++ {
			p := bytes.Clone(packet)
			binary.BigEndian.PutUint32(p[90:], seq)
			now := time.Now()
			maxSend = max(maxSend, now.Sub(previous))
			previous = now
			if err := unix.Sendto(tx, p, 0, &unix.SockaddrLinklayer{Ifindex: index}); err != nil {
				sendErrors++
			}
			sent = append(sent, now)
			select {
			case <-stopTX:
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		defer close(doneRX)
		close(rxReady)
		buf := make([]byte, 2048)
		previous := time.Now()
		for {
			now := time.Now()
			maxReceive = max(maxReceive, now.Sub(previous))
			previous = now
			select {
			case <-stopRX:
				return
			default:
			}
			n, from, e := unix.Recvfrom(rx, buf, 0)
			if e == unix.EAGAIN || e == unix.EINTR {
				continue
			}
			if e != nil {
				receiveErrors++
				continue
			}
			addr, ok := from.(*unix.SockaddrLinklayer)
			if !ok || addr.Pkttype == unix.PACKET_OUTGOING || n < 60 || !bytes.Equal(buf[50:60], packet[50:60]) {
				continue
			}
			if n != len(packet) || !bytes.Equal(buf[:90], packet[:90]) {
				bad++
				continue
			}
			seq := binary.BigEndian.Uint32(buf[90:])
			if _, exists := got[seq]; exists {
				duplicates++
			}
			got[seq] = time.Now()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	return func(begin, end time.Time) {
		time.Sleep(time.Until(end.Add(3100 * time.Millisecond)))
		close(stopTX)
		<-doneTX
		time.Sleep(time.Second)
		close(stopRX)
		<-doneRX
		stats, e := unix.GetsockoptTpacketStats(rx, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		nsScaleCheck(t, e)
		unix.Close(tx)
		unix.Close(rx)
		window, pre, post, known := 0, 0, 0, 0
		for i, at := range sent {
			if !at.Before(begin) && !at.After(end) {
				window++
			}
			if _, ok := got[uint32(i)]; ok {
				known++
				if at.Before(begin) {
					pre++
				}
				if at.After(end.Add(2 * time.Second)) {
					post++
				}
			}
		}
		pps := float64(window) / end.Sub(begin).Seconds()
		tail := sent[len(sent)-1].Sub(end)
		valid := tail >= 2*time.Second && start.Before(begin) && pre > 0 && post > 0 && sendErrors == 0 && receiveErrors == 0 && bad == 0 && duplicates == 0 && stats.Drops == 0 && maxSend <= 100*time.Millisecond && maxReceive <= 100*time.Millisecond && pps >= 500
		pass := valid && len(sent) == len(got) && known == len(sent)
		t.Logf("NS_CELL class=behavior name=S sent=%d received=%d lost=%d send_errors=%d receive_errors=%d invalid=%d duplicates=%d tp_drops=%d max_send_gap_ms=%.3f max_receive_gap_ms=%.3f window_pps=%.3f pre=%d post=%d tail_ms=%.3f valid=%t pass=%t", len(sent), len(got), len(sent)-len(got), sendErrors, receiveErrors, bad, duplicates, stats.Drops, float64(maxSend)/1e6, float64(maxReceive)/1e6, pps, pre, post, float64(tail)/1e6, valid, pass)
		if !pass {
			t.Error("S forwarding or validity failed")
		}
	}
}

func TestNSG6(t *testing.T) {
	host := os.Getenv("NS_HOST_NETNS")
	own, err := os.Readlink("/proc/self/ns/net")
	nsScaleCheck(t, err)
	if host == "" || host == own {
		t.Fatal("NS_CELL class=apparatus pass=false reason=private_netns_required")
	}
	root := t.TempDir()
	logPath := filepath.Join(root, "agent.log")
	output, err := os.Create(logPath)
	nsScaleCheck(t, err)
	defer output.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestNSG6Server$", "-test.v", "-test.timeout=30m")
	child.Env = append(os.Environ(), "NS_G6_ROOT="+root)
	child.Stdout, child.Stderr = output, output
	nsScaleCheck(t, child.Start())
	defer func() {
		os.WriteFile(filepath.Join(root, "stop"), nil, 0600)
		child.Wait()
		b, _ := os.ReadFile(logPath)
		t.Logf("NS_G6_AGENT_LOG\n%s", b)
	}()
	var ready struct {
		URL                             string
		Since                           uint64
		CPUs, Rows, Owners, Recent, Hot int
	}
	deadline := time.Now().Add(5 * time.Minute)
	for {
		b, e := os.ReadFile(filepath.Join(root, "ready.json"))
		if e == nil {
			nsScaleCheck(t, json.Unmarshal(b, &ready))
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("NS_CELL class=apparatus pass=false ready_timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ready.Rows != 500000 || ready.Owners != 500000 || ready.Recent != 1000 || ready.Hot != 5000 {
		t.Fatal("seed proof", ready)
	}
	clockBytes, err := exec.Command("getconf", "CLK_TCK").Output()
	nsScaleCheck(t, err)
	ticks, err := strconv.ParseFloat(strings.TrimSpace(string(clockBytes)), 64)
	nsScaleCheck(t, err)
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	call := func(since uint64, phase string) int {
		r, e := client.Get(fmt.Sprintf("%s/rules/hits?since_ns=%d&phase=%s", ready.URL, since, phase))
		if e != nil {
			return 0
		}
		defer r.Body.Close()
		if r.StatusCode == 429 {
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) == nil && body["error"] == "rate_limited" {
				return 429
			}
			return 0
		}
		var result HitsResponse
		e = json.NewDecoder(r.Body).Decode(&result)
		if e != nil || r.StatusCode != 200 || result.Scanned != ready.Hot || result.Truncated || len(result.Hits) != 1000 {
			return 0
		}
		seen := map[uint32]bool{}
		for _, hit := range result.Hits {
			if hit.LogicalID%500 != 0 || hit.LogicalID < 500 || hit.LogicalID > 500000 || seen[hit.LogicalID] {
				return 0
			}
			seen[hit.LogicalID] = true
		}
		return 200
	}
	scans := func() [][]string {
		b, e := os.ReadFile(logPath)
		nsScaleCheck(t, e)
		return regexp.MustCompile("hits_scan rows=([0-9]+) dur_ms=([0-9.]+) truncated=(true|false)").FindAllStringSubmatch(string(b), -1)
	}
	for i := 0; i < 2; i++ {
		before := len(scans())
		code := call(ready.Since, "coverage")
		rows := scans()
		pass := code == 200 && len(rows) == before+1
		if pass {
			n, _ := strconv.Atoi(rows[len(rows)-1][1])
			pass = n == ready.Hot && n <= 16384
		}
		t.Logf("NS_CELL class=behavior name=coverage cold=%d status=%d scans=%d hot_rows=%d id_rows=%d pass=%t", i, code, len(rows)-before, ready.Hot, ready.Rows, pass)
		if !pass {
			t.Fatal("coverage or independent execution")
		}
		time.Sleep(2100 * time.Millisecond)
	}
	for _, phase := range []string{"normal", "pressure"} {
		stopS := nsScaleStream(t)
		time.Sleep(2100 * time.Millisecond)
		beforeScans := len(scans())
		cpu0, rss0, e := nsProcess(child.Process.Pid)
		nsScaleCheck(t, e)
		begin := time.Now()
		var sent, success, limited atomic.Int64
		if phase == "normal" {
			for i := 0; i < 120; i++ {
				at := begin.Add(time.Duration(i) * 5 * time.Second)
				time.Sleep(time.Until(at))
				sent.Add(1)
				if call(ready.Since, phase) == 200 {
					success.Add(1)
				}
			}
			time.Sleep(time.Until(begin.Add(10 * time.Minute)))
		} else {
			var wg sync.WaitGroup
			for caller := 0; caller < 50; caller++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < 600; i++ {
						time.Sleep(time.Until(begin.Add(time.Duration(i) * 100 * time.Millisecond)))
						sent.Add(1)
						switch call(ready.Since, phase) {
						case 200:
							success.Add(1)
						case 429:
							limited.Add(1)
						}
					}
				}()
			}
			wg.Wait()
			time.Sleep(time.Until(begin.Add(time.Minute)))
		}
		end := time.Now()
		cpu1, rss1, e := nsProcess(child.Process.Pid)
		nsScaleCheck(t, e)
		n := len(scans()) - beforeScans
		cpu := (cpu1 - cpu0) / ticks / end.Sub(begin).Seconds() * 100
		pass := sent.Load() == success.Load() && cpu <= 5 && rss1-rss0 <= 50<<20
		if phase == "pressure" {
			r, err := client.Get(ready.URL + "/arrivals")
			nsScaleCheck(t, err)
			var arrival struct{ First, Last, Count int64 }
			nsScaleCheck(t, json.NewDecoder(r.Body).Decode(&arrival))
			r.Body.Close()
			span := float64(arrival.Last-arrival.First) / 1e9
			pass = sent.Load() == 30000 && arrival.Count == sent.Load() && success.Load()+limited.Load() == sent.Load() && float64(success.Load()) <= 20+20*span && float64(success.Load()) >= .95*20*span && n >= 29 && n <= 31 && cpu <= 30
			t.Logf("NS_CELL class=behavior name=pressure_arrivals first_ns=%d last_ns=%d span_s=%.6f arrived=%d http_200=%d http_429=%d pass=%t", arrival.First, arrival.Last, span, arrival.Count, success.Load(), limited.Load(), pass)
		}
		t.Logf("NS_CELL class=behavior name=%s sent=%d success=%d scans=%d cpu_percent=%.3f rss_growth=%d duration_s=%.3f pass=%t", phase, sent.Load(), success.Load(), n, cpu, rss1-rss0, end.Sub(begin).Seconds(), pass)
		if !pass {
			t.Error("scale threshold")
		}
		for _, scan := range scans()[beforeScans:] {
			rows, _ := strconv.Atoi(scan[1])
			dur, _ := strconv.ParseFloat(scan[2], 64)
			if rows != ready.Hot || rows > 16384 || dur > 2000 {
				t.Errorf("NS_CELL class=behavior name=scan_bound rows=%d dur_ms=%f pass=false", rows, dur)
			}
		}
		stopS(begin, end)
	}
}
