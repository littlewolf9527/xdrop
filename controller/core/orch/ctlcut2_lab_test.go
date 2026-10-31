package orch

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/condexpr"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

var labIDs = []string{"L-env", "L-boot", "L-B1", "L-B5", "L-B6", "L-B8", "L-A1", "L-A3", "L-A7", "L-E3-pc", "L-E3", "L-R3", "L-oob", "L-E6", "L-A4-table", "L-A4-cap", "L-S1", "L-S2", "L-S4", "L-ver", "L-E10", "L-2node", "L-scale"}

type labRecord struct {
	Route, Code, Table string
	Status             int
	Start, End         time.Time
}
type labFault struct {
	Status    int
	Body      string
	Drop      bool
	Delay     time.Duration
	Blackhole bool
}
type labHarness struct {
	t             *testing.T
	mu            sync.Mutex
	agent         *exec.Cmd
	agentLog      *os.File
	agentDone     chan error
	server        *http.Server
	listener      net.Listener
	base          string
	key           nc.Key
	direct        *nc.Client
	records       []labRecord
	counts        map[string]int
	fault         func(string, int, []byte) labFault
	m             *Manager
	s             *rules.Service
	db            *store.DB
	options       Options
	readStarted   time.Time
	readPinned    time.Time
	readDone      time.Time
	readDurations []time.Duration
}

func TestCtlCut2Lab(t *testing.T) {
	for _, id := range labIDs {
		id := id
		t.Run(id, func(t *testing.T) {
			if os.Getenv("XDROP_CTLCUT2_LAB") == "" {
				t.Skip("requires owned lab namespaces and native agent")
			}
			if id == "L-env" {
				labEnvelope(t)
				return
			}
			h := newLab(t)
			runLabScene(t, h, id)
		})
	}
}
func labEnvelope(t *testing.T) {
	b, e := os.ReadFile(os.Getenv("XDROP_CTLCUT2_ENVELOPE"))
	need(t, e == nil, e)
	var report struct {
		Before, After                      map[string]any
		DevDifferent, FSTypeBPF, SameMount bool
		SecretMatches                      int
		LogsChecked                        int
	}
	need(t, json.Unmarshal(b, &report) == nil, "envelope JSON")
	need(t, len(report.Before) > 0 && reflect.DeepEqual(report.Before, report.After), "host envelope changed")
	need(t, report.DevDifferent && report.FSTypeBPF && report.SameMount && report.SecretMatches == 0 && report.LogsChecked > 0, "namespace or secret witness", report)
}
func labWait(t *testing.T, limit time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("lab convergence deadline", limit)
}
func newLab(t *testing.T) *labHarness {
	t.Helper()
	key, e := os.ReadFile(os.Getenv("XDROP_CTLCUT2_KEY_FILE"))
	need(t, e == nil && len(key) > 0, "key file")
	direct, e := nc.New(NodeSpec{Name: "direct", BaseURL: os.Getenv("XDROP_CTLCUT2_AGENT_URL"), Key: nc.Secret(string(key))}, nc.Options{Timeouts: map[nc.Route]time.Duration{nc.CommitRoute: 10 * time.Minute}})
	need(t, e == nil, e)
	h := &labHarness{t: t, key: nc.Secret(string(key)), direct: direct, counts: map[string]int{}}
	t.Cleanup(h.close)
	h.startAgent()
	u, e := url.Parse(os.Getenv("XDROP_CTLCUT2_AGENT_URL"))
	need(t, e == nil, e)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) { w.WriteHeader(502) }
	h.listener, e = net.Listen("tcp", "10.77.0.1:0")
	need(t, e == nil, e)
	h.base = "http://" + h.listener.Addr().String()
	h.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record := labRecord{Route: r.URL.Path, Start: time.Now()}
		recorded := false
		defer func() {
			if recorded {
				return
			}
			if record.End.IsZero() {
				record.End = time.Now()
			}
			h.mu.Lock()
			h.records = append(h.records, record)
			h.mu.Unlock()
		}()
		if strings.HasPrefix(r.URL.Path, "/blackhole/") {
			record.Code = "blackhole"
			<-r.Context().Done()
			return
		}
		var body []byte
		if r.URL.Path == string(nc.CommitRoute) {
			body, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		h.mu.Lock()
		h.counts[r.URL.Path]++
		n := h.counts[r.URL.Path]
		script := h.fault
		h.mu.Unlock()
		f := labFault{}
		if script != nil {
			f = script(r.URL.Path, n, body)
		}
		if f.Blackhole {
			record.Code = "blackhole"
			<-r.Context().Done()
			return
		}
		rec := httptest.NewRecorder()
		if f.Status != 0 {
			rec.WriteHeader(f.Status)
			io.WriteString(rec, f.Body)
		} else {
			proxy.ServeHTTP(rec, r)
		}
		record.End = time.Now()
		record.Status = rec.Code
		var obj map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &obj)
		record.Code, _ = obj["code"].(string)
		if groups, ok := obj["groups"].([]any); ok && len(groups) > 0 {
			if group, ok := groups[0].(map[string]any); ok {
				record.Table, _ = group["table"].(string)
			}
		}
		h.mu.Lock()
		h.records = append(h.records, record)
		h.mu.Unlock()
		recorded = true
		if f.Drop {
			if hj, ok := w.(http.Hijacker); ok {
				conn, _, e := hj.Hijack()
				if e == nil {
					conn.Close()
				}
			}
			return
		}
		if f.Delay > 0 {
			time.Sleep(f.Delay)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})}
	go h.server.Serve(h.listener)
	h.db, e = store.Open(filepath.Join(t.TempDir(), "lab.db"))
	need(t, e == nil, e)
	h.options = Options{Client: nc.Options{Timeouts: map[nc.Route]time.Duration{nc.CommitRoute: 30 * time.Second}}, ReconcileInterval: time.Hour, CheckInterval: time.Second, RetryBase: 100 * time.Millisecond}
	h.makeManager()
	rules.SnapshotTestHook = func(s *rules.Service, kind string) error {
		if s == h.s {
			h.mu.Lock()
			defer h.mu.Unlock()
			if kind == "enabled" {
				h.readStarted = time.Now()
			}
			if kind == "enabled_done" {
				h.readDone = time.Now()
				h.readDurations = append(h.readDurations, time.Since(h.readStarted))
			}
			if kind == "enabled_pinned" {
				h.readPinned = time.Now()
			}
		}
		return nil
	}
	return h
}
func (h *labHarness) makeManager() {
	h.m = New([]NodeSpec{{Name: "a", BaseURL: h.base, Key: h.key}, {Name: "b", BaseURL: h.base + "/blackhole", Key: h.key}}, h.options)
	h.s = rules.New(h.db, h.m)
}
func (h *labHarness) startAgent() {
	log, e := os.CreateTemp(os.Getenv("XDROP_CTLCUT2_LOG_DIR"), "agent-*.log")
	need(h.t, e == nil, e)
	h.agentLog = log
	h.agent = exec.Command(os.Getenv("XDROP_CTLCUT2_AGENT"), "-config", os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"))
	h.agent.Stdout = log
	h.agent.Stderr = log
	need(h.t, h.agent.Start() == nil, "agent start")
	h.agentDone = make(chan error, 1)
	go func() { h.agentDone <- h.agent.Wait() }()
	self, e := os.Readlink("/proc/self/ns/mnt")
	need(h.t, e == nil, e)
	agent, e := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", h.agent.Process.Pid))
	need(h.t, e == nil && self == agent, "agent mount namespace differs")
	need(h.t, os.WriteFile(filepath.Join(os.Getenv("XDROP_CTLCUT2_LOG_DIR"), "mount-equal"), []byte("1\n"), 0600) == nil, "mount witness")
	labWait(h.t, 180*time.Second, func() bool { _, e := h.direct.Health(context.Background()); return e == nil })
}
func (h *labHarness) stopAgent() {
	if h.agent == nil {
		return
	}
	_ = h.agent.Process.Signal(syscall.SIGTERM)
	select {
	case <-h.agentDone:
	case <-time.After(15 * time.Second):
		_ = h.agent.Process.Kill()
		<-h.agentDone
	}
	h.agentLog.Close()
	h.agent = nil
}
func (h *labHarness) close() {
	if h.m != nil {
		h.m.Stop()
	}
	rules.SnapshotTestHook = nil
	if h.server != nil {
		_ = h.server.Close()
	}
	h.stopAgent()
	if h.db != nil {
		h.db.Close()
	}
	h.mu.Lock()
	records := append([]labRecord{}, h.records...)
	h.mu.Unlock()
	b, _ := json.Marshal(records)
	_ = os.WriteFile(filepath.Join(os.Getenv("XDROP_CTLCUT2_LOG_DIR"), strings.ReplaceAll(h.t.Name(), "/", "-")+"-requests.json"), b, 0600)
}
func (h *labHarness) start() { h.m.Start(h.s); h.normal() }
func (h *labHarness) normal() {
	labWait(h.t, 4*time.Minute, func() bool {
		s := h.m.Status()[0]
		return s.Online && s.Rules.State == "normal" && s.Whitelist.State == "normal"
	})
}
func (h *labHarness) list() []nc.ReadRule {
	rows := []nc.ReadRule{}
	pages := 1
	total := -1
	for page := 1; page <= pages; page++ {
		r, e := h.direct.Rules(context.Background(), page, 1000)
		need(h.t, e == nil, e)
		if page == 1 {
			pages = r.Pagination.Pages
			total = r.Pagination.Total
		}
		need(h.t, r.Pagination.Total == total, "lab pagination changed")
		rows = append(rows, r.Rules...)
	}
	need(h.t, len(rows) == total, "lab read count")
	return rows
}
func (h *labHarness) equal(excludedIDs ...string) {
	h.normal()
	before := h.m.Status()[0].RuleReconcile.LastAt
	h.m.ReconcileNow("a")
	labWait(h.t, 30*time.Minute, func() bool {
		s := h.m.Status()[0]
		return s.RuleReconcile.LastAt.After(before) && s.WhitelistReconcile.LastAt.After(before)
	})
	s := h.m.Status()[0]
	need(h.t, s.RuleReconcile.Result == "equal" && s.WhitelistReconcile.Result == "equal", "L-A3 readback difference", s.RuleReconcile, s.WhitelistReconcile)
	difference := h.readbackDifference(excludedIDs)
	need(h.t, difference == nil, "L-A3 independent store/node comparison failed", difference)
}

// Independent lab oracle. PLAN §4-4 and node/API.md GET rules/whitelist:
// readback spells wildcard protocol "all", always includes action, canonicalizes
// IP/prefixes and may spell equivalent TCP flags differently. No other fields
// are erased; all six expressions, anomaly/rate and logical identity participate.
type labRuleValue struct {
	ID                   string
	LogicalID            int64
	Match                store.Match
	PktLenMin, PktLenMax int
}

func labCanonical(v labRuleValue) labRuleValue {
	if v.Match.Protocol == "" {
		v.Match.Protocol = "all"
	}
	if v.Match.Action == "" {
		v.Match.Action = "drop"
	}
	for _, field := range []*string{&v.Match.SrcIP, &v.Match.DstIP} {
		if ip, e := netip.ParseAddr(*field); e == nil {
			*field = ip.String()
		}
	}
	for _, field := range []*string{&v.Match.SrcCIDR, &v.Match.DstCIDR} {
		if prefix, e := netip.ParsePrefix(*field); e == nil {
			*field = prefix.Masked().String()
		}
	}
	if mask, value, _, e := condexpr.ParseTCPFlags(v.Match.TCPFlags); e == nil {
		v.Match.TCPFlags = fmt.Sprintf("%d:%d", mask, value)
	}
	return v
}
func (h *labHarness) readbackDifference(excludedIDs []string) error {
	actual := h.list()
	wl, call := h.direct.Whitelist(context.Background())
	if call != nil {
		return call
	}
	tx, e := h.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := store.List(tx)
	if e != nil {
		return e
	}
	entries, e := store.ListWhitelist(tx)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	excluded := map[string]bool{}
	for _, id := range excludedIDs {
		excluded[id] = true
	}
	want, got := map[string]labRuleValue{}, map[string]labRuleValue{}
	for _, row := range rows {
		if row.Enabled && !excluded[row.ID] {
			want[row.ID] = labCanonical(labRuleValue{ID: row.ID, LogicalID: row.LogicalID, Match: row.Match})
		}
	}
	for _, r := range actual {
		need(h.t, r.LogicalID != 0, "missing logical ID")
		if _, duplicate := got[r.ID]; duplicate {
			return fmt.Errorf("duplicate node rule %s", r.ID)
		}
		got[r.ID] = labCanonical(labRuleValue{ID: r.ID, LogicalID: int64(r.LogicalID), PktLenMin: r.PktLenMin, PktLenMax: r.PktLenMax, Match: store.Match{
			SrcIP: r.SrcIP, DstIP: r.DstIP, SrcCIDR: r.SrcCIDR, DstCIDR: r.DstCIDR, SrcPort: r.SrcPort, DstPort: r.DstPort,
			Protocol: r.Protocol, Action: r.Action, RateLimit: r.RateLimit, TCPFlags: r.TCPFlags, MatchAnomaly: r.MatchAnomaly,
			TTL: r.TTL, DSCP: r.DSCP, ICMPType: r.ICMPType, ICMPCode: r.ICMPCode, Fragment: r.Fragment, PktLen: r.PktLen}})
	}
	if len(want) != len(got) {
		return fmt.Errorf("rule count database=%d node=%d", len(want), len(got))
	}
	for id, value := range want {
		if !reflect.DeepEqual(value, got[id]) {
			return fmt.Errorf("rule %s differs: database=%+v node=%+v", id, value, got[id])
		}
	}
	wantWL, gotWL := map[string]labRuleValue{}, map[string]labRuleValue{}
	for _, r := range entries {
		wantWL[r.ID] = labCanonical(labRuleValue{ID: r.ID, Match: store.Match{SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: r.SrcPort, DstPort: r.DstPort, Protocol: r.Protocol}})
	}
	for _, r := range wl.Entries {
		if _, duplicate := gotWL[r.ID]; duplicate {
			return fmt.Errorf("duplicate node whitelist %s", r.ID)
		}
		gotWL[r.ID] = labCanonical(labRuleValue{ID: r.ID, Match: store.Match{SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: r.SrcPort, DstPort: r.DstPort, Protocol: r.Protocol}})
	}
	if !reflect.DeepEqual(wantWL, gotWL) {
		return fmt.Errorf("whitelist differs: database=%v node=%v", wantWL, gotWL)
	}
	return nil
}
func (h *labHarness) create(patch rules.RulePatch) store.Rule {
	res, e := h.s.Create(rules.Actor{Kind: rules.UI}, "", patch)
	need(h.t, e == nil && !res.Existing, e)
	return res.Rule
}
func (h *labHarness) update(id string, p rules.RulePatch) store.Rule {
	r, e := h.s.Update(rules.Actor{Kind: rules.UI}, id, p)
	need(h.t, e == nil, e)
	return r
}
func (h *labHarness) history(route nc.Route) []labRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []labRecord{}
	for _, r := range h.records {
		if route == "" || r.Route == string(route) {
			out = append(out, r)
		}
	}
	return out
}
func (h *labHarness) script(f func(string, int, []byte) labFault) {
	h.mu.Lock()
	h.fault = f
	h.mu.Unlock()
}
func (h *labHarness) commit(groups []nc.Group) {
	body, e := json.Marshal(struct {
		Groups []nc.Group `json:"groups"`
	}{groups})
	need(h.t, e == nil, e)
	start := time.Now()
	_, call := h.direct.Commit(context.Background(), body, len(groups))
	h.t.Logf("out-of-band commit groups=%d duration=%s", len(groups), time.Since(start))
	need(h.t, call == nil, call)
}
func (h *labHarness) seed(n int) {
	tx, e := h.db.Begin()
	need(h.t, e == nil, e)
	defer tx.Rollback()
	for i := 0; i < n; i++ {
		match := store.Match{SrcIP: fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255), Protocol: "tcp", Action: "drop"}
		if n == 500000 && i >= 400000 {
			j := i - 400000
			match.SrcIP = ""
			if j < 50000 {
				match.SrcCIDR = fmt.Sprintf("172.16.%d.%d/32", j/256, j%256)
				match.DstCIDR = fmt.Sprintf("192.168.%d.%d/32", j/256, j%256)
			} else {
				j -= 50000
				match.SrcCIDR = fmt.Sprintf("2001:db8:1::%x/128", j+1)
				match.DstCIDR = fmt.Sprintf("2001:db8:2::%x/128", j+1)
			}
		} else if n == 1000 {
			switch i % 4 {
			case 0:
				match.SrcIP = ""
				match.SrcCIDR = fmt.Sprintf("172.16.%d.%d/32", i/256, i%256)
			case 1:
				match.TTL = p("64")
			case 2:
				match.SrcIP = ""
				match.DstPort = i + 1
				match.Protocol = "all"
			}
		}
		c, err := rules.Canonicalize(match)
		need(h.t, err == nil, err)
		id, e := store.NextLogicalID(tx)
		need(h.t, e == nil, e)
		row := store.Rule{ID: fmt.Sprintf("rule_%032x", id), LogicalID: id, Match: c.RuleInput, Kind: c.Kind, GroupKey: c.GroupKey, CondKey: c.CondKey, Enabled: true, CreatedAt: "2026-10-11T00:00:00Z", UpdatedAt: "2026-10-11T00:00:00Z", CreatedBy: "ui", UpdatedBy: "ui"}
		need(h.t, store.InsertRule(tx, row) == nil, "seed insert")
		need(h.t, store.Claim(tx, row.ID, "ui", "", row.CreatedAt, row.ExpiresAt) == nil, "seed claim")
	}
	need(h.t, tx.Commit() == nil, "seed commit")
	report, e := rules.Prepare(h.db)
	need(h.t, e == nil && len(report.Violations) == 0, "Prepare violations", e, len(report.Violations))
}

func labPatch(ip string) rules.RulePatch {
	return rules.RulePatch{SrcIP: p(ip), Protocol: p("tcp"), Action: p("drop")}
}
func (h *labHarness) whitelist(n int) {
	for i := 0; i < n; i++ {
		_, e := h.s.CreateWhitelist(rules.Actor{Kind: rules.UI}, rules.WhitelistInput{SrcIP: fmt.Sprintf("192.168.250.%d", i+1), Protocol: "tcp"})
		need(h.t, e == nil, e)
	}
}
func (h *labHarness) row(id string) nc.ReadRule {
	for _, r := range h.list() {
		if r.ID == id {
			return r
		}
	}
	h.t.Fatal("node rule missing", id)
	return nc.ReadRule{}
}
func (h *labHarness) code(code string) int {
	n := 0
	for _, r := range h.history("") {
		if r.Code == code {
			n++
		}
	}
	return n
}
func (h *labHarness) reason(reason string) {
	labWait(h.t, 4*time.Minute, func() bool {
		for _, e := range h.m.Events() {
			if e.Reason == reason {
				return true
			}
		}
		s := h.m.Status()[0]
		return s.Rules.Reason == reason || s.Whitelist.Reason == reason
	})
}
func (h *labHarness) stats() map[string]any {
	r, e := h.direct.Stats(context.Background())
	need(h.t, e == nil, e)
	return r
}
func labNumber(v any) uint64 { n, _ := strconv.ParseUint(fmt.Sprint(v), 10, 64); return n }

type labSent struct {
	Frames     int
	Start, End time.Time
}

func (h *labHarness) send(kind string, count int, duration time.Duration, change func()) labSent {
	ready := filepath.Join(h.t.TempDir(), "ready")
	cmd := exec.Command(os.Getenv("XDROP_CTLCUT2_SENDER"), "--iface", "c2a1", "--kind", kind, "--rate", "100", "--count", strconv.Itoa(count), "--seconds", fmt.Sprint(duration.Seconds()), "--ready", ready)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	need(h.t, cmd.Start() == nil, "sender start")
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	labWait(h.t, 10*time.Second, func() bool { _, e := os.Stat(ready); return e == nil })
	if change != nil {
		change()
	}
	need(h.t, cmd.Wait() == nil, "sender failed", output.String())
	var result labSent
	need(h.t, json.Unmarshal(output.Bytes(), &result) == nil, "sender report", output.String())
	need(h.t, result.Frames > 0, "sender sent nothing")
	if count > 0 {
		need(h.t, result.Frames == count, "sender frame count")
	} else {
		need(h.t, float64(result.Frames) >= 100*duration.Seconds()*0.5, "sender below half rate")
	}
	h.t.Logf("SEND kind=%s frames=%d start=%s end=%s", kind, result.Frames, result.Start.Format(time.RFC3339Nano), result.End.Format(time.RFC3339Nano))
	return result
}
func (h *labHarness) traffic(id string) {
	patch := labPatch("10.10.2.1")
	patch.TTL = p("64")
	if id == "L-R3" {
		patch.SrcIP = nil
		patch.SrcCIDR = p("10.10.2.0/24")
		patch.TTL = nil
	}
	r := h.create(patch)
	q := h.create(rules.RulePatch{SrcIP: p("10.10.2.1"), Protocol: p("tcp"), TTL: p("63"), Enabled: p(false)})
	h.start()
	base := len(h.history(""))
	before := h.stats()
	sent := h.send("normal", 0, 8*time.Second, func() {
		switch id {
		case "L-E3-pc":
			need(h.t, h.s.ForceDelete(rules.Actor{Kind: rules.UI}, r.ID) == nil, "positive delete")
		case "L-R3":
			h.update(r.ID, rules.RulePatch{SrcCIDR: p("10.10.2.0/25")})
		default:
			h.update(r.ID, rules.RulePatch{Comment: p("still drop")})
			h.normal()
			h.update(r.ID, rules.RulePatch{TTL: p("60-70")})
			h.normal()
			need(h.t, h.s.SetEnabled(rules.Actor{Kind: rules.UI}, q.ID, true) == nil, "enable partner")
			h.normal()
			need(h.t, h.s.SetEnabled(rules.Actor{Kind: rules.UI}, q.ID, false) == nil, "disable partner")
		}
		h.normal()
	})
	after := h.stats()
	passed := labNumber(after["passed_packets"]) - labNumber(before["passed_packets"])
	if id == "L-E3-pc" {
		need(h.t, passed > 0, "positive control did not observe PASS")
	} else {
		need(h.t, passed == 0, "PASS observed", passed)
		for _, key := range []string{"total_packets", "dropped_packets"} {
			need(h.t, labNumber(after[key])-labNumber(before[key]) == uint64(sent.Frames), "packet noise or loss", key, after[key], before[key], sent.Frames)
		}
	}
	writes := []labRecord{}
	for _, v := range h.history("")[base:] {
		if v.Route == string(nc.CommitRoute) || v.Route == string(nc.AtomicRoute) {
			writes = append(writes, v)
		}
	}
	need(h.t, len(writes) > 0 && sent.Start.Before(writes[0].Start) && sent.End.After(writes[len(writes)-1].End.Add(time.Second)), "traffic window incomplete", sent, writes)
	if id == "L-R3" {
		need(h.t, len(writes) == 2 && writes[0].Code == "cidr_overlap" && writes[0].Status == 409 && writes[1].Route == string(nc.AtomicRoute) && writes[1].Status == 200, "CIDR transition sequence", writes)
	}
}
func runLabScene(t *testing.T, h *labHarness, id string) {
	switch id {
	case "L-boot", "L-A1", "L-A3", "L-2node":
		h.seed(1000)
		h.whitelist(20)
		h.start()
		health, e := h.direct.Health(context.Background())
		need(t, e == nil && health.RulesSynced && health.WhitelistSynced, "boot health", e, health)
		need(t, !h.m.Status()[1].Online, "blackhole node online")
	case "L-B1":
		a := h.create(rules.RulePatch{DstIP: p("192.168.1.1"), Protocol: p("tcp")})
		b, e := h.s.Create(rules.Actor{Kind: rules.UI}, "", rules.RulePatch{SrcIP: p("0.0.0.0"), DstIP: p("192.168.1.1"), Protocol: p("tcp")})
		need(t, e == nil && b.Existing && b.Rule.ID == a.ID, "B1 existing", e)
		h.start()
		need(t, len(h.list()) == 1, "B1 duplicate node row")
	case "L-B5":
		for i := 1; i <= 3; i++ {
			x := labPatch("10.1.1.1")
			x.TTL = p(fmt.Sprint(i))
			h.create(x)
		}
		h.start()
		var wg sync.WaitGroup
		results := make(chan bool, 8)
		for i := 4; i < 12; i++ {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				x := labPatch("10.1.1.1")
				x.TTL = p(fmt.Sprint(i))
				r, e := h.s.Create(rules.Actor{Kind: rules.UI}, "", x)
				results <- e == nil && !r.Existing
			}()
		}
		wg.Wait()
		close(results)
		accepted := 0
		for ok := range results {
			if ok {
				accepted++
			}
		}
		need(t, accepted == 1, "B5 admission", accepted)
		h.normal()
		need(t, len(h.list()) == 4 && h.code("condition_capacity") == 0, "B5 node capacity")
	case "L-B6":
		ids := []string{}
		for _, anomaly := range []int{1, 2} {
			x := labPatch("10.10.2.1")
			x.MatchAnomaly = p(anomaly)
			ids = append(ids, h.create(x).ID)
		}
		h.start()
		need(t, len(h.list()) == 2, "B6 rows")
		for i, kind := range []string{"bad_fragment", "invalid"} {
			before := labNumber(h.row(ids[i]).Stats["match_count"])
			h.send(kind, 10, 0, nil)
			after := labNumber(h.row(ids[i]).Stats["match_count"])
			need(t, after-before == 10, "B6 counter", kind, before, after)
		}
	case "L-B8":
		x := labPatch("10.1.1.1")
		x.TCPFlags = p("SYN")
		x.MatchAnomaly = p(1)
		a := h.create(x)
		x = labPatch("10.1.1.2")
		x.MatchAnomaly = p(2)
		x.Action = p("rate_limit")
		x.RateLimit = p(int64(100))
		b := h.create(x)
		h.start()
		need(t, h.row(a.ID).MatchAnomaly == 1 && h.row(a.ID).TCPFlags != "" && h.row(b.ID).RateLimit == 100, "B8 fields")
	case "L-A7":
		h.start()
		base := len(h.history(nc.CommitRoute))
		atomicBase := len(h.history(nc.AtomicRoute))
		start := time.Now()
		for i := 0; i < 50; i++ {
			h.create(labPatch(fmt.Sprintf("10.2.1.%d", i+1)))
		}
		need(t, time.Since(start) < 100*time.Millisecond, "A7 construction window")
		labWait(t, 2*time.Second, func() bool { return h.m.Status()[0].Rules.State == "normal" })
		need(t, len(h.history(nc.CommitRoute))-base == 1 && len(h.history(nc.AtomicRoute)) == atomicBase, "A7 requests")
	case "L-E3-pc", "L-E3", "L-R3":
		h.traffic(id)
	case "L-oob":
		h.start()
		c, e := rules.Canonicalize(store.Match{SrcCIDR: "10.22.1.0/24", Protocol: "tcp", Action: "drop"})
		need(t, e == nil, e)
		h.commit([]nc.Group{{Key: json.RawMessage(c.GroupKey), Rules: []nc.Rule{{ID: "oob", LogicalID: 900000, SrcCIDR: "10.22.1.0/24", Protocol: "tcp", Action: "drop"}}}})
		h.create(rules.RulePatch{SrcCIDR: p("10.22.1.0/25"), Protocol: p("tcp")})
		h.normal()
		need(t, h.code("cidr_overlap") == 1 && len(h.history(nc.AtomicRoute)) == 2, "oob fallback")
		need(t, len(h.list()) == 1, "oob remained")
	case "L-E6":
		r := h.create(labPatch("10.1.1.1"))
		h.start()
		changed := nodeRule(store.NodeRow{ID: r.ID, LogicalID: r.LogicalID, Match: r.Match})
		changed.DstPort = 80
		c, e := rules.Canonicalize(ruleMatch(changed))
		need(t, e == nil, e)
		h.commit([]nc.Group{{Key: json.RawMessage(r.GroupKey), Rules: []nc.Rule{}}, {Key: json.RawMessage(c.GroupKey), Rules: []nc.Rule{changed}}})
		h.m.ReconcileNow("a")
		h.reason("drift")
		h.normal()
		need(t, len(h.history(nc.AtomicRoute)) == 2, "E6 no correction")
	case "L-A4-table":
		labTable(t, h)
	case "L-A4-cap":
		labCapacity(t, h)
	case "L-S1":
		r := h.create(labPatch("10.1.1.1"))
		h.start()
		h.script(func(route string, n int, b []byte) labFault {
			if route == string(nc.CommitRoute) && n == 1 {
				var body struct{ Groups []nc.Group }
				need(t, json.Unmarshal(b, &body) == nil, "S1 payload")
				for i, g := range body.Groups {
					if len(g.Rules) > 0 {
						return labFault{Status: 409, Body: fmt.Sprintf(`{"code":"condition_capacity","groups":[{"index":%d,"rule_ids":[%q]}]}`, i, r.ID)}
					}
				}
			}
			return labFault{}
		})
		h.update(r.ID, rules.RulePatch{SrcIP: p("10.1.1.2")})
		h.normal()
		need(t, len(h.m.Status()[0].Rules.Rejected) == 2 && h.row(r.ID).SrcIP == "10.1.1.1", "S1 old version lost")
		h.update(r.ID, rules.RulePatch{TTL: p("64")})
		h.normal()
		need(t, len(h.m.Status()[0].Rules.Rejected) == 0, "S1 cache remained")
	case "L-S2":
		h.options.Client.Timeouts[nc.CommitRoute] = 2 * time.Second
		h.makeManager()
		h.start()
		for i, mode := range []string{"drop", "delay", "500"} {
			base := len(h.history(nc.CommitRoute))
			a := len(h.history(nc.AtomicRoute))
			mode := mode
			h.script(func(route string, n int, b []byte) labFault {
				if route == string(nc.CommitRoute) && n == base+1 {
					switch mode {
					case "drop":
						return labFault{Drop: true}
					case "delay":
						return labFault{Delay: 3 * time.Second}
					default:
						return labFault{Status: 500, Body: `{"code":"synthetic"}`}
					}
				}
				return labFault{}
			})
			h.create(labPatch(fmt.Sprintf("10.3.1.%d", i+1)))
			h.reason("outcome_unknown")
			h.normal()
			need(t, len(h.history(nc.AtomicRoute)) == a+1, "S2 fallback", mode)
			h.equal()
		}
	case "L-S4":
		h.start()
		a := len(h.history(nc.AtomicRoute))
		base := len(h.history(nc.SyncWLRoute))
		h.script(func(route string, n int, b []byte) labFault {
			if route == string(nc.SyncWLRoute) && n == base+1 {
				return labFault{Status: 500}
			}
			return labFault{}
		})
		h.whitelist(1)
		h.reason("outcome_unknown")
		h.normal()
		need(t, len(h.history(nc.AtomicRoute)) == a, "S4 changed rules")
	case "L-ver":
		h.start()
		before := len(h.history(nc.CommitRoute)) + len(h.history(nc.AtomicRoute)) + len(h.history(nc.SyncWLRoute))
		h.script(func(route string, n int, b []byte) labFault {
			if route == "/" {
				return labFault{Status: 200, Body: `{"sync_protocol":8}`}
			}
			return labFault{}
		})
		for i := 0; i < 5; i++ {
			h.create(labPatch(fmt.Sprintf("10.4.1.%d", i+1)))
		}
		labWait(t, 5*time.Second, func() bool { return h.m.Status()[0].Incompatible })
		time.Sleep(1200 * time.Millisecond)
		need(t, len(h.history(nc.CommitRoute))+len(h.history(nc.AtomicRoute))+len(h.history(nc.SyncWLRoute)) == before, "incompatible write")
		h.script(nil)
		h.normal()
		need(t, !h.m.Status()[0].Incompatible, "version did not recover")
	case "L-E10":
		for _, size := range []int{1000, 500000} {
			if size == 500000 {
				h.m.Stop()
				h.db.Close()
				var e error
				h.db, e = store.Open(filepath.Join(t.TempDir(), "large.db"))
				need(t, e == nil, e)
				h.makeManager()
			}
			h.seed(size)
			h.start()
			labRestart(t, h, size)
			h.equal()
		}
	case "L-scale":
		labScale(t, h)
	default:
		t.Fatal("unimplemented lab scene", id)
	}
	h.equal()
	need(t, h.code("content_different") == 0, "L-A1 content_different")
}

func labTable(t *testing.T, h *labHarness) {
	h.start()
	// Main-session fixture fix: a 50,000-group out-of-band commit exceeds 10 min on the
	// node (preflight overlap check is quadratic), so fill the trie with a direct atomic.
	oob := make([]nc.Rule, 0, 50000)
	for i := 0; i < 50000; i++ {
		match := store.Match{SrcCIDR: fmt.Sprintf("172.20.%d.%d/32", i/256, i%256), Protocol: "tcp", Action: "drop"}
		c, e := rules.Canonicalize(match)
		need(t, e == nil, e)
		oob = append(oob, nodeRule(store.NodeRow{ID: fmt.Sprintf("oob_%d", i), LogicalID: int64(900000 + i), Match: c.RuleInput}))
	}
	keep, e := h.direct.Rules(context.Background(), 1, 1000)
	need(t, e == nil && keep.Pagination.Total <= 1000, "A4 live rules before fill", e)
	for _, r := range keep.Rules {
		oob = append(oob, r.Rule)
	}
	body, err := json.Marshal(struct {
		Rules []nc.Rule `json:"rules"`
	}{oob})
	need(t, err == nil, err)
	start := time.Now()
	reply, call := h.direct.Atomic(context.Background(), body)
	t.Logf("out-of-band atomic rules=%d duration=%s", len(oob), time.Since(start))
	need(t, call == nil && reply.Success && reply.Failed == 0 && reply.CIDRRules >= 50000, "A4 out-of-band fill", call, reply)
	h.create(rules.RulePatch{SrcCIDR: p("172.21.250.1/32"), Protocol: p("tcp")})
	h.reason("retry_exhausted")
	h.normal()
	need(t, h.code("table_full") == 3 && len(h.history(nc.AtomicRoute)) == 2 && len(h.list()) == 1, "A4 table response sequence")
	for _, record := range h.history(nc.CommitRoute) {
		need(t, record.Status == 409 && record.Code == "table_full" && record.Table == "sv4_cidr_trie", "A4 true trie capacity witness", record)
	}
}
func labCapacity(t *testing.T, h *labHarness) {
	var first store.Rule
	for i := 1; i <= 4; i++ {
		x := labPatch("10.1.1.1")
		x.TTL = p(fmt.Sprint(i))
		r := h.create(x)
		if i == 1 {
			first = r
		}
	}
	x := labPatch("10.1.1.1")
	x.TTL = p("5")
	x.Enabled = p(false)
	disabled := h.create(x)
	h.start()
	need(t, len(h.list()) == 4, "capacity starting rows")
	extra := first
	extra.ID = "rule_ffffffffffffffffffffffffffffffff"
	extra.TTL = p("6")
	c, e := rules.Canonicalize(extra.Match)
	need(t, e == nil, e)
	extra.Match = c.RuleInput
	extra.CondKey = c.CondKey
	tx, err := h.db.Begin()
	need(t, err == nil, err)
	extra.LogicalID, err = store.NextLogicalID(tx)
	need(t, err == nil, err)
	need(t, store.InsertRule(tx, extra) == nil, "capacity direct insert")
	need(t, tx.Commit() == nil, "capacity commit")
	need(t, h.s.SetEnabled(rules.Actor{Kind: rules.UI}, disabled.ID, false) == nil, "capacity notification")
	h.normal()
	need(t, h.code("condition_capacity") == 1 && len(h.list()) == 4, "capacity old group")
	rejected := h.m.Status()[0].Rules.Rejected
	need(t, len(rejected) > 0 && len(rejected[0].RuleIDs) > 0, "capacity rule_ids")
	h.m.ForceSync("a")
	h.reason("node_rejected_batch")
	need(t, h.code("condition_group_invalid") > 0 && h.m.Status()[0].Rules.State == "failed", "capacity atomic rejection")
	need(t, h.s.ForceDelete(rules.Actor{Kind: rules.UI}, extra.ID) == nil, "capacity cleanup")
	h.m.ForceSync("a")
	h.normal()
}
func labRestart(t *testing.T, h *labHarness, size int) {
	beforeAtomic, beforeWL := len(h.history(nc.AtomicRoute)), len(h.history(nc.SyncWLRoute))
	h.stopAgent()
	h.startAgent()
	reachable := time.Now()
	labWait(t, 4*time.Minute, func() bool {
		return len(h.history(nc.AtomicRoute)) > beforeAtomic && len(h.history(nc.SyncWLRoute)) > beforeWL
	})
	h.normal()
	health, e := h.direct.Health(context.Background())
	need(t, e == nil && health.RulesSynced && health.WhitelistSynced, "restart flags", e)
	atomic := h.history(nc.AtomicRoute)
	wl := h.history(nc.SyncWLRoute)
	need(t, len(atomic) >= 2 && len(wl) >= 2, "restart did not resync")
	limit := 7*time.Second + atomic[len(atomic)-1].End.Sub(atomic[len(atomic)-1].Start) + wl[len(wl)-1].End.Sub(wl[len(wl)-1].Start)
	need(t, time.Since(reachable) <= limit, "restart deadline", size, time.Since(reachable), limit)
	t.Logf("RESTART size=%d flags_after_health=%s bound=%s", size, time.Since(reachable), limit)
}
func percentile(d []time.Duration, pct int) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[(len(d)*pct+99)/100-1]
}
func labScale(t *testing.T, h *labHarness) {
	h.seed(500000)
	h.start()
	durations := []time.Duration{}
	confirmed := []time.Duration{}
	pending := []struct {
		at  time.Time
		gen uint64
	}{}
	r := h.create(labPatch("192.168.254.1"))
	h.normal()
	for i := 0; i < 200; i++ {
		started := time.Now()
		switch i % 4 {
		case 0:
			r = h.create(labPatch(fmt.Sprintf("192.168.253.%d", i+1)))
		case 1:
			h.update(r.ID, rules.RulePatch{Comment: p(fmt.Sprint(i))})
		case 2:
			need(t, h.s.SetEnabled(rules.Actor{Kind: rules.UI}, r.ID, false) == nil, "scale disable")
		case 3:
			need(t, h.s.ForceDelete(rules.Actor{Kind: rules.UI}, r.ID) == nil, "scale delete")
		}
		durations = append(durations, time.Since(started))
		h.m.mu.Lock()
		gen := h.m.lastGen
		h.m.mu.Unlock()
		pending = append(pending, struct {
			at  time.Time
			gen uint64
		}{started, gen})
		for len(pending) > 0 && h.m.Status()[0].Rules.ConfirmedGen >= pending[0].gen {
			confirmed = append(confirmed, time.Since(pending[0].at))
			pending = pending[1:]
		}
		if left := 100*time.Millisecond - time.Since(started); left > 0 {
			time.Sleep(left)
		}
	}
	h.normal()
	for _, w := range pending {
		confirmed = append(confirmed, time.Since(w.at))
	}
	need(t, percentile(durations, 99) < 2*time.Second, "G3 steady p99", percentile(durations, 99))
	// A new generation invalidates the previous atomic body through the public path.
	h.create(labPatch("192.168.254.2"))
	h.normal()
	h.mu.Lock()
	readBefore := h.readPinned
	h.mu.Unlock()
	h.m.ForceSync("a")
	var pinned, done time.Time
	labWait(t, time.Minute, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.readPinned.After(readBefore) {
			pinned = h.readPinned
			return true
		}
		return false
	})
	during := []time.Duration{}
	starts := []time.Time{}
	for i := 0; i < 20; i++ {
		started := time.Now()
		h.create(labPatch(fmt.Sprintf("192.168.252.%d", i+1)))
		starts = append(starts, started)
		during = append(during, time.Since(started))
		time.Sleep(100 * time.Millisecond)
	}
	labWait(t, time.Minute, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.readDone.After(pinned) {
			done = h.readDone
			return true
		}
		return false
	})
	windowWrites := []time.Duration{}
	for i, started := range starts {
		if !started.Before(pinned) && !started.After(done) {
			windowWrites = append(windowWrites, during[i])
		}
	}
	h.normal()
	var seq int
	var dbName, dbPath string
	err := h.db.QueryRow("PRAGMA database_list").Scan(&seq, &dbName, &dbPath)
	need(t, err == nil, "scale database path", err)
	wal, err := os.Stat(dbPath + "-wal")
	need(t, err == nil, "scale WAL size", err)
	t.Logf("SCALE snapshot_window=%s window_writes=%d wal_bytes=%d", done.Sub(pinned), len(windowWrites), wal.Size())
	need(t, len(windowWrites) >= 10, "snapshot window writes < 10", len(windowWrites), done.Sub(pinned))
	t.Logf("SCALE window_write_max=%s window_write_p50=%s", percentile(windowWrites, 100), percentile(windowWrites, 50))
	need(t, percentile(windowWrites, 100) < time.Second, "snapshot window write max >= 1s", percentile(windowWrites, 100))
	h.equal()
	maxRoute := map[string]time.Duration{}
	for _, r := range h.history("") {
		d := r.End.Sub(r.Start)
		if d > maxRoute[r.Route] {
			maxRoute[r.Route] = d
		}
	}
	limits := map[string]time.Duration{"/": 3 * time.Second, string(nc.HealthRoute): 3 * time.Second, string(nc.StatsRoute): 5 * time.Second, string(nc.RulesRoute): 30 * time.Second, string(nc.WhitelistRoute): 30 * time.Second, string(nc.CommitRoute): 30 * time.Second, string(nc.SyncWLRoute): 30 * time.Second, string(nc.AtomicRoute): 150 * time.Second}
	for route, limit := range limits {
		need(t, maxRoute[route] > 0 && maxRoute[route] <= limit/2, "A6 route half-timeout", route, maxRoute[route], limit)
	}
	rss, e := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	need(t, e == nil, e)
	h.mu.Lock()
	reads := append([]time.Duration{}, h.readDurations...)
	h.mu.Unlock()
	s := h.m.Status()[0]
	need(t, len(reads) > 0 && s.RuleReconcile.Pages >= 500, "scale observations missing")
	t.Logf("SCALE service_p99=%s force_write_max=%s confirmed_p50=%s confirmed_p99=%s narrow_reads=%v reconcile_duration=%s pages=%d rss_kib=%s route_max=%v", percentile(durations, 99), percentile(during, 100), percentile(confirmed, 50), percentile(confirmed, 99), reads, s.RuleReconcile.Duration, s.RuleReconcile.Pages, strings.TrimSpace(string(rss)), maxRoute)
}
