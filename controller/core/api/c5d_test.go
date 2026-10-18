package api

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/secret"
	"github.com/littlewolf9527/xdrop/controller/core/store"
	"github.com/mattn/go-sqlite3"
)

type c5dCancelWriter struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w c5dCancelWriter) Write(b []byte) (int, error) {
	n, e := w.ResponseRecorder.Write(b)
	w.cancel()
	return n, e
}
func (w c5dCancelWriter) Flush() { w.ResponseRecorder.Flush(); w.cancel() }
func c5dMatrix(t *testing.T, e http.Handler, r *http.Request, status int) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { e.ServeHTTP(c5dCancelWriter{w, cancel}, r.WithContext(ctx)); close(done) }()
	c5dWait(t, done, "matrix handler")
	require(t, w.Code == status, "events matrix status", w.Code, status)
	return w
}
func c5dRequest(t *testing.T, e *gin.Engine, method, path, identity, input string, status int) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("X-Xdrop-Actor", identity)
	return c5dMatrix(t, e, r, status)
}
func (f *c4aFixture) c5dCall(t *testing.T, method, path, identity, input string, status int) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v1"+path, nil)
	if strings.HasPrefix(identity, "xdk_") {
		r.Header.Set("Authorization", "Bearer "+identity)
	} else if identity != "" {
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: identity})
	}
	w := c5dMatrix(t, f.e, r, status)
	f.corpus.add("responses", w.Body.Bytes())
	return w
}
func c5dWait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout:", what)
	}
}
func c5dPtr[T any](v T) *T { return &v }

type c5dSource struct {
	*orch.Manager
	mu     sync.Mutex
	status []orch.NodeStatus
	rates  map[string]orch.RuleRate
	key    uint64
	calls  atomic.Int64
}

func (n *c5dSource) Status() []orch.NodeStatus {
	n.calls.Add(1)
	n.mu.Lock()
	defer n.mu.Unlock()
	b, _ := json.Marshal(n.status)
	var out []orch.NodeStatus
	_ = json.Unmarshal(b, &out)
	return out
}
func (n *c5dSource) Changed(rules.Change) { n.mu.Lock(); n.key++; n.mu.Unlock() }
func (n *c5dSource) TrafficInput() orch.TrafficInput {
	n.mu.Lock()
	defer n.mu.Unlock()
	v := orch.TrafficInput{Key: fmt.Sprint(n.key), Names: map[string]bool{}, Rates: map[string]orch.RuleRate{}}
	for _, s := range n.status {
		v.Names[s.Name] = true
	}
	for id, rate := range n.rates {
		v.Rates[id] = rate
	}
	return v
}
func (n *c5dSource) change(f func(*orch.NodeStatus), sample bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	f(&n.status[0])
	if sample {
		n.key++
	}
}

type c5dQueries struct {
	store.Queryer
	calls, failed atomic.Int64
	fail          atomic.Bool
}

func (q *c5dQueries) Query(s string, args ...any) (*sql.Rows, error) {
	q.calls.Add(1)
	if q.fail.Load() {
		q.failed.Add(1)
		return nil, errors.New("TEST_ONLY_READ_FAILURE")
	}
	return q.Queryer.Query(s, args...)
}

type c5dLog struct {
	sync.Mutex
	bytes.Buffer
}

func (l *c5dLog) Write(b []byte) (int, error) { l.Lock(); defer l.Unlock(); return l.Buffer.Write(b) }
func (l *c5dLog) text() string                { l.Lock(); defer l.Unlock(); return l.Buffer.String() }

type c5dFixture struct {
	t          *testing.T
	db         *store.DB
	s          *rules.Service
	acc        *auth.Service
	n          *c5dSource
	a          *API
	e          *gin.Engine
	h          *Hub
	tick, beat chan time.Time
	rounds     chan struct{}
	cycles     atomic.Int64
	now        atomic.Int64
	logs       c5dLog
	q          *c5dQueries
}

func c5dFresh(t *testing.T, configure func(*Options)) *c5dFixture {
	f := &c5dFixture{t: t, tick: make(chan time.Time, 8), beat: make(chan time.Time, 8), rounds: make(chan struct{}, 32)}
	f.now.Store(time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC).Unix())
	var err error
	f.db, err = store.Open(filepath.Join(t.TempDir(), "events.db"))
	require(t, err == nil, "open events database")
	f.n = &c5dSource{Manager: orch.New(nil, orch.Options{}), status: []orch.NodeStatus{{Name: "n1", Online: true, Rates: map[string]float64{"dropped_packets": 5, "passed_packets": 7, "dropped_bytes": 50, "passed_bytes": 70}}}}
	f.s = rules.New(f.db, f.n)
	f.s.Now = func() time.Time { return time.Unix(f.now.Load(), 0) }
	f.acc = auth.New(f.db)
	f.acc.Now = f.s.Now
	f.q = &c5dQueries{Queryer: f.db.Reader()}
	keyPath := filepath.Join(t.TempDir(), "master")
	require(t, secret.Init(keyPath) == nil, "test master")
	key, err := secret.Load(keyPath)
	require(t, err == nil, "load test master")
	opts := Options{Accounts: f.acc, NodeStore: NewNodeService(f.db, key), trafficQuery: f.q, nodeAPI: func(a *API) { f.a = a }, eventsTick: func(d time.Duration) (<-chan time.Time, func()) {
		if d == time.Second {
			return f.tick, func() {}
		}
		require(t, d == 15*time.Second, "heartbeat interval")
		return f.beat, func() {}
	}, roundDone: func() { f.cycles.Add(1); f.rounds <- struct{}{} }}
	if configure != nil {
		configure(&opts)
	}
	f.e, f.h = NewWithHub(f.s, f.n, AccountAuthenticator(f.acc), log.New(&f.logs, "", 0), opts)
	f.h.mu.Lock()
	f.h.started = true
	go f.h.run()
	f.h.mu.Unlock()
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() { f.h.Close(); close(done) }()
		select {
		case <-done:
			require(t, f.db.Close() == nil, "close fixture database")
		case <-time.After(time.Second):
			t.Error("hub cleanup blocked")
		}
	})
	return f
}
func (f *c5dFixture) login(name string) string {
	f.t.Helper()
	pw := "TEST_ONLY_PASSWORD_" + name
	e := f.acc.CreateUser(rules.Actor{Kind: rules.System, Name: "test"}, name, pw, "admin")
	require(f.t, e == nil || e.Code == "user_exists", "create test user")
	c, _, e := f.acc.Login(name, pw, "127.0.0.1")
	require(f.t, e == nil, "login fixture")
	return c
}
func (f *c5dFixture) step() {
	f.t.Helper()
	f.tick <- time.Unix(f.now.Load(), 0)
	c5dWait(f.t, f.rounds, "hub cycle")
}
func (f *c5dFixture) create(port int, expiry string) rules.Result {
	f.t.Helper()
	p := rules.RulePatch{DstIP: c5dPtr("192.0.2.10"), Protocol: c5dPtr("tcp"), DstPort: c5dPtr(port)}
	if expiry != "" {
		p.ExpiresIn = &expiry
	}
	r, e := f.s.Create(rules.Actor{Kind: rules.UI, Name: "alice"}, "", p)
	require(f.t, e == nil, "create rule")
	return r
}

type c5dListener struct {
	conn net.Conn
	once sync.Once
	stop chan struct{}
}

func (l *c5dListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.stop
	return nil, net.ErrClosed
}
func (l *c5dListener) Close() error {
	select {
	case <-l.stop:
	default:
		close(l.stop)
	}
	return nil
}
func (l *c5dListener) Addr() net.Addr { return l.conn.LocalAddr() }

type c5dWire struct {
	net.Conn
	writes  atomic.Int64
	fail    atomic.Bool
	failed  atomic.Int64
	entered chan struct{}
}

func (c *c5dWire) Write(b []byte) (int, error) {
	c.writes.Add(1)
	select {
	case c.entered <- struct{}{}:
	default:
	}
	if c.fail.Load() {
		c.failed.Add(1)
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(b)
}

type c5dMeasure struct {
	http.ResponseWriter
	events *atomic.Int64
}

func (w c5dMeasure) Write(b []byte) (int, error) {
	if bytes.HasPrefix(b, []byte("event: ")) {
		w.events.Add(int64(len(b)))
	}
	return w.ResponseWriter.Write(b)
}
func (w c5dMeasure) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type c5dStream struct {
	client           net.Conn
	server           *http.Server
	wire             *c5dWire
	ended            chan struct{}
	permits          chan struct{}
	frames           chan string
	errors           chan error
	returned, events atomic.Int64
	response         *http.Response
}

func c5dConnect(t *testing.T, h http.Handler, cookie, tail string) *c5dStream {
	t.Helper()
	client, conn := net.Pipe()
	s := &c5dStream{client: client, ended: make(chan struct{}), permits: make(chan struct{}, 4096), frames: make(chan string, 4096), errors: make(chan error, 1)}
	s.wire = &c5dWire{Conn: conn, entered: make(chan struct{}, 4096)}
	s.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { s.returned.Add(1); close(s.ended) }()
		h.ServeHTTP(c5dMeasure{w, &s.events}, r)
	})}
	l := &c5dListener{s.wire, sync.Once{}, make(chan struct{})}
	go func() { _ = s.server.Serve(l) }()
	t.Cleanup(func() { client.Close(); s.server.Close(); close(s.permits) })
	go func() {
		defer close(s.frames)
		reader := bufio.NewReader(client)
		var body *bufio.Reader
		for range s.permits {
			if body == nil {
				resp, e := http.ReadResponse(reader, &http.Request{Method: "GET"})
				if e != nil {
					s.errors <- e
					return
				}
				s.response = resp
				body = bufio.NewReader(resp.Body)
			}
			var frame strings.Builder
			for {
				line, e := body.ReadString('\n')
				if e != nil {
					s.errors <- e
					return
				}
				frame.WriteString(line)
				if line == "\n" {
					break
				}
			}
			s.frames <- frame.String()
		}
	}()
	request := "GET /api/v1/events HTTP/1.1\r\nHost: example.invalid\r\nCookie: " + auth.CookieName + "=" + cookie + "\r\n" + tail
	if tail == "" {
		request += "\r\n"
	}
	_, err := io.WriteString(client, request)
	require(t, err == nil, "send test request")
	return s
}
func (s *c5dStream) next(t *testing.T) string {
	t.Helper()
	s.permits <- struct{}{}
	select {
	case v, ok := <-s.frames:
		require(t, ok, "stream ended before expected frame")
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("frame timeout")
	}
	return ""
}
func (s *c5dStream) end(t *testing.T) {
	t.Helper()
	c5dWait(t, s.ended, "handler return")
	require(t, s.returned.Load() == 1, "handler return count")
	t.Logf("handler_returns=%d event_bytes=%d writes=%d", s.returned.Load(), s.events.Load(), s.wire.writes.Load())
}
func (f *c5dFixture) stream(cookie string) *c5dStream {
	s := c5dConnect(f.t, f.e, cookie, "")
	require(f.t, s.next(f.t) == "retry: 3000\n\n", "retry prelude")
	c5dHeaders(f.t, s.response)
	return s
}
func c5dHeaders(t *testing.T, response *http.Response) {
	t.Helper()
	require(t, response.StatusCode == 200, "SSE status")
	for name, value := range map[string]string{"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no"} {
		require(t, response.Header.Get(name) == value, "SSE response header", name, response.Header.Get(name))
	}
	t.Log("SSE_headers=3 status=200")
}
func c5dDecode(t *testing.T, frame, name string) map[string]any {
	t.Helper()
	prefix := "event: " + name + "\ndata: "
	require(t, strings.HasPrefix(frame, prefix), "event order", name, frame)
	var out map[string]any
	require(t, json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(frame, prefix))), &out) == nil, "event JSON")
	return out
}
func c5dPair(t *testing.T, s *c5dStream, first, second string) map[string]map[string]any {
	t.Helper()
	values := map[string]map[string]any{}
	for i := 0; i < 2; i++ {
		frame := s.next(t)
		name := strings.TrimPrefix(strings.SplitN(frame, "\n", 2)[0], "event: ")
		require(t, (name == first || name == second) && values[name] == nil, "increment class multiset", first, second, name)
		values[name] = c5dDecode(t, frame, name)
	}
	require(t, len(values) == 2 && values[first] != nil && values[second] != nil, "increment pair incomplete")
	return values
}
func (f *c5dFixture) snapshot(s *c5dStream) []map[string]any {
	out := []map[string]any{}
	for _, name := range []string{"rules", "nodes", "traffic"} {
		out = append(out, c5dDecode(f.t, s.next(f.t), name))
	}
	f.t.Log("events=3 classes=rules,nodes,traffic")
	return out
}
func (f *c5dFixture) rest(cookie, path string) map[string]any {
	r := httptest.NewRequest("GET", "/api/v1"+path, nil)
	r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.e.ServeHTTP(w, r)
	require(f.t, w.Code == 200, "REST status", path)
	return decoded[map[string]any](f.t, w)
}
func (f *c5dFixture) compare(cookie string, v []map[string]any) {
	t := f.t
	n := f.rest(cookie, "/nodes")
	require(t, reflect.DeepEqual(v[1]["nodes"], n["nodes"]) && v[1]["epoch"] == n["epoch"], "nodes snapshot vs REST")
	require(t, reflect.DeepEqual(v[2]["top"], f.rest(cookie, "/traffic/top?n=5")), "top vs REST")
	sys := f.rest(cookie, "/system")
	for _, raw := range sys["nodes"].([]any) {
		row := raw.(map[string]any)
		rec := v[1]["reconcile"].(map[string]any)[row["name"].(string)].(map[string]any)
		require(t, reflect.DeepEqual(rec["rules"], row["rule_reconcile"]) && reflect.DeepEqual(rec["whitelist"], row["whitelist_reconcile"]), "reconcile projection")
	}
}
func (f *c5dFixture) overview(cookie string, traffic map[string]any) {
	f.t.Helper()
	want := map[string]any{}
	f.n.mu.Lock()
	for field, rate := range map[string]string{"dropped_pps": "dropped_packets", "passed_pps": "passed_packets", "dropped_bytes_ps": "dropped_bytes", "passed_bytes_ps": "passed_bytes"} {
		var sum float64
		for _, n := range f.n.status {
			sum += n.Rates[rate]
		}
		want[field] = sum
	}
	if len(f.n.status) > 0 {
		seen := map[any]bool{}
		for _, value := range want {
			require(f.t, !seen[value], "overview input rates must differ")
			seen[value] = true
		}
	}
	f.n.mu.Unlock()
	rows := f.rest(cookie, "/nodes")["nodes"].([]any)
	want["nodes_total"], want["nodes_online"] = float64(len(rows)), float64(0)
	for _, raw := range rows {
		if raw.(map[string]any)["online"].(bool) {
			want["nodes_online"] = want["nodes_online"].(float64) + 1
		}
	}
	require(f.t, reflect.DeepEqual(traffic["overview"], want), "overview six fields", traffic["overview"], want)
	f.t.Logf("overview_fields=6 expected=%v", want)
}

func TestC5DEvents(t *testing.T) {
	t.Run("snapshots", func(t *testing.T) {
		var recordCold atomic.Bool
		registered := make(chan [3][]byte, 1)
		var f *c5dFixture
		f = c5dFresh(t, func(o *Options) {
			o.afterSnapshotRead = func() {
				if recordCold.Load() {
					var values [3][]byte
					for i, b := range f.h.cache {
						values[i] = append([]byte(nil), b...)
					}
					registered <- values
				}
			}
		})
		cookie := f.login("alice")
		f.n.change(func(n *orch.NodeStatus) { n.Online = false }, true)
		f.step()
		require(t, f.n.calls.Load() == 0, "zero subscribers read Status")
		s := f.stream(cookie)
		f.step()
		cold := f.snapshot(s)
		f.compare(cookie, cold)
		f.overview(cookie, cold[2])
		warm := f.stream(cookie)
		hot := f.snapshot(warm)
		require(t, reflect.DeepEqual(hot, cold), "hot snapshot")
		f.overview(cookie, hot[2])
		s.client.Close()
		warm.client.Close()
		s.end(t)
		warm.end(t)
		f.h.mu.Lock()
		require(t, len(f.h.subs) == 0, "zero subscription precondition")
		f.h.mu.Unlock()
		f.create(80, "")
		f.n.change(func(n *orch.NodeStatus) { n.Online = true; n.Rates["dropped_packets"] = 11 }, true)
		newSeq, newGen := f.s.Revision()
		newNodes := f.rest(cookie, "/nodes")
		require(t, float64(newSeq) > cold[0]["seq"].(float64) && float64(newGen) > cold[0]["gen"].(float64), "zero-period rules did not change")
		require(t, !reflect.DeepEqual(newNodes["nodes"], cold[1]["nodes"]), "zero-period nodes did not change")
		require(t, cold[2]["overview"].(map[string]any)["dropped_pps"] != float64(11), "zero-period traffic did not change")
		recordCold.Store(true)
		beforeReconnect := f.cycles.Load()
		again := f.stream(cookie)
		var observed [3][]byte
		select {
		case observed = <-registered:
		case <-time.After(time.Second):
			t.Fatal("registration cache witness absent")
		}
		t.Logf("registration_cache_bytes=[%d,%d,%d] cycles_before=%d cycles_at_registration=%d changed_classes=3", len(observed[0]), len(observed[1]), len(observed[2]), beforeReconnect, f.cycles.Load())
		require(t, f.cycles.Load() == beforeReconnect, "registration advanced clock")
		require(t, len(observed[0]) == 0 && len(observed[1]) == 0 && len(observed[2]) == 0, "zero-period registration read warm cache")
		f.step()
		fresh := f.snapshot(again)
		require(t, f.cycles.Load() == beforeReconnect+1, "cold snapshot must use exactly one cycle")
		f.compare(cookie, fresh)
		f.overview(cookie, fresh[2])
		require(t, !reflect.DeepEqual(fresh[1], cold[1]), "zero-period cache survived")
		require(t, fresh[0]["seq"] == float64(newSeq) && fresh[0]["gen"] == float64(newGen), "cold rules did not match new state")
		require(t, reflect.DeepEqual(fresh[1]["nodes"], newNodes["nodes"]) && fresh[2]["overview"].(map[string]any)["dropped_pps"] == float64(11), "cold nodes/traffic did not match new state")
		for i := range fresh {
			require(t, !reflect.DeepEqual(fresh[i], cold[i]), "cold class equals old cache", i)
		}
		t.Log("reconnect_events=3 sequence=rules,nodes,traffic cold_cycles=1 changed_classes=3")
		again.client.Close()
		again.end(t)
	})
	t.Run("increments", func(t *testing.T) {
		f := c5dFresh(t, nil)
		cookie := f.login("alice")
		s := f.stream(cookie)
		f.step()
		v := f.snapshot(s)
		r := f.create(80, "1h")
		f.step()
		first := c5dPair(t, s, "rules", "traffic")["rules"]
		require(t, first["seq"].(float64) > v[0]["seq"].(float64), "create seq")
		f.create(80, "2h")
		f.step()
		renew := c5dDecode(t, s.next(t), "rules")
		require(t, renew["seq"].(float64) > first["seq"].(float64) && renew["gen"] == first["gen"], "renew seq/gen")
		f.n.change(func(n *orch.NodeStatus) { n.Online = false }, false)
		f.step()
		c5dDecode(t, s.next(t), "nodes")
		f.n.change(func(n *orch.NodeStatus) {
			n.RuleReconcile.LastAt = time.Unix(f.now.Load(), 0)
			n.RuleReconcile.Result = "equal"
		}, false)
		f.step()
		rec := c5dDecode(t, s.next(t), "nodes")
		v[1] = rec
		f.compare(cookie, v)
		f.n.change(func(n *orch.NodeStatus) { n.Rates["dropped_packets"] = 11 }, true)
		f.step()
		traffic := c5dPair(t, s, "nodes", "traffic")["traffic"]
		require(t, traffic["overview"].(map[string]any)["dropped_pps"] == float64(11), "overview")
		before := s.events.Load()
		f.step()
		require(t, s.events.Load() == before, "unchanged cycle emitted")
		s.client.Close()
		s.end(t)
		t.Logf("cycles=%d unchanged_event_delta=0 rule_created=%t", f.cycles.Load(), r.Rule.ID != "")
	})
	for _, empty := range []bool{false, true} {
		empty := empty
		t.Run(fmt.Sprintf("db-only-%t", empty), func(t *testing.T) {
			f := c5dFresh(t, nil)
			if empty {
				f.n.status = nil
			}
			cookie := f.login("alice")
			s := f.stream(cookie)
			f.step()
			f.overview(cookie, f.snapshot(s)[2])
			key := f.n.TrafficInput().Key
			require(t, store.PutNode(f.db, store.Node{Name: "outside", BaseURL: "http://192.0.2.3", KeyNonce: []byte("TEST_ONLY"), KeyCipher: []byte("TEST_ONLY")}, true) == nil, "external node")
			require(t, f.n.TrafficInput().Key == key, "orch key changed")
			f.step()
			v := c5dPair(t, s, "nodes", "traffic")["traffic"]
			require(t, v["top"].(map[string]any)["incomplete"] == true, "external node missed")
			f.overview(cookie, v)
			s.client.Close()
			s.end(t)
			t.Log("frozen_orch_key=true traffic_events=1")
		})
	}
	t.Run("status-count", func(t *testing.T) {
		f := c5dFresh(t, nil)
		cookie := f.login("alice")
		for i := 0; i < 3; i++ {
			f.step()
		}
		require(t, f.n.calls.Load() == 0, "empty hub read")
		streams := []*c5dStream{}
		for i := 0; i < 100; i++ {
			streams = append(streams, f.stream(cookie))
		}
		for i := 0; i < 10; i++ {
			f.n.change(func(n *orch.NodeStatus) { n.HealthAt = time.Unix(int64(i+1), 0) }, true)
			f.step()
			for _, s := range streams {
				if i == 0 {
					f.snapshot(s)
				} else {
					c5dPair(t, s, "nodes", "traffic")
				}
			}
		}
		require(t, f.n.calls.Load() == 10, "Status amplification", f.n.calls.Load())
		for _, s := range streams {
			s.client.Close()
			s.end(t)
		}
		t.Logf("subscribers=100 completed_cycles=10 status_calls=%d snapshot_extra_calls=0", f.n.calls.Load())
	})
}

func TestC5DReadFailure(t *testing.T) {
	for _, kind := range []string{"nodes", "traffic"} {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			var fail, counting atomic.Bool
			var reads, failures, nodes, targets, sessions atomic.Int64
			var gate atomic.Pointer[chan struct{}]
			f := c5dFresh(t, func(o *Options) {
				o.beforeWriteAuth = func() {
					if ch := gate.Load(); ch != nil {
						<-*ch
					}
				}
			})
			pool := f.db.Reader().(*sql.DB)
			pool.SetMaxOpenConns(1)
			pool.SetMaxIdleConns(1)
			conn, err := pool.Conn(context.Background())
			require(t, err == nil, "reader connection")
			err = conn.Raw(func(driver any) error {
				driver.(*sqlite3.SQLiteConn).RegisterAuthorizer(func(op int, table, column, database string) int {
					if counting.Load() && op == sqlite3.SQLITE_SELECT {
						reads.Add(1)
					}
					if op == sqlite3.SQLITE_READ {
						if counting.Load() {
							switch table {
							case "nodes":
								nodes.Add(1)
							case "rules":
								targets.Add(1)
							case "sessions":
								sessions.Add(1)
							}
						}
						if fail.Load() && ((kind == "nodes" && table == "nodes") || (kind == "traffic" && table == "rules")) {
							failures.Add(1)
							return sqlite3.SQLITE_DENY
						}
					}
					return sqlite3.SQLITE_OK
				})
				return nil
			})
			require(t, err == nil && conn.Close() == nil, "install actual SQL read counter")
			measure := func() int64 {
				ch := make(chan struct{})
				gate.Store(&ch)
				before := reads.Load()
				counting.Store(true)
				f.step()
				counting.Store(false)
				delta := reads.Load() - before
				gate.Store(nil)
				close(ch)
				t.Logf("cycle=%d actual_SQL_SELECTs=%d injected_errors=%d", f.cycles.Load(), delta, failures.Load())
				return delta
			}
			cookie := f.login("alice")
			rule := f.create(79, "")
			f.n.rates = map[string]orch.RuleRate{rule.Rule.ID: {PPS: 5, BytesPS: 50, Nodes: 1}}
			a, b := f.stream(cookie), f.stream(cookie)
			normal := measure()
			f.snapshot(a)
			f.snapshot(b)
			require(t, normal > 0 && nodes.Load() > 0 && targets.Load() > 0 && sessions.Load() > 0, "actual reads missing from normal measurement")
			beforeA, beforeB := a.events.Load(), b.events.Load()
			fail.Store(true)
			f.create(80, "")
			f.n.change(func(n *orch.NodeStatus) { n.Online = false }, true)
			failedReads := measure()
			require(t, failures.Load() > 0, "read failure injection absent")
			require(t, failedReads <= normal, "failed cycle actual read amplification", failedReads, normal)
			a.end(t)
			b.end(t)
			require(t, a.events.Load() == beforeA && b.events.Load() == beforeB, "failed cycle published partial events")
			require(t, strings.Contains(f.logs.text(), "hub snapshot read failed; closed_streams=2\n"), "actual close count log")
			cycles := f.cycles.Load()
			require(t, measure() == 0, "no-subscriber cycle read database")
			require(t, f.cycles.Load() == cycles+1, "hub stopped on read failure")
			f.h.mu.Lock()
			empty := f.h.cache[0] == nil && f.h.cache[1] == nil && f.h.cache[2] == nil
			f.h.mu.Unlock()
			require(t, empty, "failure retained cache")
			c := f.stream(cookie)
			require(t, measure() <= normal, "persistent failure actual read amplification")
			c.end(t)
			require(t, c.events.Load() == 0, "persistent failure delivered events")
			require(t, strings.Contains(f.logs.text(), "closed_streams=1\n"), "new failed stream count")
			fail.Store(false)
			d := f.stream(cookie)
			require(t, measure() <= normal, "recovery actual read amplification")
			v := f.snapshot(d)
			require(t, reads.Load() <= f.cycles.Load()*normal, "failure read amplification", reads.Load(), f.cycles.Load(), normal)
			f.compare(cookie, v)
			require(t, failures.Load() > 0, "read failure injection absent")
			f.h.mu.Lock()
			running := !f.h.closing
			f.h.mu.Unlock()
			require(t, running, "hub lifetime")
			t.Logf("cycles=%d failed_reads=%d actual_SQL_SELECTs=%d normal_reads_per_cycle=%d actual_closed=3 failed_cycle_event_bytes=0", f.cycles.Load(), failures.Load(), reads.Load(), normal)
			d.client.Close()
			d.end(t)
		})
	}
}

func TestC5DRegistration(t *testing.T) {
	t.Run("snapshot-race", func(t *testing.T) {
		var armed atomic.Bool
		var completed atomic.Bool
		var completedInside, lockWait atomic.Bool
		var f *c5dFixture
		f = c5dFresh(t, func(o *Options) {
			o.afterSnapshotRead = func() {
				if !armed.CompareAndSwap(true, false) {
					return
				}
				f.n.change(func(n *orch.NodeStatus) { n.Online = false }, false)
				done := make(chan struct{})
				go func() { f.tick <- time.Unix(f.now.Load(), 0); <-f.rounds; completed.Store(true); close(done) }()
				select {
				case <-done:
					completedInside.Store(true)
				case <-time.After(200 * time.Millisecond):
					lockWait.Store(true)
				}
			}
		})
		cookie := f.login("alice")
		a := f.stream(cookie)
		f.step()
		f.snapshot(a)
		armed.Store(true)
		b := f.stream(cookie)
		require(t, completedInside.Load() != lockWait.Load(), "registration barrier did not execute")
		t.Logf("broadcast_completed_inside_hook=%t hub_lock_wait_200ms=%t", completedInside.Load(), lockWait.Load())
		for i := 0; i < 3; i++ {
			f.step()
		}
		seenB := false
		for i := 0; i < 6 && !seenB; i++ {
			v := b.next(t)
			if strings.HasPrefix(v, "event: nodes\n") {
				n := c5dDecode(t, v, "nodes")
				seenB = !n["nodes"].([]any)[0].(map[string]any)["online"].(bool)
			}
		}
		require(t, seenB, "registration lost state B")
		require(t, completed.Load(), "racing cycle never completed")
		t.Logf("racing_cycle_completed=%t cycles=%d latest_nodes=B", completed.Load(), f.cycles.Load())
		a.client.Close()
		b.client.Close()
		a.end(t)
		b.end(t)
	})
	t.Run("post-register-auth", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var armed atomic.Bool
		f := c5dFresh(t, func(o *Options) {
			o.atRegister = func() {
				if armed.Load() {
					close(entered)
					<-release
				}
			}
		})
		cookie := f.login("alice")
		armed.Store(true)
		s := c5dConnect(t, f.e, cookie, "")
		c5dWait(t, entered, "before registration")
		require(t, f.acc.Logout(rules.Actor{Kind: rules.UI, Name: "alice"}, cookie) == nil, "logout race")
		close(release)
		s.end(t)
		require(t, s.events.Load() == 0 && f.cycles.Load() == 0, "post-register authentication race")
		t.Log("hub_cycles=0 handler_returns=1 events=0")
	})
}
func TestC5DRevocation(t *testing.T) {
	for _, mode := range []string{"logout", "password", "delete-user", "session-hours", "expiry", "cli-password"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			f := c5dFresh(t, nil)
			aCookie, bCookie, otherCookie := f.login("alice"), f.login("alice"), f.login("bob")
			a, b, other := f.stream(aCookie), f.stream(bCookie), f.stream(otherCookie)
			f.step()
			f.snapshot(a)
			f.snapshot(b)
			f.snapshot(other)
			mutate := func(method, path, cookie, body string) {
				r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
				w := httptest.NewRecorder()
				f.e.ServeHTTP(w, r)
				require(t, w.Code == 204 || w.Code == 200, "revocation mutation status", w.Code)
			}
			switch mode {
			case "logout":
				mutate("POST", "/auth/logout", aCookie, "")
			case "password":
				mutate("PUT", "/users/alice/password", otherCookie, `{"password":"TEST_ONLY_NEW_PASSWORD"}`)
			case "delete-user":
				mutate("DELETE", "/users/alice", otherCookie, "")
			case "session-hours":
				f.now.Add(int64(2 * time.Hour / time.Second))
				require(t, f.acc.UpdateSettings(rules.Actor{Kind: rules.UI, Name: "bob"}, auth.SettingsPatch{SessionHours: c5dPtr(1)}) == nil, "shorten sessions")
			case "expiry":
				f.now.Add(int64(25 * time.Hour / time.Second))
			case "cli-password":
				cli := auth.New(f.db)
				require(t, cli.SetPassword(rules.Actor{Kind: rules.System, Name: "cli"}, "alice", "TEST_ONLY_CLI_PASSWORD") == nil, "other auth instance password")
			}
			f.step()
			a.end(t)
			closed := int64(1)
			if mode != "logout" {
				b.end(t)
				closed++
			}
			if mode == "session-hours" || mode == "expiry" {
				other.end(t)
				closed++
			} else {
				f.create(80, "")
				f.step()
				c5dDecode(t, other.next(t), "rules")
				require(t, other.returned.Load() == 0, "other user's stream closed")
				if mode == "logout" {
					c5dDecode(t, b.next(t), "rules")
					require(t, b.returned.Load() == 0, "other session closed")
					b.client.Close()
					b.end(t)
				}
				other.client.Close()
				other.end(t)
			}
			require(t, closed > 0 && f.cycles.Load() > 0, "revocation execution witness")
			t.Logf("actual_closed=%d completed_cycles=%d", closed, f.cycles.Load())
		})
	}
	t.Run("before-write-auth", func(t *testing.T) {
		first, second, releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		var armed atomic.Bool
		var calls atomic.Int64
		f := c5dFresh(t, func(o *Options) {
			o.beforeWriteAuth = func() {
				if !armed.Load() {
					return
				}
				switch calls.Add(1) {
				case 1:
					close(first)
					<-releaseFirst
				case 2:
					close(second)
					<-releaseSecond
				}
			}
		})
		cookie := f.login("alice")
		s := f.stream(cookie)
		f.step()
		f.snapshot(s)
		armed.Store(true)
		f.create(80, "")
		f.step()
		c5dWait(t, first, "first in-flight event")
		f.create(81, "")
		f.step()
		f.h.mu.Lock()
		pending := 0
		for sub := range f.h.subs {
			pending += len(sub.slots[0]) + len(sub.slots[2])
		}
		f.h.mu.Unlock()
		require(t, pending > 0, "pending-event precondition")
		close(releaseFirst)
		c5dDecode(t, s.next(t), "rules")
		c5dWait(t, second, "event taken before auth")
		before := s.events.Load()
		cycles := f.cycles.Load()
		require(t, f.acc.Logout(rules.Actor{Kind: rules.UI, Name: "alice"}, cookie) == nil, "write-window logout")
		close(releaseSecond)
		s.end(t)
		require(t, s.events.Load() == before && f.cycles.Load() == cycles, "write after revoke or clock compensation")
		t.Logf("pending_slots=%d hook_arrivals=%d post_revoke_event_bytes=0 actual_closed=1 cycles=%d", pending, calls.Load(), cycles)
	})
}

func TestC5DWire(t *testing.T) {
	for _, mode := range []string{"blocked-revoke", "blocked-close", "closed-window", "body-400", "closed-retry", "shutdown-three", "heartbeat", "permissions"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var armed atomic.Bool
			f := c5dFresh(t, func(o *Options) {
				if mode == "closed-window" {
					o.beforeWriteAuth = func() {
						if armed.Load() {
							close(entered)
							<-release
						}
					}
				}
			})
			cookie := f.login("alice")
			if mode == "permissions" {
				for _, identity := range []string{"", "key"} {
					r := httptest.NewRequest("GET", "/api/v1/events", nil)
					want := 401
					if identity == "key" {
						_, key, _, e := f.acc.IssueCredential(rules.Actor{Kind: rules.UI, Admin: true, Name: "alice"}, "test")
						require(t, e == nil, "issue fixture credential")
						r.Header.Set("Authorization", "Bearer "+key)
						want = 403
					}
					w := httptest.NewRecorder()
					f.e.ServeHTTP(w, r)
					require(t, w.Code == want, "events permission", identity, w.Code)
				}
				return
			}
			if mode == "body-400" {
				s := c5dConnect(t, f.e, cookie, "Content-Length: 10\r\n\r\nab")
				require(t, s.client.SetReadDeadline(time.Now().Add(2*time.Second)) == nil, "fixture response read bound")
				start := time.Now()
				resp, err := http.ReadResponse(bufio.NewReader(s.client), &http.Request{Method: "GET"})
				require(t, err == nil && resp.StatusCode == 400, "partial body status")
				body, err := io.ReadAll(resp.Body)
				require(t, err == nil && bytes.Contains(body, []byte(`"bad_request"`)) && time.Since(start) < time.Second, "partial body bounded response")
				s.end(t)
				return
			}
			if mode == "closed-retry" {
				f.h.Close()
				s := c5dConnect(t, f.e, cookie, "")
				c5dWait(t, s.wire.entered, "closed response write")
				start := time.Now()
				s.end(t)
				require(t, time.Since(start) < 1500*time.Millisecond, "closed response deadline")
				return
			}
			s := f.stream(cookie)
			f.step()
			f.snapshot(s)
			switch mode {
			case "blocked-revoke", "blocked-close":
				for len(s.wire.entered) > 0 {
					<-s.wire.entered
				}
				f.create(80, "")
				f.step()
				c5dWait(t, s.wire.entered, "blocked underlying write")
				before := s.returned.Load()
				require(t, before == 0, "write was not blocked")
				start := time.Now()
				if mode == "blocked-revoke" {
					require(t, f.acc.Logout(rules.Actor{Kind: rules.UI, Name: "alice"}, cookie) == nil, "logout blocked writer")
					f.step()
				} else {
					f.h.Close()
				}
				s.end(t)
				require(t, time.Since(start) < time.Second, "blocked stream close latency")
			case "closed-window":
				armed.Store(true)
				f.create(80, "")
				f.step()
				c5dWait(t, entered, "write deadline window")
				before := s.events.Load()
				f.h.Close()
				close(release)
				s.end(t)
				require(t, s.events.Load() == before, "closed stream wrote or extended deadline")
			case "shutdown-three":
				second, third := f.stream(cookie), f.stream(cookie)
				f.snapshot(second)
				f.snapshot(third)
				f.h.Close()
				s.end(t)
				second.end(t)
				third.end(t)
				c5dWait(t, f.h.done, "hub exit")
				next := c5dConnect(t, f.e, cookie, "")
				require(t, next.next(t) == "retry: 3000\n\n", "closed retry")
				c5dHeaders(t, next.response)
				next.end(t)
				require(t, next.events.Load() == 0, "closed hub emitted snapshot")
				t.Log("closed_streams=3 hub_exited=true new_stream_events=0")
			case "heartbeat":
				f.beat <- time.Unix(f.now.Load()+15, 0)
				require(t, s.next(t) == ": ping\n\n", "heartbeat")
				s.client.Close()
				s.end(t)
				f.h.mu.Lock()
				count := len(f.h.subs)
				f.h.mu.Unlock()
				require(t, count == 0, "failed writer retained")
				t.Log("heartbeat_count=1 remaining_subscribers=0")
			}
		})
	}
}

func TestC5DSlowSubscriber(t *testing.T) {
	f := c5dFresh(t, nil)
	cookie := f.login("alice")
	slow, fast := f.stream(cookie), f.stream(cookie)
	f.step()
	f.snapshot(slow)
	f.snapshot(fast)
	for len(slow.wire.entered) > 0 {
		<-slow.wire.entered
	}
	f.create(1, "")
	f.step()
	c5dWait(t, slow.wire.entered, "slow stream blocked")
	c5dPair(t, fast, "rules", "traffic")
	f.create(2, "")
	f.step()
	c5dPair(t, fast, "rules", "traffic")
	f.h.mu.Lock()
	full := 0
	for s := range f.h.subs {
		if len(s.slots[0]) == 1 {
			full++
		}
	}
	f.h.mu.Unlock()
	require(t, full == 1 && slow.returned.Load() == 0, "full slow-slot precondition")
	start := time.Now()
	commits, overwrites := 0, 0
	var latest float64
	for cycle := 0; cycle < 5; cycle++ {
		for i := 0; i < 20; i++ {
			f.create(100+commits, "")
			commits++
		}
		f.step()
		overwrites++
		v := c5dPair(t, fast, "rules", "traffic")["rules"]
		latest = v["seq"].(float64)
	}
	elapsed := time.Since(start)
	require(t, commits == 100 && overwrites >= 4 && elapsed <= time.Second, "producer bound", commits, overwrites, elapsed)
	observed := []float64{}
	for i := 0; i < 4; i++ {
		frame := slow.next(t)
		if strings.HasPrefix(frame, "event: rules\n") {
			seq := c5dDecode(t, frame, "rules")["seq"].(float64)
			observed = append(observed, seq)
			if seq == latest {
				break
			}
		}
	}
	require(t, len(observed) == 2 && observed[0] < 3 && observed[1] == latest, "slow slot retained intermediate state", observed, latest)
	seq, _ := f.s.Revision()
	require(t, uint64(latest) == seq, "fast stream missed latest revision")
	slow.client.Close()
	fast.client.Close()
	slow.end(t)
	fast.end(t)
	t.Logf("commits=%d cycles_with_full_slot=%d overwritten=%d slow_rule_events=%d latest_seq=%d elapsed=%s PERF_admit_limit=1s", commits, overwrites, overwrites, len(observed), seq, elapsed)
}

func TestC5DCloseAuth(t *testing.T) {
	for _, phase := range []string{"before-write", "after-register"} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var armed, closeReturned atomic.Bool
			var arrivals, authCalls, lateAuth atomic.Int64
			f := c5dFresh(t, func(o *Options) {
				hook := func() {
					if armed.CompareAndSwap(true, false) {
						arrivals.Add(1)
						close(entered)
						<-release
					}
				}
				if phase == "before-write" {
					o.beforeWriteAuth = hook
				} else {
					o.afterRegister = hook
				}
			})
			authenticate := f.h.auth
			f.h.auth = func(r *http.Request) (rules.Actor, *Error) {
				authCalls.Add(1)
				if closeReturned.Load() {
					lateAuth.Add(1)
				}
				return authenticate(r)
			}
			cookie := f.login("alice")
			warm := f.stream(cookie)
			f.step()
			f.snapshot(warm)
			armed.Store(true)
			s := warm
			if phase == "before-write" {
				f.create(80, "")
				f.step()
				c5dWait(t, entered, "event taken before authentication")
				f.create(81, "")
				f.step()
			} else {
				s = c5dConnect(t, f.e, cookie, "")
				c5dWait(t, entered, "registration completed before authentication")
			}
			f.h.mu.Lock()
			pending := 0
			for sub := range f.h.subs {
				for _, slot := range sub.slots {
					pending += len(slot)
				}
			}
			f.h.mu.Unlock()
			require(t, pending > 0 && arrivals.Load() == 1 && authCalls.Load() > 0, "close/auth barrier preconditions")
			before := s.events.Load()
			f.h.Close()
			closeReturned.Store(true)
			close(release)
			s.end(t)
			if s != warm {
				warm.end(t)
			}
			t.Logf("close_returned=%t hook_arrivals=%d pending_slots=%d auth_calls=%d post_close_auth=%d post_close_event_bytes=%d handler_returns=%d", closeReturned.Load(), arrivals.Load(), pending, authCalls.Load(), lateAuth.Load(), s.events.Load()-before, s.returned.Load())
			require(t, closeReturned.Load() && lateAuth.Load() == 0 && s.events.Load() == before && s.returned.Load() == 1, "authentication or event after Close returned")
		})
	}
}

func TestC5DSeams(t *testing.T) {
	v := reflect.ValueOf(Options{})
	for _, name := range []string{"eventsTick", "afterSnapshotRead", "beforeWriteAuth", "atRegister", "afterRegister", "roundDone", "nodesRead"} {
		require(t, v.FieldByName(name).IsNil(), "non-nil default seam", name)
	}
	t.Log("nil_default_seams=7")
}

func TestC5DHeartbeatWriteFailure(t *testing.T) {
	f := c5dFresh(t, nil)
	s := f.stream(f.login("alice"))
	f.step()
	f.snapshot(s)
	s.wire.fail.Store(true)
	f.beat <- time.Unix(f.now.Load()+15, 0)
	s.end(t)
	f.h.mu.Lock()
	remaining := len(f.h.subs)
	f.h.mu.Unlock()
	require(t, s.wire.failed.Load() > 0 && remaining == 0 && f.cycles.Load() > 0, "heartbeat write failure did not unregister")
	t.Logf("failed_writes=%d handler_returns=%d remaining_subscribers=%d completed_cycles=%d", s.wire.failed.Load(), s.returned.Load(), remaining, f.cycles.Load())
}
