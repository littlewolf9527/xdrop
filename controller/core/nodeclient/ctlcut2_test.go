package nodeclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testClient(t *testing.T, rt http.RoundTripper, opts Options) *Client {
	t.Helper()
	opts.Transport = rt
	c, e := New(NodeSpec{Name: "test", BaseURL: "http://node.invalid", Key: Secret("cut2-test-secret")}, opts)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func handlerRT(h http.HandlerFunc) http.RoundTripper {
	return transportFunc(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result(), nil
	})
}

var routeBodies = map[Route]string{
	ProbeRoute: `{"sync_protocol":11}`, HealthRoute: `{"status":"healthy"}`, StatsRoute: `{"total_packets":2,"dropped_packets":1,"passed_packets":1}`,
	RulesRoute: `{"rules":[],"count":0,"pagination":{"page":1,"limit":1000,"total":0,"pages":0}}`, WhitelistRoute: `{"entries":[],"count":0}`,
	CommitRoute: `{"code":"committed","groups":[{"index":0,"result":"created"}]}`, AtomicRoute: `{"success":true,"added":0,"failed":0,"rules":0,"cidr_rules":0,"rejected":[]}`,
	SyncWLRoute: `{"total":0,"failed":0}`,
}
var routes = []Route{ProbeRoute, HealthRoute, StatsRoute, RulesRoute, WhitelistRoute, CommitRoute, AtomicRoute, SyncWLRoute}

func callRoute(c *Client, route Route) *CallError {
	ctx := context.Background()
	switch route {
	case ProbeRoute:
		_, e := c.Probe(ctx)
		return e
	case HealthRoute:
		_, e := c.Health(ctx)
		return e
	case StatsRoute:
		_, e := c.Stats(ctx)
		return e
	case RulesRoute:
		_, e := c.Rules(ctx, 1, 1000)
		return e
	case WhitelistRoute:
		_, e := c.Whitelist(ctx)
		return e
	case CommitRoute:
		_, e := c.Commit(ctx, []byte(`{"groups":[]}`), 1)
		return e
	case AtomicRoute:
		_, e := c.Atomic(ctx, []byte(`{"rules":[]}`))
		return e
	default:
		_, e := c.SyncWhitelist(ctx, []byte(`{"entries":[]}`))
		return e
	}
}

type countReader struct {
	size, read int64
	prefix     string
}

func (r *countReader) Read(p []byte) (int, error) {
	if r.read == r.size {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.size-r.read)
	for i := int64(0); i < n; i++ {
		p[i] = ' '
		if r.read+i < int64(len(r.prefix)) {
			p[i] = r.prefix[r.read+i]
		}
	}
	r.read += n
	return int(n), nil
}

func TestCtlCut2(t *testing.T) {
	t.Run("NC-routes", func(t *testing.T) {
		seen := map[Route]int{}
		c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) {
			route := Route(r.URL.Path)
			seen[route]++
			wantKey := "cut2-test-secret"
			if route == ProbeRoute || route == HealthRoute {
				wantKey = ""
			}
			if r.Header.Get("X-API-Key") != wantKey {
				t.Error("authentication header mismatch")
			}
			wantMethod := "GET"
			wantBody := ""
			switch route {
			case CommitRoute:
				wantMethod = "POST"
				wantBody = `{"groups":[]}`
			case AtomicRoute:
				wantMethod = "POST"
				wantBody = `{"rules":[]}`
			case SyncWLRoute:
				wantMethod = "POST"
				wantBody = `{"entries":[]}`
			}
			body, _ := io.ReadAll(r.Body)
			if r.Method != wantMethod || string(body) != wantBody {
				t.Errorf("method/body %s %s", r.Method, body)
			}
			query := ""
			if route == RulesRoute {
				query = "page=1&limit=1000"
			}
			if r.URL.RawQuery != query {
				t.Errorf("query=%s", r.URL.RawQuery)
			}
			io.WriteString(w, routeBodies[route])
		}), Options{})
		for _, route := range routes {
			if e := callRoute(c, route); e != nil {
				t.Fatal(e)
			}
		}
		if len(seen) != 8 {
			t.Fatalf("routes=%d", len(seen))
		}
		for _, n := range seen {
			if n != 1 {
				t.Fatal(seen)
			}
		}
	})
	t.Run("NC-probe", func(t *testing.T) {
		cases := []struct {
			name, body string
			status     int
			want       ProbeResult
		}{
			{"integer", `{"sync_protocol":11}`, 200, OK}, {"string", `{"sync_protocol":"9"}`, 200, Incompatible}, {"decimal", `{"sync_protocol":9.0}`, 200, Incompatible},
			{"exponent", `{"sync_protocol":1e1}`, 200, Incompatible}, {"negative", `{"sync_protocol":-9}`, 200, Incompatible}, {"overflow", `{"sync_protocol":99999999999999999999}`, 200, Incompatible},
			{"missing", `{}`, 200, Incompatible}, {"duplicate", `{"sync_protocol":9,"sync_protocol":8}`, 200, Incompatible}, {"large", strings.Repeat(" ", 65537), 200, Incompatible},
			{"text", `not JSON`, 200, Incompatible}, {"server", `{}`, 500, Unreachable}, {"transport", ``, 0, Unreachable}, {"redirect", `{}`, 307, Unreachable}, {"not-200", `{"sync_protocol":9}`, 201, Unreachable},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				c := testClient(t, transportFunc(func(r *http.Request) (*http.Response, error) {
					if tc.status == 0 {
						return nil, errors.New("offline")
					}
					w := httptest.NewRecorder()
					w.WriteHeader(tc.status)
					io.WriteString(w, tc.body)
					return w.Result(), nil
				}), Options{})
				got, _ := c.Probe(context.Background())
				if got != tc.want {
					t.Fatalf("got %s want %s", got, tc.want)
				}
			})
		}
	})
	t.Run("NC-limit", func(t *testing.T) {
		// Independent PLAN §4-2 constants/formulas, never Client.limit.
		limits := map[Route]int64{ProbeRoute: 64 << 10, HealthRoute: 64 << 10, StatsRoute: 1 << 20, RulesRoute: 16 << 20, WhitelistRoute: 32 << 20, SyncWLRoute: 1 << 20}
		cases := []struct {
			name   string
			route  Route
			body   []byte
			groups int
		}{}
		for _, route := range routes {
			cases = append(cases, struct {
				name   string
				route  Route
				body   []byte
				groups int
			}{string(route), route, []byte(`{"rules":[]}`), 1})
		}
		cases = append(cases, struct {
			name   string
			route  Route
			body   []byte
			groups int
		}{"atomic-scaled", AtomicRoute, []byte(`{"rules":[],"padding":"` + strings.Repeat(" ", 3<<20) + `"}`), 0}, struct {
			name   string
			route  Route
			body   []byte
			groups int
		}{"commit-scaled", CommitRoute, []byte(`{"groups":[]}`), 1000})
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				limit := limits[tc.route]
				if tc.route == CommitRoute {
					limit = 4<<20 + 64*int64(tc.groups)
				}
				if tc.route == AtomicRoute {
					limit = max(4<<20, 2*int64(len(tc.body)))
				}
				for _, size := range []struct {
					name  string
					bytes int64
				}{{"exact", limit}, {"plus-one", limit + 1}, {"double", 2 * limit}} {
					size := size
					t.Run(size.name, func(t *testing.T) {
						var reader *countReader
						c := testClient(t, transportFunc(func(r *http.Request) (*http.Response, error) {
							return &http.Response{StatusCode: 200, Body: io.NopCloser(reader), Header: make(http.Header)}, nil
						}), Options{})
						reader = &countReader{size: size.bytes, prefix: routeBodies[tc.route]}
						var out map[string]any
						e := c.call(context.Background(), tc.route, "", tc.body, tc.groups, &out)
						if size.bytes > limit {
							if e == nil || e.Kind != "too_large" {
								t.Fatalf("error=%v", e)
							}
							if reader.read > limit+1 {
								t.Fatalf("consumed=%d limit=%d", reader.read, limit)
							}
						} else {
							if e != nil || reader.read != limit {
								t.Fatalf("error=%v consumed=%d limit=%d", e, reader.read, limit)
							}
						}
					})
				}
			})
		}
	})
	t.Run("NC-shape", nestedShapeTests)
	t.Run("NC-dupkey", func(t *testing.T) {
		for _, route := range []Route{CommitRoute, AtomicRoute, StatsRoute} {
			route := route
			t.Run(string(route), func(t *testing.T) {
				body := strings.TrimSuffix(routeBodies[route], "}") + `,"extra":{"x":1,"x":2}}`
				c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }), Options{})
				if e := callRoute(c, route); e == nil || e.Kind != "invalid" {
					t.Fatalf("error=%v", e)
				}
			})
		}
	})
	t.Run("NC-redirect", func(t *testing.T) {
		target := 0
		c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/target" {
				target++
				io.WriteString(w, routeBodies[StatsRoute])
				return
			}
			w.Header().Set("Location", "/target")
			w.WriteHeader(307)
		}), Options{})
		_, e := c.Stats(context.Background())
		if e == nil || e.Kind != "redirect" || target != 0 {
			t.Fatalf("error=%v targets=%d", e, target)
		}
	})
	t.Run("NC-timeout", func(t *testing.T) {
		for _, route := range routes {
			route := route
			t.Run(string(route), func(t *testing.T) {
				opts := Options{Timeouts: map[Route]time.Duration{route: 50 * time.Millisecond}}
				c := testClient(t, transportFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() }), opts)
				start := time.Now()
				e := callRoute(c, route)
				if e == nil || e.Kind != "timeout" || time.Since(start) >= time.Second || time.Since(start) < 40*time.Millisecond {
					t.Fatalf("error=%v elapsed=%s", e, time.Since(start))
				}
			})
		}
	})
	t.Run("NC-secret", func(t *testing.T) {
		c := testClient(t, handlerRT(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			io.WriteString(w, `{"code":"cut2-test-secret","error":"cut2-test-secret","nested":{"cut2-test-secret":"cut2-test-secret"}}`)
		}), Options{})
		_, e := c.Atomic(context.Background(), []byte(`{"rules":[]}`))
		if e == nil {
			t.Fatal("expected failure")
		}
		for _, v := range []any{*c, c, NodeSpec{Name: "n", Key: Secret("cut2-test-secret")}, e, fmt.Errorf("wrapped: %w", e)} {
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if strings.Contains(fmt.Sprintf(format, v), "cut2-test-secret") {
					t.Fatal("secret in formatted object")
				}
			}
			b, err := json.Marshal(v)
			if err != nil || strings.Contains(string(b), "cut2-test-secret") {
				t.Fatal("secret in JSON or encoding failure")
			}
		}
	})
}
