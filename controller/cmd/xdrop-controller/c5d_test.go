package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/api"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/config"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c5dCloserFunc func()

func (f c5dCloserFunc) Close() { f() }

type c5dHubHolder struct{ hub *api.Hub }

func (h *c5dHubHolder) Close() {
	if h.hub != nil {
		h.hub.Close()
	}
}

type c5dPipes struct {
	conns chan net.Conn
	stop  chan struct{}
	once  sync.Once
}

func (l *c5dPipes) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.stop:
		return nil, net.ErrClosed
	}
}
func (l *c5dPipes) Close() error   { l.once.Do(func() { close(l.stop) }); return nil }
func (l *c5dPipes) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

type c5dWritingConn struct {
	net.Conn
	entered chan struct{}
}

func (c *c5dWritingConn) Write(b []byte) (int, error) {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	return c.Conn.Write(b)
}
func c5dSignal(t *testing.T, c <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout", name)
	}
}
func c5dDatabase(t *testing.T) (config.Config, string) {
	t.Helper()
	cfg := config.Config{Listen: "127.0.0.1:18081", Database: filepath.Join(t.TempDir(), "controller.db"), SecretKeyFile: c5bMasterFile(t)}
	db, e := store.Open(cfg.Database)
	c4aAssert(t, e == nil, "seed database")
	acc := auth.New(db)
	c4aAssert(t, acc.CreateUser(rules.Actor{Kind: rules.System, Name: "test"}, "alice", "TEST_ONLY_PASSWORD", "admin") == nil, "seed user")
	cookie, _, failure := acc.Login("alice", "TEST_ONLY_PASSWORD", "127.0.0.1")
	c4aAssert(t, failure == nil && db.Close() == nil, "seed session")
	return cfg, cookie
}
func TestC5DAssembly(t *testing.T) {
	for _, mode := range []string{"production-open", "override-open", "partial-body", "closed-retry"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			cfg, cookie := c5dDatabase(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := defaults()
			box := &c5dHubHolder{}
			ready := make(chan struct{})
			var returns atomic.Int64
			if mode == "override-open" || mode == "closed-retry" {
				a.hub = box
				a.api = func(s *rules.Service, n api.Nodes, acc *auth.Service) http.Handler {
					e, h := api.NewWithHub(s, n, api.AccountAuthenticator(acc), nil, api.Options{Accounts: acc})
					box.hub = h
					return e
				}
			}
			srv := &http.Server{}
			a.server = func(_ string, h http.Handler) server {
				srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer returns.Add(1)
					defer http.NewResponseController(w).Flush()
					h.ServeHTTP(w, r)
				})
				close(ready)
				return srv
			}
			listener := &c5dPipes{conns: make(chan net.Conn), stop: make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- assemble(ctx, cfg, listener, a) }()
			c5dSignal(t, ready, "assembly server")
			t.Cleanup(func() { cancel(); srv.Close() })
			if mode == "closed-retry" {
				box.hub.Close()
			}
			count := 1
			if strings.HasSuffix(mode, "-open") {
				count = 3
			}
			for i := 0; i < count; i++ {
				client, server := net.Pipe()
				defer client.Close()
				wire := &c5dWritingConn{server, make(chan struct{}, 32)}
				listener.conns <- wire
				request := "GET /api/v1/events HTTP/1.1\r\nHost: example.invalid\r\nCookie: " + auth.CookieName + "=" + cookie + "\r\n"
				if mode == "partial-body" {
					request += "Content-Length: 10\r\n\r\nab"
				} else {
					request += "\r\n"
				}
				_, err := io.WriteString(client, request)
				c4aAssert(t, err == nil, "pipe request")
				if strings.HasSuffix(mode, "-open") {
					response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "GET"})
					c4aAssert(t, err == nil && response.StatusCode == 200, "open stream status")
					b := make([]byte, len("retry: 3000\n\n"))
					_, err = io.ReadFull(response.Body, b)
					c4aAssert(t, err == nil && string(b) == "retry: 3000\n\n", "live prelude")
				} else {
					c5dSignal(t, wire.entered, "underlying blocked response write")
				}
			}
			c4aAssert(t, returns.Load() == 0, "handlers were not open")
			began := time.Now()
			cancel()
			select {
			case err := <-done:
				c4aAssert(t, err == nil && time.Since(began) < 3*time.Second, fmt.Sprint("assembly shutdown ", err, " ", time.Since(began)))
			case <-time.After(3 * time.Second):
				t.Fatal("assembly exceeded 3s")
			}
			c4aAssert(t, returns.Load() == int64(count), fmt.Sprint("handler return count ", returns.Load(), " ", count))
			t.Logf("branch=%s open_streams=%d handler_returns=%d shutdown=%s result=nil", mode, count, returns.Load(), time.Since(began))
		})
	}
}
func TestC5DStatic(t *testing.T) {
	cfg, cookie := c5dDatabase(t)
	db, err := store.Open(cfg.Database)
	c4aAssert(t, err == nil, "static database")
	defer db.Close()
	acc := auth.New(db)
	steps := []string{}
	n := fakeManager{&steps}
	s := rules.New(db, n)
	e, h := api.NewWithHub(s, n, api.AccountAuthenticator(acc), nil, api.Options{Accounts: acc})
	defer h.Close()
	handler := combineHandlers(e, nil)
	for _, v := range []struct {
		method, path string
		status       int
	}{{"GET", "/", 200}, {"HEAD", "/", 200}, {"GET", "/rules/123", 200}, {"GET", "/index.html", 200}, {"GET", "/missing.js", 404}, {"POST", "/", 405}} {
		v := v
		t.Run(v.method+v.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(v.method, v.path, nil))
			c4aAssert(t, w.Code == v.status && w.Header().Get("X-Content-Type-Options") == "nosniff" && w.Header().Get("X-Frame-Options") == "DENY", "static status/security headers")
			if v.status == 200 {
				c4aAssert(t, w.Header().Get("Cache-Control") == "no-cache", "index cache")
				if v.method != "HEAD" {
					c4aAssert(t, strings.Contains(w.Body.String(), "xdrop console") && strings.Contains(w.Body.String(), "前端未构建"), "placeholder")
				}
			} else {
				c4aAssert(t, strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain"), "plain text error")
			}
		})
	}
	for _, authenticated := range []bool{false, true} {
		authenticated := authenticated
		t.Run(map[bool]string{false: "api-anonymous-404", true: "api-authenticated-404"}[authenticated], func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/nope", nil)
			want := 401
			if authenticated {
				r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
				want = 404
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			c4aAssert(t, w.Code == want && strings.HasPrefix(w.Header().Get("Content-Type"), "application/json"), "API prefix routing")
		})
	}
	t.Run("api-post", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/v1/rules", strings.NewReader(`{"dst_ip":"192.0.2.10"}`))
		r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		rows, failure := s.List()
		c4aAssert(t, w.Code == 201 && failure == nil && len(rows) == 1, fmt.Sprint("combined handler API POST ", w.Code))
		t.Log("combined_api_post_status=201 committed_rules=1")
	})
}
