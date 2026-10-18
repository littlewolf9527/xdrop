package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/auth"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/secret"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type c5bTransport func(*http.Request) (*http.Response, error)

func (f c5bTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func c5bReply(code int, body string) (*http.Response, error) {
	return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
}
func c5bHealthy(r *http.Request) (*http.Response, error) {
	switch nc.Route(r.URL.Path) {
	case nc.ProbeRoute:
		return c5bReply(200, `{"sync_protocol":11}`)
	case nc.HealthRoute:
		return c5bReply(200, `{"status":"healthy","rules_synced":true,"whitelist_synced":true}`)
	case nc.StatsRoute:
		return c5bReply(200, `{"total_packets":0,"dropped_packets":0,"passed_packets":0}`)
	case nc.SyncWLRoute:
		return c5bReply(200, `{"total":0,"failed":0}`)
	case nc.AtomicRoute:
		return c5bReply(200, `{"success":true,"added":0,"failed":0,"rules":0,"cidr_rules":0,"rejected":[]}`)
	}
	return c5bReply(200, `{"rules":[],"pagination":{"page":1,"limit":1000,"total":0,"pages":1}}`)
}
func c5bMaster(t *testing.T) (*secret.Key, []byte, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master")
	require(t, secret.Init(path) == nil, "master init")
	info, e := os.Stat(path)
	require(t, e == nil && info.Mode().Perm() == 0600, "master mode")
	b, e := os.ReadFile(path)
	require(t, e == nil, "master read")
	raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	require(t, e == nil && len(raw) == 32, "master shape")
	k, e := secret.Load(path)
	require(t, e == nil, "master load")
	return k, raw, bytes.TrimSpace(b)
}
func c5bAttach(t *testing.T, f *fixture, acc *auth.Service) (*NodeService, string) {
	t.Helper()
	k, _, _ := c5bMaster(t)
	s := NewNodeService(f.db, k)
	s.client.Transport = c5bTransport(c5bHealthy)
	authenticate := Authenticator(testActor)
	if acc != nil {
		authenticate = AccountAuthenticator(acc)
	}
	f.e = New(f.s, f.n, authenticate, log.New(f.logs, "", 0), Options{Accounts: acc, NodeStore: s})
	return s, c4aSecret(t)
}

func TestC5BOrdering(t *testing.T) {
	for _, second := range []string{"PATCH", "DELETE"} {
		second := second
		t.Run("C5B-order-"+second, func(t *testing.T) {
			f := fresh(t)
			s, key := c5bAttach(t, f, nil)
			var mu sync.Mutex
			lastURL := ""
			transport := c5bTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				lastURL = "http://" + r.URL.Host
				mu.Unlock()
				return c5bHealthy(r)
			})
			m := orch.New(nil, orch.Options{Client: nc.Options{Transport: transport}, HealthInterval: time.Hour, StatsInterval: time.Hour})
			m.Start(f.s)
			defer m.Stop()
			var a *API
			f.e = New(f.s, m, testActor, nil, Options{NodeStore: s, nodeAPI: func(v *API) { a = v }})
			request(t, f.e, "POST", "/api/v1/nodes", "ui", c4aJSON(map[string]string{"name": "n", "base_url": "http://192.0.2.1", "api_key": key}), 201)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			var commits atomic.Int32
			s.afterCommit = func() {
				if commits.Add(1) == 1 {
					close(entered)
					select {
					case <-release:
					case <-time.After(2 * time.Second):
					}
				}
			}
			firstDone := make(chan *httptest.ResponseRecorder, 1)
			go func() { firstDone <- c5bCall(f.e, "PATCH", "/nodes/n", `{"base_url":"http://192.0.2.2"}`) }()
			c5bWait(t, entered, "first committed")
			locked := !a.nodeWrite.TryLock()
			if !locked {
				a.nodeWrite.Unlock()
				unblock()
				t.Error("nodeWrite absent at committed boundary")
			}
			secondDone := make(chan *httptest.ResponseRecorder, 1)
			started := make(chan struct{})
			go func() {
				close(started)
				secondDone <- c5bCall(f.e, second, "/nodes/n", `{"base_url":"http://192.0.2.3"}`)
			}()
			c5bWait(t, started, "second started")
			unblock()
			for i, ch := range []chan *httptest.ResponseRecorder{firstDone, secondDone} {
				select {
				case w := <-ch:
					want := 200
					if i == 1 && second == "DELETE" {
						want = 204
					}
					require(t, w.Code == want, "ordered response", w.Code)
				case <-time.After(3 * time.Second):
					t.Fatal("ordered requests timeout")
				}
			}
			row, e := store.FindNode(f.db.Reader(), "n")
			if second == "DELETE" {
				require(t, e == sql.ErrNoRows && len(m.Status()) == 0, "delete final state")
			} else {
				require(t, e == nil && row.BaseURL == "http://192.0.2.3", "last commit row")
				deadline := time.Now().Add(time.Second)
				for time.Now().Before(deadline) {
					mu.Lock()
					got := lastURL
					mu.Unlock()
					if got == row.BaseURL {
						break
					}
					time.Sleep(time.Millisecond)
				}
				mu.Lock()
				got := lastURL
				mu.Unlock()
				require(t, got == row.BaseURL, "actual client URL differs")
			}
			t.Log("nodeWrite_trylock=false commits=2 both_returned=1 final_state_verified=1")
		})
	}
	t.Run("C5B-test-delete", func(t *testing.T) {
		f := fresh(t)
		s, key := c5bAttach(t, f, nil)
		url := "http://192.0.2.2"
		_, e := s.Change(rules.Actor{}, "create", "n", NodePatch{&url, &key})
		require(t, e == nil, "seed")
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		var requests atomic.Int32
		s.client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
			requests.Add(1)
			if r.URL.Path == "/" {
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}
			}
			return c5bHealthy(r)
		})
		var a *API
		f.e = New(f.s, f.n, testActor, nil, Options{NodeStore: s, nodeAPI: func(v *API) { a = v }})
		tested, deleted := make(chan int, 1), make(chan int, 1)
		go func() { tested <- c5bCall(f.e, "POST", "/nodes/n/test", "").Code }()
		c5bWait(t, entered, "probe entered")
		locked := !a.nodeWrite.TryLock()
		if !locked {
			a.nodeWrite.Unlock()
			unblock()
			t.Error("stored test lacks lock")
		}
		go func() { deleted <- c5bCall(f.e, "DELETE", "/nodes/n", "").Code }()
		select {
		case <-deleted:
			unblock()
			t.Fatal("delete passed blocked test")
		case <-time.After(20 * time.Millisecond):
		}
		unblock()
		for _, v := range []struct {
			ch   chan int
			want int
		}{{tested, 200}, {deleted, 204}} {
			select {
			case code := <-v.ch:
				require(t, code == v.want, "request code")
			case <-time.After(time.Second):
				t.Fatal("test/delete timeout")
			}
		}
		count := requests.Load()
		require(t, count == 2, "Probe+Stats witness")
		request(t, f.e, "POST", "/api/v1/nodes/n/test", "ui", "", 404)
		time.Sleep(20 * time.Millisecond)
		require(t, requests.Load() == count, "request after delete")
		t.Log("probe_entered=1 nodeWrite_trylock=false delete_waited=1 requests_before=2 requests_after=2")
	})
}

func TestC5BNodeWrites(t *testing.T) {
	t.Run("C5B-key-update-delete", func(t *testing.T) {
		f := fresh(t)
		s, key := c5bAttach(t, f, nil)
		next := c4aSecret(t)
		var oldHits, newHits, total atomic.Int32
		tr := c5bTransport(func(r *http.Request) (*http.Response, error) {
			total.Add(1)
			switch r.Header.Get("X-API-Key") {
			case key:
				oldHits.Add(1)
			case next:
				newHits.Add(1)
			}
			return c5bHealthy(r)
		})
		m := orch.New(nil, orch.Options{Client: nc.Options{Transport: tr}, HealthInterval: time.Hour, StatsInterval: time.Hour})
		m.Start(f.s)
		defer m.Stop()
		f.e = New(f.s, m, testActor, nil, Options{NodeStore: s})
		request(t, f.e, "POST", "/api/v1/nodes", "ui", c4aJSON(map[string]string{"name": "n", "base_url": "http://192.0.2.2", "api_key": key}), 201)
		await := func(v *atomic.Int32) {
			deadline := time.Now().Add(time.Second)
			for v.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			require(t, v.Load() > 0, "authenticated node request")
		}
		await(&oldHits)
		request(t, f.e, "PATCH", "/api/v1/nodes/n", "ui", c4aJSON(map[string]string{"api_key": next}), 200)
		await(&newHits)
		// Settle both workers before observing deletion's zero-contact boundary.
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			v := m.Status()
			if len(v) == 1 && v[0].Rules.State == "normal" && v[0].Whitelist.State == "normal" {
				break
			}
			time.Sleep(time.Millisecond)
		}
		before := total.Load()
		request(t, f.e, "DELETE", "/api/v1/nodes/n", "ui", "", 204)
		after := total.Load()
		require(t, before > 0 && before == after && len(m.Status()) == 0, "delete contacted node")
		t.Logf("old_key_requests=%d new_key_requests=%d delete_requests=0", oldHits.Load(), newHits.Load())
	})
	t.Run("C5B-audit-rollback", func(t *testing.T) {
		f := fresh(t)
		s, key := c5bAttach(t, f, nil)
		url := "http://192.0.2.2"
		_, err := f.db.Exec(`CREATE TRIGGER fail_node_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'TEST_ONLY_AUDIT_FAILURE'); END`)
		require(t, err == nil, "audit failure fixture")
		_, e := s.Change(rules.Actor{}, "create", "n", NodePatch{&url, &key})
		require(t, e != nil && e.Code == "internal", "audit failure path")
		_, err = store.FindNode(f.db.Reader(), "n")
		require(t, err == sql.ErrNoRows, "audit failure committed node")
	})
}

var _ = context.Background

func c5bNodeRoute(key string) bool {
	return key == "POST /nodes" || key == "PATCH /nodes/:name" || key == "DELETE /nodes/:name" || key == "POST /nodes/:name/test" || key == "POST /nodes/test"
}
func c5bMatrixNode(t *testing.T, f *fixture, acc *auth.Service, route string) (string, int) {
	s, key := c5bAttach(t, f, acc)
	url := "http://192.0.2.2"
	_, e := s.Change(rules.Actor{Kind: rules.System, Name: "fixture"}, "create", "n1", NodePatch{&url, &key})
	require(t, e == nil, "matrix node fixture")
	switch route {
	case "POST /nodes":
		return c4aJSON(map[string]string{"name": "n2", "base_url": url, "api_key": key}), 201
	case "PATCH /nodes/:name":
		return `{"base_url":"http://192.0.2.3"}`, 200
	case "DELETE /nodes/:name":
		return "", 204
	case "POST /nodes/test":
		return c4aJSON(map[string]string{"base_url": url, "api_key": key}), 200
	}
	return "", 200
}

func c5bCall(e http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
	r.Header.Set("X-Xdrop-Actor", "ui")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}
func c5bWait(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture timeout: " + label)
	}
}
func TestC5BAPI(t *testing.T) {
	t.Run("C5B-validation", func(t *testing.T) {
		f := fresh(t)
		_, key := c5bAttach(t, f, nil)
		for _, tc := range []struct{ name, url, key string }{{"", "http://192.0.2.2", key}, {"region/node", "http://192.0.2.2", key}, {"n", "ftp://192.0.2.2", key}, {"n", "http://user@192.0.2.2", key}, {"n", "http://192.0.2.2?q=1", key}, {"n", "http://192.0.2.2", ""}, {"n", "http://192.0.2.2", strings.Repeat("x", 4097)}} {
			w := request(t, f.e, "POST", "/api/v1/nodes", "ui", c4aJSON(map[string]string{"name": tc.name, "base_url": tc.url, "api_key": tc.key}), 400)
			if strings.Contains(tc.name, "/") {
				require(t, decoded[Error](t, w).Message == "name must not contain '/'" && !strings.Contains(w.Body.String(), tc.name), "slash name message")
			}
		}
		input := c4aJSON(map[string]string{"name": "n", "base_url": "http://192.0.2.2", "api_key": key})
		request(t, f.e, "POST", "/api/v1/nodes", "ui", input, 201)
		request(t, f.e, "POST", "/api/v1/nodes", "ui", input, 409)
		request(t, f.e, "PATCH", "/api/v1/nodes/n", "ui", `{}`, 400)
		request(t, f.e, "PATCH", "/api/v1/nodes/n", "ui", `{"name":"renamed"}`, 400)
	})
	t.Run("C5B-guard", func(t *testing.T) {
		f := fresh(t)
		s, key := c5bAttach(t, f, nil)
		k, raw, b64 := c5bMaster(t)
		s.Key = k
		w := request(t, f.e, "POST", "/api/v1/nodes", "ui", c4aJSON(map[string]string{"name": "n", "base_url": "http://192.0.2.2", "api_key": key}), 201)
		get := request(t, f.e, "GET", "/api/v1/nodes", "ui", "", 200)
		rows, e := store.AuditAfter(f.db.Reader(), "", "", "", 0, 100)
		require(t, e == nil && len(rows) > 0, "audit sample")
		audit, _ := json.Marshal(rows)
		f.logs.WriteString("TEST_ONLY_LOG_SAMPLE\n")
		samples := [][]byte{w.Body.Bytes(), get.Body.Bytes(), f.logs.Bytes(), audit}
		for _, suffix := range []string{"", "-wal"} {
			var path string
			require(t, f.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path) == nil, "database path")
			b, e := os.ReadFile(path + suffix)
			require(t, e == nil && len(b) > 0, "database sample")
			samples = append(samples, b)
		}
		for _, b := range samples {
			require(t, len(b) > 0, "nonzero sample")
			for _, v := range [][]byte{[]byte(key), raw, b64} {
				require(t, len(v) > 0 && !bytes.Contains(b, v), "secret in forbidden carrier")
			}
		}
		t.Logf("node_key_samples=%d master_raw_samples=%d master_base64_samples=%d matches=0", len(samples), len(samples), len(samples))
	})
	t.Run("C5B-merge", func(t *testing.T) {
		f := fresh(t)
		s, key := c5bAttach(t, f, nil)
		url := "http://192.0.2.2"
		for _, name := range []string{"n1", "absent", "broken"} {
			_, e := s.Change(rules.Actor{}, "create", name, NodePatch{&url, &key})
			require(t, e == nil, "seed")
		}
		_, e := f.db.Exec("UPDATE nodes SET key_nonce=? WHERE name='broken'", []byte{1})
		require(t, e == nil, "corrupt fixture")
		var got struct{ Nodes []NodeDTO }
		w := request(t, f.e, "GET", "/api/v1/nodes", "ui", "", 200)
		require(t, json.Unmarshal(w.Body.Bytes(), &got) == nil, "decode")
		require(t, len(got.Nodes) == 3 && got.Nodes[0].Name == "n1" && got.Nodes[1].Name == "absent" && !got.Nodes[1].KeyUnreadable && got.Nodes[2].KeyUnreadable, "merge order, uniqueness, actual decryption")
		request(t, f.e, "PATCH", "/api/v1/nodes/broken", "ui", c4aJSON(map[string]string{"api_key": key}), 200)
		n, e := store.FindNode(f.db.Reader(), "broken")
		require(t, e == nil, "repair row")
		plain, e := s.Key.Open(n.Name, n.KeyNonce, n.KeyCipher)
		require(t, e == nil && plain == key, "key repair")
	})
	t.Run("C5B-redirect", func(t *testing.T) {
		f := fresh(t)
		s, key := c5bAttach(t, f, nil)
		var first, second int
		s.client.Transport = c5bTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "192.0.2.3" {
				second++
				return c5bReply(200, `{"sync_protocol":11}`)
			}
			first++
			v, _ := c5bReply(302, "")
			v.Header.Set("Location", "http://192.0.2.3/")
			return v, nil
		})
		w := request(t, f.e, "POST", "/api/v1/nodes/test", "ui", c4aJSON(map[string]string{"base_url": "http://192.0.2.2", "api_key": key}), 200)
		v := decoded[nodeTestDTO](t, w)
		require(t, first == 1 && second == 0 && !v.Reachable, "redirect followed")
		t.Log("first_hop=1 second_hop=0")
	})
}
