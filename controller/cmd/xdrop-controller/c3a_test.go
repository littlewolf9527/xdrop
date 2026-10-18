package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/api"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/config"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/secret"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

type fakeManager struct{ steps *[]string }

func (m fakeManager) AddNode(nc.NodeSpec) error { return nil }
func (m fakeManager) RemoveNode(string)         {}

func (m fakeManager) Changed(rules.Change)      {}
func (m fakeManager) Status() []orch.NodeStatus { return nil }
func (m fakeManager) ForceSync(string)          {}
func (m fakeManager) ReconcileNow(string)       {}
func (m fakeManager) Start(*rules.Service)      { *m.steps = append(*m.steps, "start") }
func (m fakeManager) Stop()                     { *m.steps = append(*m.steps, "stop") }

type fakeServer struct {
	steps       *[]string
	shutdownErr error
}

func (s fakeServer) Serve(net.Listener) error {
	*s.steps = append(*s.steps, "serve")
	return http.ErrServerClosed
}
func (s fakeServer) ListenAndServe() error { return s.Serve(nil) }
func (s fakeServer) Shutdown(ctx context.Context) error {
	*s.steps = append(*s.steps, "shutdown")
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second {
		return errors.New("missing bounded shutdown")
	}
	return s.shutdownErr
}
func TestCtlCut3Main(t *testing.T) {
	fixture := func(cfg config.Config, prepareErr, shutdownErr, closeErr error, violations bool) ([]string, error, time.Duration) {
		steps := []string{}
		var interval time.Duration
		add := func(s string) { steps = append(steps, s) }
		cfg.SecretKeyFile = c5bMasterFile(t)
		savedMaster, savedNodes := readMaster, readNodes
		defer func() { readMaster, readNodes = savedMaster, savedNodes }()
		readMaster = func(path string) (*secret.Key, error) { add("master_key"); return savedMaster(path) }
		readNodes = func(q store.Queryer) ([]store.Node, error) { add("nodes"); return savedNodes(q) }
		a := assembly{
			static: http.NotFoundHandler(),
			hub:    c5dCloserFunc(func() {}),
			open: func(path string) (*store.DB, error) {
				add("open")
				if path == "" {
					path = filepath.Join(t.TempDir(), "main.db")
				}
				db, err := store.Open(path)
				if err == nil {
					t.Cleanup(func() { db.Close() })
				}
				return db, err
			},
			prepare: func(*store.DB) (rules.Report, error) {
				add("prepare")
				r := rules.Report{}
				if violations {
					r.Violations = []rules.Violation{{ID: "a", Reason: "invalid"}, {ID: "b", Reason: "invalid"}}
				}
				return r, prepareErr
			},
			manager: func(_ []nc.NodeSpec, o orch.Options) manager {
				add("manager")
				interval = o.ReconcileInterval
				return fakeManager{&steps}
			},
			service: func(*store.DB, rules.ChangeSink, ...func() []rules.DeliveryNode) *rules.Service {
				add("service")
				return nil
			},
			api: func(_ *rules.Service, _ api.Nodes, auth *auth.Service) http.Handler {
				add("api")
				if auth == nil {
					t.Error("missing authenticator")
				}
				return http.NotFoundHandler()
			},
			server: func(string, http.Handler) server { add("server"); return fakeServer{&steps, shutdownErr} },
			close:  func(*store.DB) error { add("close"); return closeErr },
		}
		err := assemble(context.Background(), cfg, nil, a)
		return steps, err, interval
	}
	t.Run("MAIN-order", func(t *testing.T) {
		failure := errors.New("injected lifecycle failure")
		for _, test := range []struct {
			prepare, shutdown, close error
			violations               bool
		}{{}, {prepare: failure}, {shutdown: failure}, {close: failure}, {violations: true}} {
			steps, err, _ := fixture(config.Config{}, test.prepare, test.shutdown, test.close, test.violations)
			want := []string{"open", "prepare", "master_key", "nodes", "manager", "service", "start", "api", "server", "serve", "shutdown", "stop", "close"}
			if test.prepare != nil || test.violations {
				want = []string{"open", "prepare", "close"}
			}
			if !reflect.DeepEqual(steps, want) {
				t.Errorf("sequence %v want %v", steps, want)
			}
			wantErr := test.prepare != nil || test.shutdown != nil || test.close != nil || test.violations
			if (err != nil) != wantErr {
				t.Errorf("error=%v wantError=%v", err, wantErr)
			}
		}
	})
	t.Run("CF-orch", func(t *testing.T) {
		dir := t.TempDir()
		key := filepath.Join(dir, "key")
		path := filepath.Join(dir, "config.example.yaml")
		if e := os.WriteFile(key, []byte("sentinel"), 0600); e != nil {
			t.Fatal(e)
		}
		text := "listen: 192.0.2.1:80\ndatabase: " + filepath.Join(dir, "db") + "\nsecret_key_file: " + key + "\n"
		if e := os.WriteFile(path, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		cfg, e := config.Load(path)
		if e != nil {
			t.Fatal(e)
		}
		db, e := store.Open(cfg.Database)
		if e != nil {
			t.Fatal(e)
		}
		if e = store.SetReconcileIntervalMinutes(db, 7); e != nil {
			t.Fatal(e)
		}
		if e = db.Close(); e != nil {
			t.Fatal(e)
		}
		_, e, interval := fixture(cfg, nil, nil, nil, false)
		if e != nil || interval != 7*time.Minute {
			t.Fatalf("actual orch option %v %v", interval, e)
		}
	})
}
