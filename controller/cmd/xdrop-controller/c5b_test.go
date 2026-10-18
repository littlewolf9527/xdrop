package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/littlewolf9527/xdrop/controller/core/api"
	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/config"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
	"github.com/littlewolf9527/xdrop/controller/core/orch"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
	"github.com/littlewolf9527/xdrop/controller/core/secret"
	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func c5bMasterFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "master")
	c4aAssert(t, secret.Init(p) == nil, "master fixture")
	info, e := os.Stat(p)
	c4aAssert(t, e == nil && info.Mode().Perm() == 0600, "master mode")
	return p
}
func c5bCommand(t *testing.T, path string, args []string, input string) (int, []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stdin")
	c4aAssert(t, os.WriteFile(p, []byte(input), 0600) == nil, "stdin fixture")
	f, e := os.Open(p)
	c4aAssert(t, e == nil, "open stdin")
	defer f.Close()
	var out bytes.Buffer
	saved := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(saved)
	rc := nodeCommand(args, path, f, &out)
	cfg, e := config.Load(path)
	c4aAssert(t, e == nil, "CLI scan configuration")
	encoded, e := os.ReadFile(cfg.SecretKeyFile)
	c4aAssert(t, e == nil, "CLI master sample")
	encoded = bytes.TrimSpace(encoded)
	raw, e := base64.StdEncoding.DecodeString(string(encoded))
	c4aAssert(t, e == nil && len(raw) == 32, "CLI raw master sample")
	sample := append([]byte("TEST_ONLY_CLI_LOG_SAMPLE"), out.Bytes()...)
	c4aAssert(t, len(sample) > 0 && !bytes.Contains(sample, raw) && !bytes.Contains(sample, encoded), "CLI master leak")
	t.Logf("cli_output_samples=1 master_raw_samples=1 master_base64_samples=1 sample_bytes=%d matches=0", len(sample))
	return rc, out.Bytes()
}

type c5bRoundTrip func(*http.Request) (*http.Response, error)

func (f c5bRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestC5BCLI(t *testing.T) {
	var commandLogs bytes.Buffer
	savedLog := log.Writer()
	log.SetOutput(&commandLogs)
	defer log.SetOutput(savedLog)
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.example.yaml")
	master := filepath.Join(dir, "master")
	dbpath := filepath.Join(dir, "db")
	c4aAssert(t, os.WriteFile(path, []byte("listen: 127.0.0.1:18081\ndatabase: "+dbpath+"\nsecret_key_file: "+master+"\n"), 0600) == nil, "config")
	key := c4aPassword(t)
	t.Run("C5B-init", func(t *testing.T) {
		rc, _ := c5bCommand(t, path, []string{"secret-key", "init"}, "")
		c4aAssert(t, rc == 0, "init")
		_, e := os.Stat(dbpath)
		c4aAssert(t, os.IsNotExist(e), "init opened database")
		before, e := os.ReadFile(master)
		c4aAssert(t, e == nil, "master")
		info, e := os.Stat(master)
		c4aAssert(t, e == nil && info.Mode().Perm() == 0600, "master permissions")
		rc, out := c5bCommand(t, path, []string{"secret-key", "init"}, "")
		after, _ := os.ReadFile(master)
		c4aAssert(t, rc == 1 && bytes.Equal(before, after) && !bytes.Contains(out, bytes.TrimSpace(before)), "overwrite/redaction")
	})
	t.Run("C5B-cli-validation", func(t *testing.T) {
		for _, v := range []struct{ name, url, key string }{{"", "http://192.0.2.2", key}, {"region/node", "http://192.0.2.2", key}, {"n", "ftp://192.0.2.2", key}, {"n", "http://user@192.0.2.2", key}, {"n", "http://192.0.2.2?q=1", key}, {"n", "http://192.0.2.2", ""}, {"n", "http://192.0.2.2", strings.Repeat("x", 4097)}} {
			rc, out := c5bCommand(t, path, []string{"node", "add", v.name, "--url", v.url, "--key-stdin"}, v.key+"\n")
			c4aAssert(t, rc == 1, "invalid node accepted")
			if strings.Contains(v.name, "/") {
				c4aAssert(t, strings.Contains(string(out), "name must not contain '/'") && !strings.Contains(string(out), v.name), "slash rule")
			}
		}
	})
	t.Run("C5B-cli-write", func(t *testing.T) {
		rc, out := c5bCommand(t, path, []string{"node", "add", "n", "--url", "http://192.0.2.2", "--key-stdin"}, key+"\r\nDISCARDED_TEST_LINE\n")
		c4aAssert(t, rc == 0 && !bytes.Contains(out, []byte(key)), "add")
		rc, _ = c5bCommand(t, path, []string{"node", "add", "n", "--url", "http://192.0.2.2", "--key-stdin"}, key+"\n")
		c4aAssert(t, rc == 1, "duplicate")
		rc, _ = c5bCommand(t, path, []string{"node", "update", "n", "--url", "http://192.0.2.3"}, "")
		c4aAssert(t, rc == 0, "URL-only read stdin")
		db, e := store.Open(dbpath)
		c4aAssert(t, e == nil, "db")
		defer db.Close()
		n, e := store.FindNode(db.Reader(), "n")
		c4aAssert(t, e == nil && n.BaseURL == "http://192.0.2.3", "persisted URL")
		k, e := secret.Load(master)
		c4aAssert(t, e == nil, "master")
		plain, e := k.Open(n.Name, n.KeyNonce, n.KeyCipher)
		c4aAssert(t, e == nil && plain == key, "single-line key")
		rows, e := store.AuditAfter(db.Reader(), "", "", "", 0, 100)
		c4aAssert(t, e == nil && len(rows) == 2, "audit count")
		for _, ev := range rows {
			c4aAssert(t, ev.Actor == "system:cli" && ev.Target == "node:n", "CLI audit actor")
		}
	})
	t.Run("C5B-startup", func(t *testing.T) {
		cfg, e := config.Load(path)
		c4aAssert(t, e == nil, "load config")
		keyFile, e := os.ReadFile(master)
		c4aAssert(t, e == nil, "master sample")
		encoded := bytes.TrimSpace(keyFile)
		raw, e := base64.StdEncoding.DecodeString(string(encoded))
		c4aAssert(t, e == nil, "raw sample")
		for _, mode := range []string{"valid", "replaced", "nonce", "cipher", "permission", "length"} {
			mode := mode
			t.Run(mode, func(t *testing.T) {
				local := cfg
				local.SecretKeyFile = filepath.Join(t.TempDir(), "master")
				c4aAssert(t, os.WriteFile(local.SecretKeyFile, keyFile, 0600) == nil, "copy master")
				info, e := os.Stat(local.SecretKeyFile)
				c4aAssert(t, e == nil && info.Mode().Perm() == 0600, "copied permissions")
				db, e := store.Open(dbpath)
				c4aAssert(t, e == nil, "db")
				old, e := store.FindNode(db.Reader(), "n")
				c4aAssert(t, e == nil, "seed row")
				defer func() { store.PutNode(db, old, false); db.Close() }()
				row := old
				switch mode {
				case "replaced":
					local.SecretKeyFile = c5bMasterFile(t)
				case "nonce":
					row.KeyNonce = []byte{1}
				case "cipher":
					row.KeyCipher = append([]byte{}, row.KeyCipher...)
					row.KeyCipher[0] ^= 1
				case "permission":
					c4aAssert(t, os.Chmod(local.SecretKeyFile, 0644) == nil, "chmod")
				case "length":
					short := make([]byte, 31)
					_, e := rand.Read(short)
					c4aAssert(t, e == nil, "random short master")
					c4aAssert(t, os.WriteFile(local.SecretKeyFile, []byte(base64.StdEncoding.EncodeToString(short)), 0600) == nil, "length fixture")
				}
				c4aAssert(t, store.PutNode(db, row, false) == nil, "row fixture")
				loadedFile, e := os.ReadFile(local.SecretKeyFile)
				c4aAssert(t, e == nil && len(loadedFile) > 0, "loaded master sample")
				loadedEncoded := bytes.TrimSpace(loadedFile)
				loadedRaw, e := base64.StdEncoding.DecodeString(string(loadedEncoded))
				c4aAssert(t, e == nil && len(loadedRaw) > 0, "loaded raw sample")
				var requests atomic.Int32
				var logs bytes.Buffer
				saved := log.Writer()
				log.SetOutput(&logs)
				defer log.SetOutput(saved)
				a := defaults()
				a.hub = c5dCloserFunc(func() {})
				var m *orch.Manager
				steps := []string{}
				a.manager = func(specs []nc.NodeSpec, o orch.Options) manager {
					o.Client.Transport = c5bRoundTrip(func(r *http.Request) (*http.Response, error) {
						requests.Add(1)
						return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
					})
					m = orch.New(specs, o)
					return m
				}
				a.api = func(s *rules.Service, n api.Nodes, _ *auth.Service) http.Handler {
					count := 0
					if mode == "valid" {
						count = 1
					}
					c4aAssert(t, len(n.Status()) == count, "startup orch membership")
					k, e := secret.Load(local.SecretKeyFile)
					c4aAssert(t, e == nil, "load key")
					h := api.New(s, n, func(*http.Request) (rules.Actor, *api.Error) { return rules.Actor{Kind: rules.UI, Admin: true}, nil }, log.New(&logs, "", 0), api.Options{NodeStore: api.NewNodeService(db, k)})
					w := httptest.NewRecorder()
					h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/nodes", nil))
					var v struct{ Nodes []api.NodeDTO }
					c4aAssert(t, json.Unmarshal(w.Body.Bytes(), &v) == nil && len(v.Nodes) == 1 && v.Nodes[0].KeyUnreadable == (mode != "valid"), "unreadable DTO")
					logs.Write(w.Body.Bytes())
					return h
				}
				a.server = func(string, http.Handler) server { return fakeServer{steps: &steps} }
				err := assemble(context.Background(), local, nil, a)
				badFile := mode == "permission" || mode == "length"
				c4aAssert(t, (err != nil) == badFile, "startup outcome")
				if badFile {
					c4aAssert(t, m == nil && strings.Contains(err.Error(), "secret_key_file"), "bad master startup boundary")
					logs.WriteString(err.Error())
				} else if mode != "valid" {
					c4aAssert(t, requests.Load() == 0, "unreadable key contacted node")
				}
				logs.WriteString("TEST_ONLY_STARTUP_LOG_SAMPLE")
				row.UpdatedBy = "TEST_ONLY_SCAN"
				c4aAssert(t, store.PutNode(db, row, false) == nil, "retain nonempty WAL sample")
				samples := [][]byte{logs.Bytes()}
				for _, suffix := range []string{"", "-wal"} {
					b, e := os.ReadFile(dbpath + suffix)
					c4aAssert(t, e == nil && len(b) > 0, "database sample")
					samples = append(samples, b)
				}
				for _, b := range samples {
					for _, v := range [][]byte{[]byte(key), raw, encoded, loadedRaw, loadedEncoded} {
						c4aAssert(t, len(v) > 0 && !bytes.Contains(b, v), "startup secret leak")
					}
				}
				t.Logf("startup_mode=%s samples=%d master_forms=2", mode, len(samples))
			})
		}
	})
	t.Run("C5B-cli-delete", func(t *testing.T) {
		rc, _ := c5bCommand(t, path, []string{"node", "delete", "n"}, "")
		c4aAssert(t, rc == 0, "delete read stdin")
		db, e := store.Open(dbpath)
		c4aAssert(t, e == nil, "db")
		defer db.Close()
		rows, e := store.Nodes(db.Reader())
		c4aAssert(t, e == nil && len(rows) == 0, "delete persisted")
	})
}
