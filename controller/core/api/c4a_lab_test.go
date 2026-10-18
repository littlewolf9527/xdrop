package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/auth"
	"github.com/littlewolf9527/xdrop/controller/core/config"
)

type labAccountState struct {
	mu                                       sync.Mutex
	password, key, cookie, database, logfile string
	secrets                                  map[string][]string
	responses                                [][]byte
	counts                                   map[string]int
}

var labAccounts = struct {
	sync.Mutex
	states map[string]*labAccountState
}{states: map[string]*labAccountState{}}

func labAccount(base string) *labAccountState {
	labAccounts.Lock()
	defer labAccounts.Unlock()
	return labAccounts.states[base]
}
func labBearer(base string) string {
	s := labAccount(base)
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key
}
func labAccountResponse(base, path string, b []byte) {
	if path != "/system" && path != "/nodes" {
		return
	}
	s := labAccount(base)
	if s != nil {
		s.mu.Lock()
		s.responses = append(s.responses, append([]byte(nil), b...))
		s.mu.Unlock()
	}
}
func (s *labAccountState) record(t *testing.T, kind, value string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[kind] = append(s.secrets[kind], value)
	path := os.Getenv("XDROP_C4A_SECRET_FILE")
	require(t, path != "", "private secret scan manifest missing")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	require(t, e == nil, "secret scan manifest open")
	defer f.Close()
	require(t, json.NewEncoder(f).Encode(map[string]string{"kind": kind, "value": value}) == nil, "secret scan manifest write")
}
func labCLI(t *testing.T, binary, path, operation, password string) {
	t.Helper()
	cmd := exec.Command(binary, "-config", path, "user", operation, "lab-admin")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, e := cmd.CombinedOutput()
	require(t, e == nil, "account CLI failed")
	require(t, !bytes.Contains(out, []byte(password)), "account CLI exposed password")
}

var labLegacyDatabase string

func labAccountBefore(t *testing.T, binary, path, logfile string) func() {
	t.Helper()
	if binary != os.Getenv("XDROP_CTLCUT3_CONTROLLER") {
		return func() {}
	}
	cfg := config.Config{Database: labLegacyDatabase}
	if labLegacyDatabase == "" {
		var e error
		cfg, e = config.Load(path)
		require(t, e == nil, "account configuration")
	}
	base := os.Getenv("XDROP_CTLCUT3_URL")
	s := &labAccountState{password: c4aSecret(t), database: cfg.Database, logfile: logfile, secrets: map[string][]string{}, counts: map[string]int{}}
	s.record(t, "password", s.password)
	labCLI(t, binary, path, "add", s.password)
	labAccounts.Lock()
	labAccounts.states[base] = s
	labAccounts.Unlock()
	return func() {
		labWait(t, 30*time.Second, func() bool {
			_, code, _, _, e := labRaw(base, "GET", "/health", "", "", "", nil)
			return e == nil && code == 200
		})
		s.cookie = labLogin(t, base, s, s.password)
		s.key = labIssue(t, base, s, s.cookie)
		t.Cleanup(func() { labAccountScan(t) })
	}
}
func labRaw(base, method, path, cookie, key, body string, headers http.Header) ([]byte, int, []*http.Cookie, time.Duration, error) {
	r, e := http.NewRequest(method, base+"/api/v1"+path, strings.NewReader(body))
	if e != nil {
		return nil, 0, nil, 0, e
	}
	if headers != nil {
		r.Header = headers.Clone()
	}
	if cookie != "" {
		r.Header.Set("Cookie", auth.CookieName+"="+cookie)
	}
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	start := time.Now()
	resp, e := client.Do(r)
	if e != nil {
		return nil, 0, nil, time.Since(start), e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(resp.Body)
	labAccountResponse(base, path, b)
	return b, resp.StatusCode, resp.Cookies(), time.Since(start), e
}
func labLogin(t *testing.T, base string, s *labAccountState, password string) string {
	t.Helper()
	_, code, cs, _, e := labRaw(base, "POST", "/auth/login", "", "", c4aJSON(LoginInput{"lab-admin", password}), nil)
	require(t, e == nil && code == 200 && len(cs) == 1, "lab login")
	c4aCookieCheck(t, cs[0], 86400)
	s.record(t, "token", cs[0].Value)
	return cs[0].Value
}
func labIssue(t *testing.T, base string, s *labAccountState, cookie string) string {
	t.Helper()
	b, code, _, _, e := labRaw(base, "POST", "/credentials", cookie, "", `{"name":"lab"}`, nil)
	var v IssuedDTO
	require(t, e == nil && code == 201 && json.Unmarshal(b, &v) == nil && len(v.Key) > 21, "lab issue credential")
	s.record(t, "key", v.Key)
	s.record(t, "secret", v.Key[21:])
	return v.Key
}
func labAccountScan(t *testing.T) {
	t.Helper()
	s := labAccount(os.Getenv("XDROP_CTLCUT3_URL"))
	require(t, s != nil, "lab account state")
	s.mu.Lock()
	defer s.mu.Unlock()
	scan := func(kind string, b []byte) {
		s.counts[kind]++
		for _, values := range s.secrets {
			for _, value := range values {
				require(t, !bytes.Contains(b, []byte(value)), "authentication secret leak", kind)
			}
		}
	}
	for _, file := range []struct{ kind, path string }{{"logs", s.logfile}, {"database", s.database}, {"wal", s.database + "-wal"}} {
		b, e := os.ReadFile(file.path)
		if os.IsNotExist(e) && s.counts[file.kind] > 0 {
			continue
		}
		require(t, e == nil, "authentication scan file", file.kind)
		scan(file.kind, b)
	}
	for _, b := range s.responses {
		scan("responses", b)
	}
	for _, kind := range []string{"password", "key", "secret", "token"} {
		require(t, len(s.secrets[kind]) > 0, "missing authentication secret class", kind)
	}
	for _, kind := range []string{"logs", "database", "wal", "responses"} {
		require(t, s.counts[kind] > 0, "missing lab scan class", kind)
	}
	proof := map[string]any{"counts": s.counts, "secret_classes": 4, "matches": 0}
	b, e := json.Marshal(proof)
	require(t, e == nil && os.WriteFile(s.logfile+".auth-scan.json", b, 0600) == nil, "scan proof")
	t.Logf("C4A_SECRET secret_classes=4 logs=%d database=%d wal=%d responses=%d matches=0", s.counts["logs"], s.counts["database"], s.counts["wal"], s.counts["responses"])
}
func TestC4ALab(t *testing.T) {
	t.Run("L-c4a", func(t *testing.T) {
		if os.Getenv("XDROP_CTLCUT3_LAB") == "" {
			t.Skip("requires owned lab namespaces and native binaries")
		}
		root := t.TempDir()
		dbpath := filepath.Join(root, "controller.db")
		labSeed(t, dbpath)
		base, agentURL := os.Getenv("XDROP_CTLCUT3_URL"), os.Getenv("XDROP_CTLCUT2_AGENT_URL")
		logs, keyfile := os.Getenv("XDROP_CTLCUT2_LOG_DIR"), os.Getenv("XDROP_CTLCUT2_KEY_FILE")
		labProcessStart(t, os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"), filepath.Join(logs, "L-c4a-agent.log"))
		path := filepath.Join(root, "controller.example.yaml")
		text := "listen: " + strings.TrimPrefix(base, "http://") + "\ndatabase: " + dbpath + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
		require(t, os.WriteFile(path, []byte(text), 0600) == nil, "lab configuration")
		labNodeInit(t, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), path, "lab", agentURL, keyfile)
		binary := os.Getenv("XDROP_CTLCUT3_CONTROLLER")
		labProcessStart(t, binary, path, filepath.Join(logs, "L-c4a-controller.log"))
		s := labAccount(base)
		for _, test := range []struct {
			path   string
			status int
		}{{"/rules", 401}, {"/health", 200}} {
			_, code, _, _, e := labRaw(base, "GET", test.path, "", "", "", nil)
			require(t, e == nil && code == test.status, "public authentication boundary")
		}
		_, code, _, _, e := labRaw(base, "POST", "/auth/login", "", "", c4aJSON(LoginInput{"lab-admin", c4aSecret(t)}), nil)
		require(t, e == nil && code == 401, "bad password")
		old := s.cookie
		password := c4aSecret(t)
		s.record(t, "password", password)
		labCLI(t, binary, path, "passwd", password)
		_, code, _, _, e = labRaw(base, "GET", "/auth/me", old, "", "", nil)
		require(t, e == nil && code == 401, "live CLI revokes session")
		time.Sleep(time.Second)
		cookie := labLogin(t, base, s, password)
		id := s.key[4:20]
		_, code, _, _, e = labRaw(base, "DELETE", "/credentials/"+id, cookie, "", "", nil)
		require(t, e == nil && code == 204, "revoke lab key")
		_, code, _, _, e = labRaw(base, "GET", "/auth/me", "", s.key, "", nil)
		require(t, e == nil && code == 401, "revoked key next request")
		newkey := labIssue(t, base, s, cookie)
		s.mu.Lock()
		s.key = newkey
		s.mu.Unlock()
		_, code, _, _, e = labRaw(base, "GET", "/auth/me", "", newkey, "", nil)
		require(t, e == nil && code == 200, "new lab key restores access")
		for _, path := range []string{"/system", "/nodes"} {
			_, code, _, _, e = labRaw(base, "GET", path, "", newkey, "", nil)
			require(t, e == nil && code == 200, "scan response")
		}
		samples := []time.Duration{}
		for i := 0; i < 20; i++ {
			_, code, cs, elapsed, e := labRaw(base, "POST", "/auth/login", "", "", c4aJSON(LoginInput{"lab-admin", password}), nil)
			require(t, e == nil && code == 200 && len(cs) == 1, "login sample")
			s.record(t, "token", cs[0].Value)
			samples = append(samples, elapsed)
		}
		p99 := labP99(samples)
		t.Logf("L-c4a login_samples=%d login_p99=%s limit=500ms", len(samples), p99)
		require(t, len(samples) == 20 && p99 < 500*time.Millisecond, "login performance")
		labAccountScan(t)
		t.Log(fmt.Sprint("L-c4a no_identity=401 health=200 wrong_password=401 live_cli=401 revoke=401 restored=200"))
	})
}
