package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/auth"
)

type c5dLabStream struct {
	frames chan string
	done   chan struct{}
}

func c5dLabConnect(t *testing.T, base, cookie string) *c5dLabStream {
	t.Helper()
	r, err := http.NewRequest("GET", base+"/api/v1/events", nil)
	require(t, err == nil, "SSE request")
	r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	transport := &http.Transport{ResponseHeaderTimeout: 3 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	response, err := (&http.Client{Transport: transport}).Do(r)
	require(t, err == nil && response.StatusCode == 200, "SSE response")
	t.Cleanup(func() { response.Body.Close() })
	s := &c5dLabStream{make(chan string, 256), make(chan struct{})}
	go func() {
		defer close(s.done)
		scan := bufio.NewScanner(response.Body)
		scan.Buffer(make([]byte, 4096), 4<<20)
		var frame strings.Builder
		for scan.Scan() {
			line := scan.Text()
			if line == "" {
				if strings.HasPrefix(frame.String(), "event:") {
					s.frames <- frame.String()
				}
				frame.Reset()
			} else {
				frame.WriteString(line + "\n")
			}
		}
	}()
	return s
}
func (s *c5dLabStream) wait(t *testing.T, duration time.Duration, event string, accepts func(map[string]any) bool) map[string]any {
	t.Helper()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	for {
		select {
		case frame := <-s.frames:
			if !strings.HasPrefix(frame, "event: "+event+"\n") {
				continue
			}
			var value map[string]any
			require(t, json.Unmarshal([]byte(strings.SplitN(frame, "data: ", 2)[1]), &value) == nil, "SSE JSON")
			if accepts == nil || accepts(value) {
				return value
			}
		case <-timer.C:
			t.Fatal("SSE event deadline", event)
		case <-s.done:
			t.Fatal("SSE ended before event", event)
		}
	}
}
func (s *c5dLabStream) closed(t *testing.T, duration time.Duration) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(duration):
		t.Fatal("SSE close deadline")
	}
}
func TestC5DLab(t *testing.T) {
	t.Run("L-c5d", func(t *testing.T) {
		if os.Getenv("XDROP_CTLCUT3_LAB") == "" {
			t.Skip("requires owned lab namespaces and native binaries")
		}
		root := t.TempDir()
		data := filepath.Join(root, "data")
		require(t, os.Mkdir(data, 0700) == nil, "data directory")
		base, logs := os.Getenv("XDROP_CTLCUT3_URL"), os.Getenv("XDROP_CTLCUT2_LOG_DIR")
		binary := os.Getenv("XDROP_CTLCUT3_CONTROLLER")
		agent := labProcessStart(t, os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"), filepath.Join(logs, "L-c5d-agent.log"))
		path := filepath.Join(root, "controller.example.yaml")
		cfg := "listen: " + strings.TrimPrefix(base, "http://") + "\ndatabase: " + filepath.Join(data, "controller.db") + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
		require(t, os.WriteFile(path, []byte(cfg), 0600) == nil, "configuration")
		labNodeInit(t, binary, path, "lab", os.Getenv("XDROP_CTLCUT2_AGENT_URL"), os.Getenv("XDROP_CTLCUT2_KEY_FILE"))
		ctl := labProcessStart(t, binary, path, filepath.Join(logs, "L-c5d-controller.log"))
		account := labAccount(base)
		aCookie, bCookie := account.cookie, labLogin(t, base, account, account.password)
		a, b := c5dLabConnect(t, base, aCookie), c5dLabConnect(t, base, bCookie)
		for _, s := range []*c5dLabStream{a, b} {
			for _, name := range []string{"rules", "nodes", "traffic"} {
				s.wait(t, 2*time.Second, name, nil)
			}
		}
		call := func(cookie, method, path, body string, want int) []byte {
			t.Helper()
			v, code, _, _, err := labRaw(base, method, path, cookie, "", body, nil)
			require(t, err == nil && code == want, "lab API", method, path, code)
			return v
		}
		var created CreateResponse
		start := time.Now()
		require(t, json.Unmarshal(call(bCookie, "POST", "/rules", `{"dst_ip":"192.0.2.10","action":"drop","expires_in":"1h"}`, 201), &created) == nil, "create")
		first := a.wait(t, 2*time.Second-time.Since(start), "rules", nil)
		b.wait(t, 2*time.Second-time.Since(start), "rules", nil)
		createTime := time.Since(start)
		start = time.Now()
		call(bCookie, "POST", "/rules", `{"dst_ip":"192.0.2.10","action":"drop","expires_in":"2h"}`, 200)
		newer := func(v map[string]any) bool {
			return v["seq"].(float64) > first["seq"].(float64) && v["gen"] == first["gen"]
		}
		a.wait(t, 2*time.Second-time.Since(start), "rules", newer)
		b.wait(t, 2*time.Second-time.Since(start), "rules", newer)
		renewTime := time.Since(start)
		labWait(t, 30*time.Second, func() bool {
			var nodes struct{ Nodes []NodeDTO }
			return json.Unmarshal(call(bCookie, "GET", "/nodes", "", 200), &nodes) == nil && len(nodes.Nodes) == 1 && nodes.Nodes[0].Rules.State == "normal"
		})
		ready := filepath.Join(root, "sender-ready")
		cmd := exec.Command("python3", os.Getenv("XDROP_CTLCUT2_SENDER"), "--iface", "c2a1", "--kind", "normal", "--dst", "192.0.2.10", "--rate", "100", "--seconds", "20", "--ready", ready)
		var sender bytes.Buffer
		cmd.Stdout, cmd.Stderr = &sender, &sender
		require(t, cmd.Start() == nil, "sender start")
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		labWait(t, 5*time.Second, func() bool { _, err := os.Stat(ready); return err == nil })
		start = time.Now()
		b.wait(t, 12*time.Second, "traffic", func(v map[string]any) bool {
			encoded, _ := json.Marshal(v["top"])
			var top topResponse
			if json.Unmarshal(encoded, &top) != nil {
				return false
			}
			for _, r := range top.Rules {
				if r.RuleID == created.ID && r.PPS > 0 {
					return true
				}
			}
			return false
		})
		trafficTime := time.Since(start)
		start = time.Now()
		call(aCookie, "POST", "/auth/logout", "", 204)
		a.closed(t, 2*time.Second-time.Since(start))
		logoutTime := time.Since(start)
		call(bCookie, "POST", "/rules", `{"dst_ip":"192.0.2.11"}`, 201)
		b.wait(t, 2*time.Second, "rules", func(v map[string]any) bool { return v["seq"].(float64) > first["seq"].(float64) })
		password := c4aSecret(t)
		account.record(t, "password", password)
		labCLI(t, binary, path, "passwd", password)
		start = time.Now()
		b.closed(t, 2*time.Second)
		cliTime := time.Since(start)
		account.cookie = labLogin(t, base, account, password)
		c := c5dLabConnect(t, base, account.cookie)
		for _, name := range []string{"rules", "nodes", "traffic"} {
			c.wait(t, 2*time.Second, name, nil)
		}
		call(account.cookie, "GET", "/system", "", 200)
		labAccountScan(t)
		start = time.Now()
		require(t, ctl.cmd.Process.Signal(syscall.SIGTERM) == nil, "SIGTERM")
		select {
		case err := <-ctl.done:
			ctl.stopped = true
			require(t, err == nil, "controller exit")
		case <-time.After(5 * time.Second):
			t.Fatal("controller stop deadline")
		}
		c.closed(t, 5*time.Second-time.Since(start))
		stopTime := time.Since(start)
		files, err := os.ReadDir(data)
		require(t, err == nil && len(files) == 1 && files[0].Name() == "controller.db", "single database file")
		t.Setenv("XDROP_CTLCUT3_CONTROLLER", "")
		ctl = labProcessStart(t, binary, path, filepath.Join(logs, "L-c5d-controller-restart.log"))
		t.Setenv("XDROP_CTLCUT3_CONTROLLER", binary)
		labWait(t, 30*time.Second, func() bool {
			_, code, _, _, err := labRaw(base, "GET", "/health", "", "", "", nil)
			return err == nil && code == 200
		})
		response, err := (&http.Client{Timeout: 3 * time.Second}).Get(base + "/")
		require(t, err == nil && response.StatusCode == 200, "restart static status")
		page, err := io.ReadAll(response.Body)
		response.Body.Close()
		require(t, err == nil && bytes.Contains(page, []byte("前端未构建")), "restart placeholder")
		c5bLabStop(t, ctl)
		require(t, cmd.Wait() == nil, "sender completion")
		var report struct{ Frames int }
		require(t, json.Unmarshal(sender.Bytes(), &report) == nil && report.Frames > 0, "sender frames")
		c5bLabStop(t, agent)
		t.Logf("L-c5d snapshots=9 create_s=%.3f renew_s=%.3f traffic_s=%.3f logout_s=%.3f cli_s=%.3f stop_s=%.3f sender_frames=%d exit=0 single_file=1 restart_static=1 restart_health=1", createTime.Seconds(), renewTime.Seconds(), trafficTime.Seconds(), logoutTime.Seconds(), cliTime.Seconds(), stopTime.Seconds(), report.Frames)
	})
}
