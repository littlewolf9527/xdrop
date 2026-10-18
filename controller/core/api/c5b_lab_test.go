package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/config"
	nc "github.com/littlewolf9527/xdrop/controller/core/nodeclient"
)

func labNodeInit(t *testing.T, binary, path, name, url, keyfile string) {
	t.Helper()
	cfg, e := config.Load(path)
	require(t, e == nil, "node configuration")
	key, e := os.ReadFile(keyfile)
	require(t, e == nil && len(key) > 0, "node key fixture")
	init := exec.Command(binary, "-config", path, "secret-key", "init")
	out, e := init.CombinedOutput()
	require(t, e == nil, "secret-key init")
	info, e := os.Stat(cfg.SecretKeyFile)
	require(t, e == nil && info.Mode().Perm() == 0600, "master permissions")
	encoded, e := os.ReadFile(cfg.SecretKeyFile)
	require(t, e == nil, "master sample")
	raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	require(t, e == nil && len(raw) == 32, "master length")
	add := exec.Command(binary, "-config", path, "node", "add", name, "--url", url, "--key-stdin")
	add.Stdin = bytes.NewReader(append(bytes.TrimSpace(key), '\n'))
	b, e := add.CombinedOutput()
	require(t, e == nil, "node add")
	out = append(out, b...)
	for _, secret := range [][]byte{bytes.TrimSpace(key), bytes.TrimSpace(encoded), raw} {
		require(t, !bytes.Contains(out, secret), "CLI secret exposure")
	}
}
func c5bLabStop(t *testing.T, p *labProcess) {
	t.Helper()
	require(t, p.cmd.Process.Signal(syscall.SIGTERM) == nil, "SIGTERM")
	select {
	case e := <-p.done:
		p.stopped = true
		require(t, e == nil, "process exit")
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		p.stopped = true
		t.Fatal("process stop deadline")
	}
}
func TestC5BLab(t *testing.T) {
	t.Run("L-c5b", func(t *testing.T) {
		if os.Getenv("XDROP_CTLCUT3_LAB") == "" {
			t.Skip("requires owned lab namespaces and native binaries")
		}
		root := t.TempDir()
		base, logs := os.Getenv("XDROP_CTLCUT3_URL"), os.Getenv("XDROP_CTLCUT2_LOG_DIR")
		binary := os.Getenv("XDROP_CTLCUT3_CONTROLLER")
		firstURL, secondURL := os.Getenv("XDROP_CTLCUT2_AGENT_URL"), os.Getenv("XDROP_C5B_AGENT2_URL")
		firstKey, secondKey := os.Getenv("XDROP_CTLCUT2_KEY_FILE"), os.Getenv("XDROP_C5B_AGENT2_KEY_FILE")
		first := labProcessStart(t, os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"), filepath.Join(logs, "L-c5b-agent1.log"))
		second := labProcessStart(t, os.Getenv("XDROP_C5B_AGENT2"), os.Getenv("XDROP_C5B_AGENT2_CONFIG"), filepath.Join(logs, "L-c5b-agent2.log"))
		path := filepath.Join(root, "controller.example.yaml")
		text := "listen: " + strings.TrimPrefix(base, "http://") + "\ndatabase: " + filepath.Join(root, "controller.db") + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
		require(t, os.WriteFile(path, []byte(text), 0600) == nil, "configuration")
		labNodeInit(t, binary, path, "lab", firstURL, firstKey)
		ctl := labProcessStart(t, binary, path, filepath.Join(logs, "L-c5b-controller.log"))
		s := labAccount(base)
		call := func(method, path, body string, want int) []byte {
			t.Helper()
			b, code, _, _, e := labRaw(base, method, path, s.cookie, "", body, nil)
			require(t, e == nil && code == want, "node lab API", method, path, code)
			return b
		}
		direct := func(url, keyfile string) *nc.Client {
			t.Helper()
			key, e := os.ReadFile(keyfile)
			require(t, e == nil, "direct key")
			c, e := nc.New(nc.NodeSpec{BaseURL: url, Key: nc.Secret(strings.TrimSpace(string(key)))}, nc.Options{})
			require(t, e == nil, "direct client")
			return c
		}
		a, b := direct(firstURL, firstKey), direct(secondURL, secondKey)
		count := func(c *nc.Client) int {
			r, e := c.Rules(context.Background(), 1, 1000)
			if e != nil {
				return -1
			}
			return r.Pagination.Total
		}
		call("POST", "/rules", `{"src_ip":"192.0.2.41","protocol":"tcp","dst_port":80}`, 201)
		labWait(t, 30*time.Second, func() bool { return count(a) == 1 })
		before := count(a)
		require(t, before > 0, "nonempty first node")
		key, e := os.ReadFile(secondKey)
		require(t, e == nil, "second key")
		call("POST", "/nodes", c4aJSON(map[string]string{"name": "second", "base_url": secondURL, "api_key": strings.TrimSpace(string(key))}), 201)
		controllerCount := func() int {
			var rows CapacityDTO
			require(t, json.Unmarshal(call("GET", "/capacity", "", 200), &rows) == nil, "controller count")
			return rows.Rules.Total
		}
		want := controllerCount()
		require(t, want == before, "controller initial count")
		labWait(t, 30*time.Second, func() bool { return count(b) == want })
		call("DELETE", "/nodes/lab", "", 204)
		call("POST", "/rules", `{"src_ip":"192.0.2.42","protocol":"tcp","dst_port":81}`, 201)
		labWait(t, 30*time.Second, func() bool { return count(b) == want+1 })
		require(t, count(a) == before && before > 0 && controllerCount() == want+1, "first rules retained and second advanced")
		labAccountScan(t)
		c5bLabStop(t, ctl)
		t.Setenv("XDROP_CTLCUT3_CONTROLLER", "")
		ctl = labProcessStart(t, binary, path, filepath.Join(logs, "L-c5b-controller-restart.log"))
		t.Setenv("XDROP_CTLCUT3_CONTROLLER", binary)
		labWait(t, 30*time.Second, func() bool {
			data, code, _, _, e := labRaw(base, "GET", "/nodes", s.cookie, "", "", nil)
			var v struct{ Nodes []NodeDTO }
			return e == nil && code == 200 && json.Unmarshal(data, &v) == nil && len(v.Nodes) == 1 && v.Nodes[0].Name == "second" && !v.Nodes[0].KeyUnreadable && v.Nodes[0].Rules.State == "normal"
		})
		require(t, count(a) == before && count(b) == want+1, "restart preserves first rules")
		c5bLabStop(t, ctl)
		c5bLabStop(t, second)
		c5bLabStop(t, first)
		t.Logf("L-c5b first_before=%d first_after=%d second_before=%d second_after=%d restart_nodes=1 key_readable=1", before, before, want, want+1)
	})
}
