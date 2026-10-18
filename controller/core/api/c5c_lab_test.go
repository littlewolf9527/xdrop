package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var c5cHitsAccess = regexp.MustCompile(`\|\s+GET\s+"/api/v1/rules/hits\?since_ns=[0-9]+"`)

func TestC5CHitsLogFormat(t *testing.T) {
	sample := `[GIN] 2026/01/01 - 00:00:05 | 200 | 1ms | 127.0.0.1 | GET "/api/v1/rules/hits?since_ns=0"`
	require(t, len(c5cHitsAccess.FindAllString(sample, -1)) == 1 && !c5cHitsAccess.MatchString("hits_scan rows=1 dur_ms=0.1 truncated=false"), "access log format")
	t.Log("agent_access_sample_matches=1 scan_counter_matches=0")
}
func TestC5CLab(t *testing.T) {
	t.Run("L-c5c", func(t *testing.T) {
		if os.Getenv("XDROP_CTLCUT3_LAB") == "" {
			t.Skip("requires owned lab namespaces and native binaries")
		}
		root := t.TempDir()
		data := filepath.Join(root, "data")
		require(t, os.Mkdir(data, 0700) == nil, "data directory")
		base, logs := os.Getenv("XDROP_CTLCUT3_URL"), os.Getenv("XDROP_CTLCUT2_LOG_DIR")
		binary := os.Getenv("XDROP_CTLCUT3_CONTROLLER")
		agentLog := filepath.Join(logs, "L-c5c-agent.log")
		began := time.Now()
		agent := labProcessStart(t, os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"), agentLog)
		config := filepath.Join(root, "controller.example.yaml")
		dbPath := filepath.Join(data, "controller.db")
		cfg := "listen: " + strings.TrimPrefix(base, "http://") + "\ndatabase: " + dbPath + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
		require(t, os.WriteFile(config, []byte(cfg), 0600) == nil, "configuration")
		labNodeInit(t, binary, config, "lab", os.Getenv("XDROP_CTLCUT2_AGENT_URL"), os.Getenv("XDROP_CTLCUT2_KEY_FILE"))
		ctl := labProcessStart(t, binary, config, filepath.Join(logs, "L-c5c-controller.log"))
		account := labAccount(base)
		call := func(method, path, body string, want int) []byte {
			t.Helper()
			b, status, _, _, e := labRaw(base, method, path, account.cookie, "", body, nil)
			require(t, e == nil && status == want, "traffic lab response", method, path, status)
			return b
		}
		var created CreateResponse
		require(t, json.Unmarshal(call("POST", "/rules", `{"dst_ip":"192.0.2.10","action":"drop"}`, 201), &created) == nil, "created rule")
		labWait(t, 30*time.Second, func() bool {
			var nodes struct{ Nodes []NodeDTO }
			return json.Unmarshal(call("GET", "/nodes", "", 200), &nodes) == nil && len(nodes.Nodes) == 1 && nodes.Nodes[0].Rules.State == "normal"
		})
		ready := filepath.Join(root, "sender-ready")
		cmd := exec.Command("python3", os.Getenv("XDROP_CTLCUT2_SENDER"), "--iface", "c2a1", "--kind", "normal", "--dst", "192.0.2.10", "--rate", "100", "--seconds", "180", "--ready", ready)
		var sender bytes.Buffer
		cmd.Stdout = &sender
		cmd.Stderr = &sender
		require(t, cmd.Start() == nil, "sender start")
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		labWait(t, 5*time.Second, func() bool { _, e := os.Stat(ready); return e == nil })
		sentAt := time.Now()
		labWait(t, 155*time.Second, func() bool { return time.Since(sentAt) >= 150*time.Second })
		var top topResponse
		labWait(t, 20*time.Second, func() bool {
			if json.Unmarshal(call("GET", "/traffic/top", "", 200), &top) != nil || len(top.Rules) == 0 || len(top.Targets) == 0 {
				return false
			}
			r := top.Rules[0]
			return r.RuleID == created.ID && top.Targets[0].Target == "192.0.2.10" && r.PPS >= 80 && r.PPS <= 120 && r.Share != nil && *r.Share > 0 && *r.Share <= 1
		})
		var history struct {
			Step   int `json:"step_s"`
			Points []struct {
				T int64 `json:"t"`
			}
		}
		require(t, json.Unmarshal(call("GET", "/traffic/history?range=15m", "", 200), &history) == nil && history.Step == 5 && len(history.Points) >= 20, "memory history")
		for i, p := range history.Points {
			require(t, p.T%5 == 0 && (i == 0 || p.T > history.Points[i-1].T), "bucket order/alignment")
		}
		raw, e := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro&_query_only=1")
		require(t, e == nil, "read-only database")
		var cluster, node int
		require(t, raw.QueryRow("SELECT COUNT(*) FROM traffic_1m WHERE node=''").Scan(&cluster) == nil && raw.QueryRow("SELECT COUNT(*) FROM traffic_1m WHERE node='lab'").Scan(&node) == nil && cluster > 0 && node > 0, "minute persistence")
		require(t, raw.Close() == nil, "reader close")
		require(t, cmd.Wait() == nil, "sender completion")
		var report struct {
			Frames     int
			Start, End time.Time
		}
		require(t, json.Unmarshal(sender.Bytes(), &report) == nil && report.Frames >= 15000 && report.End.Sub(report.Start) >= 150*time.Second, "sender count/duration")
		labAccountScan(t)
		c5bLabStop(t, ctl)
		c5bLabStop(t, agent)
		duration := time.Since(began).Seconds()
		log, e := os.ReadFile(agentLog)
		require(t, e == nil, "agent log")
		hits := len(c5cHitsAccess.FindAll(log, -1))
		require(t, hits > 0 && hits == bytes.Count(log, []byte(`"/api/v1/rules/hits?since_ns=`)) && float64(hits)/duration <= 0.25, "access log request rate", hits, duration)
		files, e := os.ReadDir(data)
		require(t, e == nil && len(files) == 1 && files[0].Name() == "controller.db", "single database file")
		t.Logf("L-c5c pps=%.3f share=%.6f points=%d step=5 cluster_minutes=%d node_minutes=%d hits_access=%d duration_s=%.3f sender_frames=%d sender_seconds=%.3f exit=0 single_file=1", top.Rules[0].PPS, *top.Rules[0].Share, len(history.Points), cluster, node, hits, duration, report.Frames, report.End.Sub(report.Start).Seconds())
	})
}
