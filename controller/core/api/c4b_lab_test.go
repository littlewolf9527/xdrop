package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xdrop/controller/core/store"
)

func TestC4BLab(t *testing.T) {
	t.Run("L-c4b", func(t *testing.T) {
		if os.Getenv("XDROP_CTLCUT3_LAB") == "" {
			t.Skip("requires owned lab namespaces and native binaries")
		}
		root := t.TempDir()
		dbpath := filepath.Join(root, "controller.db")
		labSeed(t, dbpath)
		base, agentURL := os.Getenv("XDROP_CTLCUT3_URL"), os.Getenv("XDROP_CTLCUT2_AGENT_URL")
		logs, keyfile := os.Getenv("XDROP_CTLCUT2_LOG_DIR"), os.Getenv("XDROP_CTLCUT2_KEY_FILE")
		labProcessStart(t, os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"), filepath.Join(logs, "L-c4b-agent.log"))
		path := filepath.Join(root, "controller.example.yaml")
		text := "listen: " + strings.TrimPrefix(base, "http://") + "\ndatabase: " + dbpath + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
		require(t, os.WriteFile(path, []byte(text), 0600) == nil, "lab config")
		labNodeInit(t, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), path, "lab", agentURL, keyfile)
		from := time.Now().UTC().Format(store.TimeFormat)
		binary := os.Getenv("XDROP_CTLCUT3_CONTROLLER")
		labProcessStart(t, binary, path, filepath.Join(logs, "L-c4b-controller.log"))
		s := labAccount(base)
		cookie := labLogin(t, base, s, s.password)
		key := labIssue(t, base, s, cookie)
		call := func(method, path, identity, body string, status int, headers http.Header) []byte {
			t.Helper()
			b, code, _, _, e := labRaw(base, method, path, identity, "", body, headers)
			require(t, e == nil && code == status, "lab audit request", method, path, code)
			return b
		}
		b := call("POST", "/rules", cookie, `{"dst_ip":"192.0.2.240","protocol":"tcp","dst_port":65240}`, 201, http.Header{"X-Forwarded-For": []string{"198.51.100.7"}})
		var r CreateResponse
		require(t, json.Unmarshal(b, &r) == nil, "rule result")
		call("DELETE", "/rules/"+r.ID, cookie, "", 204, nil)
		call("POST", "/whitelist", cookie, `{"dst_ip":"192.0.2.241","comment":"audit lab"}`, 201, nil)
		call("POST", "/nodes/lab/sync", cookie, "", 202, nil)
		_, code, _, _, e := labRaw(base, "GET", "/audit", "", key, "", nil)
		require(t, e == nil && code == 403, "machine audit denied")
		password := c4aSecret(t)
		s.record(t, "password", password)
		labCLI(t, binary, path, "passwd", password)
		cookie = labLogin(t, base, s, password)
		to := time.Now().UTC().Add(time.Second).Format(store.TimeFormat)
		query := "from=" + url.QueryEscape(from) + "&to=" + url.QueryEscape(to)
		cursor := ""
		all := []store.AuditEvent{}
		for {
			b := call("GET", "/audit?"+query+"&limit=1000&cursor="+url.QueryEscape(cursor), cookie, "", 200, nil)
			var page struct {
				Items []store.AuditEvent `json:"items"`
				Next  string             `json:"next_cursor"`
			}
			require(t, json.Unmarshal(b, &page) == nil, "page")
			all = append(all, page.Items...)
			cursor = page.Next
			if cursor == "" {
				break
			}
			require(t, len(all) < 10000, "audit page loop")
		}
		parsed, e := url.Parse(base)
		require(t, e == nil, "client address")
		seen := map[string]bool{}
		cli, spoof := false, false
		for _, ev := range all {
			seen[ev.Action] = true
			if ev.Actor == "system:cli" {
				require(t, ev.Source == "", "CLI source")
				cli = cli || ev.Action == "user.password"
			} else {
				require(t, ev.Source == parsed.Hostname(), "client namespace source", ev.Action)
			}
			if ev.Action == "rule.create" && ev.Target == "rule:"+r.ID {
				spoof = ev.Source == parsed.Hostname()
			}
		}
		for _, action := range []string{"auth.login", "credential.issue", "rule.create", "rule.delete", "whitelist.create", "node.sync", "user.password"} {
			require(t, seen[action], "missing lab audit action", action)
		}
		require(t, cli && spoof, "CLI and spoof witnesses")
		b = call("GET", "/audit/export?"+query+"&format=csv", cookie, "", 200, nil)
		records, e := csv.NewReader(strings.NewReader(string(b))).ReadAll()
		require(t, e == nil && len(records)-1 == len(all), "export range count")
		for _, path := range []string{"/system", "/nodes"} {
			call("GET", path, cookie, "", 200, nil)
		}
		labAccountScan(t)
		t.Logf("L-c4b actions=7 audit_rows=%d csv_rows=%d source_verified=1 spoof_ignored=1 machine=403 live_cli=1", len(all), len(records)-1)
	})
}
