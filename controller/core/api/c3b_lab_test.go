package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCtlCut3BLab(t *testing.T) {
	t.Run("L3-cap", func(t *testing.T) {
		if os.Getenv("XDROP_CTLCUT3_LAB") == "" {
			t.Skip("requires owned lab namespaces and native binaries")
		}
		// labSeed: 400000 exact + 50000 v4 + 50000 v6, both directions.
		want := []int{400000, 100000, 0, 0, 0, 50000, 50000, 50000, 50000, 500000}
		names := []string{"blacklist", "cidr_blacklist", "cond", "cidr_cond", "whitelist", "sv4_cidr_trie", "dv4_cidr_trie", "sv6_cidr_trie", "dv6_cidr_trie", "logical_state"}
		root := t.TempDir()
		dbpath := filepath.Join(root, "controller.db")
		labSeed(t, dbpath)
		base, agentURL := os.Getenv("XDROP_CTLCUT3_URL"), os.Getenv("XDROP_CTLCUT2_AGENT_URL")
		logs, keyfile := os.Getenv("XDROP_CTLCUT2_LOG_DIR"), os.Getenv("XDROP_CTLCUT2_KEY_FILE")
		labProcessStart(t, os.Getenv("XDROP_CTLCUT2_AGENT"), os.Getenv("XDROP_CTLCUT2_AGENT_CONFIG"), filepath.Join(logs, "L3-cap-agent.log"))
		config := filepath.Join(root, "controller.example.yaml")
		text := "listen: " + strings.TrimPrefix(base, "http://") + "\ndatabase: " + dbpath + "\nsecret_key_file: " + filepath.Join(root, "master.key") + "\n"
		require(t, os.WriteFile(config, []byte(text), 0600) == nil, "configuration write")
		labNodeInit(t, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), config, "lab", agentURL, keyfile)
		labProcessStart(t, os.Getenv("XDROP_CTLCUT3_CONTROLLER"), config, filepath.Join(logs, "L3-cap-controller.log"))
		client := &http.Client{Timeout: 30 * time.Second}
		defer client.CloseIdleConnections()
		compared := []int{0, 1, 5, 6, 7, 8}
		ready := func(s SystemDTO) bool {
			if len(s.Nodes) != 1 || !s.Nodes[0].Online || s.Nodes[0].RulesState != "normal" || s.Nodes[0].WhitelistState != "normal" || len(s.Nodes[0].Capacity) != len(want) {
				return false
			}
			for _, i := range compared {
				c := s.Nodes[0].Capacity[i]
				if c.Name != names[i] || c.ControllerUsed != want[i] || c.NodeUsed != float64(want[i]) {
					return false
				}
			}
			return true
		}
		labWait(t, 5*time.Minute, func() bool {
			data, status, _, _, err := labCall(client, base, "GET", "/system", "")
			var s SystemDTO
			return err == nil && status == 200 && json.Unmarshal(data, &s) == nil && ready(s)
		})
		capacityTimes, systemTimes := []time.Duration{}, []time.Duration{}
		for sample := 0; sample < 50; sample++ {
			data, status, _, elapsed, err := labCall(client, base, "GET", "/capacity", "")
			var c CapacityDTO
			require(t, err == nil && status == 200 && json.Unmarshal(data, &c) == nil, "capacity response", sample, status, err)
			require(t, len(c.Dimensions) == len(want), "dimensions")
			for i, d := range c.Dimensions {
				require(t, d.Name == names[i] && d.Used == want[i], "capacity seed", d.Name, d.Used, want[i])
				if i >= 5 && i <= 8 {
					require(t, d.Free == 0 && d.Exhausted, "full tree", d)
				}
			}
			require(t, c.Tightest.Name == names[5] || c.Tightest.Name == names[6] || c.Tightest.Name == names[7] || c.Tightest.Name == names[8], "tightest tree", c.Tightest)
			require(t, c.Rules.Enabled == 500000 && c.Rules.Total == 500000 && len(c.OverloadedNodes) == 0, "capacity totals", c.Rules)
			capacityTimes = append(capacityTimes, elapsed)
			data, status, _, elapsed, err = labCall(client, base, "GET", "/system", "")
			var s SystemDTO
			require(t, err == nil && status == 200 && json.Unmarshal(data, &s) == nil && ready(s), "system cached comparison", sample, status, err)
			require(t, s.Controller.RulesEnabled == 500000 && s.Controller.RulesTotal == 500000 && s.Controller.Whitelist == 0, "system totals", s.Controller)
			systemTimes = append(systemTimes, elapsed)
		}
		capP99, sysP99 := labP99(capacityTimes), labP99(systemTimes)
		t.Logf("L3-cap capacity_samples=%d capacity_p99=%s system_samples=%d system_p99=%s limit=200ms", len(capacityTimes), capP99, len(systemTimes), sysP99)
		require(t, len(capacityTimes) == 50 && len(systemTimes) == 50 && capP99 <= 200*time.Millisecond && sysP99 <= 200*time.Millisecond, "read latency")
	})
}
