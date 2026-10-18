package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCtlCut3Config(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "node-key")
	const secret = "KEY-C3A-MUST-NOT-LEAK"
	if err := os.WriteFile(key, []byte(secret+"\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("listen: 192.0.2.1:18081\ndatabase: %s\nsecret_key_file: %s\n", filepath.Join(dir, "controller.db"), key)
	load := func(text string) (Config, error) {
		t.Helper()
		path := filepath.Join(dir, "config.example.yaml")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	t.Run("CF-ok", func(t *testing.T) {
		{
			cfg, err := load(base)
			if err != nil || cfg.Listen != "192.0.2.1:18081" || cfg.Database != filepath.Join(dir, "controller.db") || cfg.SecretKeyFile != key {
				t.Fatalf("configuration mismatch: %+v %v", cfg, err)
			}
			if strings.Contains(fmt.Sprintf("%+v", cfg), secret) {
				t.Fatal("configuration formatting leaked secret")
			}
		}
	})
	t.Run("CF-reject", func(t *testing.T) {
		cases := map[string]string{
			"empty": "", "syntax": "listen: [", "unknown": base + "mystery: true\n", "old-key": base + "default_expire: 1h\n",
			"nested": base + "    mystery: true\n", "duplicate": base + "listen: 192.0.2.3:80\n", "multi": base + "---\n{}\n",
			"relative-db":   strings.Replace(base, filepath.Join(dir, "controller.db"), "controller.db", 1),
			"key-relative":  strings.Replace(base, key, "relative-key", 1),
			"key-missing":   strings.Replace(base, "secret_key_file: "+key, "", 1),
			"actor-missing": base, "actor-false": base + "insecure_dev_actor_header: false\n", "actor-true": base + "insecure_dev_actor_header: true\n",
			"interval": base + "reconcile_interval: 59s\n", "interval-valid": base + "reconcile_interval: 7m\n", "interval-null": base + "reconcile_interval: null\n", "bad-duration": base + "reconcile_interval: seven\n", "listen": strings.Replace(base, "192.0.2.1:18081", "bad", 1),
			"nodes": base + "nodes: []\n", "nodes-null": base + "nodes: null\n", "nodes-map": base + "nodes: {}\n",
		}
		for name, input := range cases {
			_, err := load(input)
			if name == "actor-missing" {
				if err != nil {
					t.Error(err)
				}
				continue
			}
			if err == nil {
				t.Errorf("%s accepted", name)
			} else if strings.Contains(err.Error(), secret) {
				t.Errorf("%s leaked key", name)
			}
			if strings.HasPrefix(name, "interval") || name == "bad-duration" {
				if err == nil || err.Error() != "reconcile_interval moved to settings" {
					t.Errorf("old key rejection: %v", err)
				}
			}
			if strings.HasPrefix(name, "nodes") && (err == nil || err.Error() != `nodes moved to database; use the web UI or "node add"`) {
				t.Errorf("old nodes rejection: %v", err)
			}
		}
		if _, err := Load(filepath.Join(dir, "absent.example.yaml")); err == nil {
			t.Error("unreadable file accepted")
		}
		_, err := load("listen: bad\ndatabase: relative\n")
		if err != nil && strings.Contains(err.Error(), "认证未实现") {
			t.Error("obsolete authentication check")
		}
		for _, field := range []string{"listen", "database", "secret_key_file"} {
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Errorf("missing aggregated error %s: %v", field, err)
			}
		}
	})
}
