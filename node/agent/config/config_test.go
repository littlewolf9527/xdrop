package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Node authentication still rejects placeholder credentials.
func TestValidate_RejectsPlaceholderKeys(t *testing.T) {
	for key, rejected := range map[string]bool{"abc123def456": false, "CHANGE_ME_NODE_KEY": true, "change-me-node": true, "Changeme123": true, "REPLACE_ME_KEY": true, "": true, " \t\n": true} {
		t.Run(key, func(t *testing.T) {
			cfg := &Config{Server: ServerConfig{Interface: "eth0"}, Auth: AuthConfig{NodeAPIKey: key}}
			if err := cfg.Validate(); (err != nil) != rejected {
				t.Fatalf("Validate() err=%v wantErr=%v", err, rejected)
			}
		})
	}
}

func TestLooksLikePlaceholder(t *testing.T) {
	cases := map[string]bool{
		"":                   false,
		"real-key-abcdef":    false,
		"admin":              false,
		"CHANGE_ME":          true,
		"CHANGE_ME_NODE_KEY": true,
		"change-me":          true,
		"changeme":           true,
		"Changeme":           true,
		"REPLACE_ME_SECRET":  true,
		"replace_me":         true,
	}
	for input, want := range cases {
		if got := looksLikePlaceholder(input); got != want {
			t.Errorf("looksLikePlaceholder(%q) = %v, want %v", input, got, want)
		}
	}
}

// A real child process must reach the sentinel after Load and Validate.
func TestAPIFinalLegacyConfigWarning(t *testing.T) {
	if path := os.Getenv("P7_CONFIG_CHILD"); path != "" {
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("P7_CONFIG_CONTINUED")
		return
	}
	for _, keys := range []string{"controller_url: ignored-sentinel", "controller_sync_key: ignored-sentinel", "controller_url: ignored-sentinel\n  controller_sync_key: ignored-sentinel"} {
		path := filepath.Join(t.TempDir(), "legacy.yaml")
		if err := os.WriteFile(path, []byte("server:\n  interface: eth0\nauth:\n  node_api_key: test-node-key-0001\n  "+keys+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestAPIFinalLegacyConfigWarning$", "-test.v")
		cmd.Env = append(os.Environ(), "P7_CONFIG_CHILD="+path)
		out, err := cmd.CombinedOutput()
		text := string(out)
		if err != nil || strings.Count(text, "[WARN]") != 1 || !strings.Contains(text, "已废弃、忽略") || !strings.Contains(text, "P7_CONFIG_CONTINUED") || strings.Contains(text, "ignored-sentinel") {
			t.Fatalf("legacy process: %v %s", err, out)
		}
	}
	t.Log("CLOSEOUT_CONFIG_WARN cases=3 continued=3 warn_lines=3 values_leaked=0")
}
