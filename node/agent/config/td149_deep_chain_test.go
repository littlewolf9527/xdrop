package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestTD149Config(t *testing.T) {
	for _, c := range []struct {
		name, value string
		pass, bad   bool
	}{
		{"missing", "", false, false}, {"true", "true", false, false},
		{"false", "false", true, false}, {"null", "null", false, true},
		{"quoted", `"false"`, false, true}, {"integer", "1", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			yaml := "bpf: {}\n"
			if c.value != "" {
				yaml = "bpf:\n  ipv6_deep_chain_drop: " + c.value + "\n"
			}
			path := filepath.Join(t.TempDir(), "td149.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if c.bad {
				if err == nil || !strings.Contains(err.Error(), "bpf.ipv6_deep_chain_drop must be a boolean") {
					t.Fatalf("startup error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pass := cfg.BPF.IPv6DeepChainDrop != nil && !*cfg.BPF.IPv6DeepChainDrop
			if pass != c.pass {
				t.Fatalf("pass=%t want=%t", pass, c.pass)
			}
			t.Logf("TD149_CONFIG name=%s pass=%t", c.name, pass)
		})
	}
}
