package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestTD073XDPModeConfig(t *testing.T) {
	for _, value := range []string{"", "auto", "native", "generic", "offload", "Native", "bogus"} {
		t.Run("mode="+value, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			path := filepath.Join(t.TempDir(), "td073.yaml")
			text := "bpf: {}\n"
			if value != "" {
				text = "bpf:\n  xdp_mode: " + value + "\n"
			}
			if err := os.WriteFile(path, []byte(text+"auth:\n  node_api_key: test-node-key-0001\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			want := value
			if want == "" {
				want = "auto"
			}
			if cfg.BPF.XDPMode != want {
				t.Fatalf("bpf.xdp_mode=%q want %q", cfg.BPF.XDPMode, want)
			}
			err = cfg.Validate()
			valid := value == "" || value == "auto" || value == "native" || value == "generic"
			if valid && err != nil {
				t.Fatal(err)
			}
			if !valid && (err == nil || !strings.Contains(err.Error(), "bpf.xdp_mode")) {
				t.Fatalf("invalid mode must report key: %v", err)
			}
		})
	}
	c := &Config{Server: ServerConfig{Interface: "td073v0"}, Auth: AuthConfig{NodeAPIKey: "test-node-key-0001"}}
	if err := c.Validate(); err != nil || c.BPF.XDPMode != "auto" {
		t.Fatalf("constructed default: %q %v", c.BPF.XDPMode, err)
	}
}
