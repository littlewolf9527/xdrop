package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestNSHitsConfig(t *testing.T) {
	for _, value := range []string{"missing", "5", "20", "1000", "0", "1001", "-1", "1.5", "null", "\"5\""} {
		t.Run(value, func(t *testing.T) {
			viper.Reset()
			defer viper.Reset()
			body := "server:\n  interface: eth0\n"
			if value != "missing" {
				body += "  hits_rate_limit: " + value + "\n"
			}
			path := filepath.Join(t.TempDir(), "config.example.yaml")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			valid := value == "missing" || value == "5" || value == "20" || value == "1000"
			pass := (err == nil) == valid
			if valid && err == nil {
				want := 20
				if value == "5" {
					want = 5
				}
				if value == "1000" {
					want = 1000
				}
				pass = pass && cfg.Server.HitsRateLimit == want
			} else if err != nil {
				pass = pass && strings.Contains(err.Error(), "server.hits_rate_limit")
			}
			t.Logf("NS_CELL class=behavior name=rate_config value=%s valid=%t pass=%t", value, valid, pass)
			if !pass {
				t.Fatal(cfg, err)
			}
		})
	}
	cfg := Config{Server: ServerConfig{Interface: "eth0"}, Auth: AuthConfig{NodeAPIKey: "test-node-key-0001"}}
	if err := cfg.Validate(); err != nil || cfg.Server.HitsRateLimit != 20 {
		t.Fatal(cfg, err)
	}
}
