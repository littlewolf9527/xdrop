package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/littlewolf9527/xdrop/node/agent/ratelimit"
	"github.com/spf13/viper"
)

func TestTD074RateLimitDivisorConfig(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
		valid bool
	}{
		{"", 0, true}, {"0", 0, true}, {"1", 1, true}, {"4096", 4096, true}, {"4097", 0, false}, {"-1", 0, false}, {"1.5", 0, false}, {"1.0", 0, false}, {"nope", 0, false}, {"true", 0, false},
	} {
		t.Run("value="+tc.value, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			text := "bpf: {}\n"
			if tc.value != "" {
				text = "bpf:\n  rate_limit_divisor: " + tc.value + "\n"
			}
			p := filepath.Join(t.TempDir(), "td074.yaml")
			if err := os.WriteFile(p, []byte(text+"auth:\n  node_api_key: test-node-key-0001\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(p)
			if err == nil {
				err = cfg.Validate()
			}
			if tc.valid {
				if err != nil || cfg.BPF.RateLimitDivisor != tc.want {
					t.Fatalf("TD074_CONFIG %q cfg=%+v err=%v want=%d", tc.value, cfg, err, tc.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), "bpf.rate_limit_divisor") {
				t.Fatalf("TD074_CONFIG invalid %q error=%v must name key", tc.value, err)
			}
		})
	}
	for _, v := range []int{-1, 4097} {
		c := Config{BPF: BPFConfig{RateLimitDivisor: v}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "0..4096") {
			t.Fatalf("TD074_CONFIG direct %d error=%v", v, err)
		}
	}
}

func TestTD074DivisorDocumentation(t *testing.T) {
	for _, name := range []string{"../../config.example.yaml", "../../README.md", "../../README.zh.md", "../../../GETTING_STARTED.md", "../../../GETTING_STARTED.zh.md"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		terms := []string{"rate_limit_divisor", "4096", "X7"}
		if strings.Contains(name, ".zh.") {
			terms = append(terms, "固定", "不多于", "放大")
		} else {
			terms = append(terms, "fixed", "no larger", "amplifies")
		}
		for _, term := range terms {
			if !strings.Contains(s, term) {
				t.Errorf("TD074_DOC %s missing %q", name, term)
			}
		}
	}
}

func TestTD074DivisorExplicitNullAndAuto(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, envMode, env string
		valid                    bool
	}{
		{name: "null", yaml: "bpf:\n  rate_limit_divisor: null\n"},
		{name: "tilde", yaml: "bpf:\n  rate_limit_divisor: ~\n"},
		{name: "empty-value", yaml: "bpf:\n  rate_limit_divisor:\n"},
		{name: "missing-key", yaml: "server:\n  port: 8080\n", valid: true},
		{name: "integer-zero", yaml: "bpf:\n  rate_limit_divisor: 0\n", valid: true},
		{name: "empty-bpf", yaml: "bpf: {}\n", valid: true},
		{name: "mixed-case-null", yaml: "BpF:\n  RaTe_LiMiT_DiViSoR: null\n"},
		{name: "uppercase-zero", yaml: "BPF:\n  RATE_LIMIT_DIVISOR: 0\n", valid: true},
		{name: "quoted-integer", yaml: "bpf:\n  rate_limit_divisor: \"8\"\n"},
		{name: "automatic-env-null", yaml: "bpf:\n  rate_limit_divisor: null\n", envMode: "automatic", env: "8"},
		{name: "automatic-env-zero", yaml: "bpf:\n  rate_limit_divisor: 0\n", envMode: "automatic", env: "8"},
		{name: "bound-env-null", yaml: "bpf:\n  rate_limit_divisor: null\n", envMode: "bound", env: "8"},
		{name: "unrelated-env", yaml: "bpf: {}\n", envMode: "automatic", valid: true},
		{name: "env-not-enabled", yaml: "bpf: {}\n", env: "8", valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			t.Setenv("TD074_R3_BPF_RATE_LIMIT_DIVISOR", tc.env)
			t.Setenv("TD074_R3_SERVER_PORT", "8088")
			if tc.envMode == "automatic" {
				viper.SetEnvPrefix("TD074_R3")
				viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
				viper.AutomaticEnv()
			} else if tc.envMode == "bound" {
				if err := viper.BindEnv("bpf.rate_limit_divisor", "TD074_R3_BPF_RATE_LIMIT_DIVISOR"); err != nil {
					t.Fatal(err)
				}
			}
			p := filepath.Join(t.TempDir(), "td074.yaml")
			if err := os.WriteFile(p, []byte(tc.yaml+"auth:\n  node_api_key: test-node-key-0001\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(p)
			if !tc.valid {
				if err == nil || !strings.Contains(err.Error(), "bpf.rate_limit_divisor") || !strings.Contains(err.Error(), "0..4096") {
					t.Fatalf("TD074_NULL %s Load error=%v want key=bpf.rate_limit_divisor range=0..4096", tc.name, err)
				}
				// Environment values remain strings: the existing strict integer
				// check must still reject them, even when they override YAML zero.
				if tc.envMode != "" && viper.Get("bpf.rate_limit_divisor") != tc.env {
					t.Fatal("TD074_NULL environment override was not exercised")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.Validate(); err != nil || cfg.BPF.RateLimitDivisor != 0 {
				t.Fatalf("TD074_AUTO %s divisor=%d error=%v want=0", tc.name, cfg.BPF.RateLimitDivisor, err)
			}
			if tc.envMode == "automatic" && cfg.Server.Port != 8088 {
				t.Fatalf("TD074_AUTO unrelated environment override port=%d want=8088", cfg.Server.Port)
			}
			online := filepath.Join(t.TempDir(), "online")
			if err := os.WriteFile(online, []byte("0-2,5"), 0600); err != nil {
				t.Fatal(err)
			}
			snapshot, err := ratelimit.Resolve(online, func() (int, error) { return 8, nil }, cfg.BPF.RateLimitDivisor)
			if err != nil || snapshot.Divisor != 4 || snapshot.Source != "auto" {
				t.Fatalf("TD074_AUTO %s snapshot=%+v error=%v want divisor=4 source=auto", tc.name, snapshot, err)
			}
		})
	}
}
