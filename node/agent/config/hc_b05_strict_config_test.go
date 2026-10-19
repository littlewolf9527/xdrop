package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const hcB05Auth = "auth:\n  node_api_key: test-only-hcb05-node-key\n"

func hcB05ConfigFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "strict-test.yaml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHCB05StrictConfigReject(t *testing.T) {
	for _, tc := range []struct{ name, yaml, key string }{
		{"top_level", "foo: true\n", "foo"},
		{"bpf_typo", "bpf: {pining: require}\n", "bpf.pining"},
		{"pair_typo", "fast_forward:\n  pairs:\n    - inbound: test-in\n      outbound: test-out\n      filter_onn: inbound\n", "fast_forward.pairs[0].filter_onn"},
		{"server_typo", "server: {prot: 8080}\n", "server.prot"},
		{"bpf_null", "bpf: {pining: null}\n", "bpf.pining"},
		{"bpf_empty_map", "bpf: {pining: {}}\n", "bpf.pining"},
		{"top_null", "foo:\n", "foo"},
		{"top_empty_map", "foo: {}\n", "foo"},
		{"dotted_typo", "bpf.pining: null\n", "bpf.pining"},
		{"single_map_typo", "fast_forward: {pairs: {inbound: test-in, outbound: test-out, filter_onn: null}}\n", "fast_forward.pairs[0].filter_onn"},
		{"second_pair_typo", "fast_forward:\n  pairs:\n    - inbound: test-in\n      outbound: test-out\n    - filter_onn: {}\n", "fast_forward.pairs[1].filter_onn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			_, err := Load(hcB05ConfigFile(t, tc.yaml+hcB05Auth))
			want := `unknown config key "` + tc.key + `"`
			if err == nil || err.Error() != want {
				t.Fatalf("error=%v want %s", err, want)
			}
		})
	}
	for _, tc := range []struct {
		name, yaml string
		want       []string
	}{
		{"mixed_keys_null", "bpf: {123: null, pining: null}\n", []string{`unknown config key "bpf.123"`, `unknown config key "bpf.pining"`}},
		{"mixed_keys_empty_map", "bpf: {123: {}, pining: {}}\n", []string{`unknown config key "bpf.123"`, `unknown config key "bpf.pining"`}},
		{"auth_key_null", "auth: {node_api_kee: null}\n", []string{`unknown config key "auth.node_api_kee"`}},
		{"auth_legacy_typo_empty_map", "auth: {controller_urll: {}}\n", []string{`unknown config key "auth.controller_urll"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			_, err := Load(hcB05ConfigFile(t, tc.yaml))
			matched := false
			for _, want := range tc.want {
				matched = matched || err != nil && err.Error() == want
			}
			if !matched {
				t.Fatalf("error=%v want exactly one of %q", err, tc.want)
			}
		})
	}
}

func TestHCB05StrictConfigNonFileUnknown(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("bpf.pining", "require")
	_, err := Load(hcB05ConfigFile(t, "bpf: {pinning: auto}\n"+hcB05Auth))
	if err == nil || !strings.Contains(err.Error(), "pining") {
		t.Fatalf("non-file unknown key must reach UnmarshalExact: error=%v", err)
	}
}

func TestHCB05StrictConfigAccept(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, pinning string
		pair                bool
	}{
		{"example", "", "auto", false},
		// Same key structure as scripts/ffkit/runner.py; no script execution.
		{"ffkit_shape", "server:\n  port: 18080\n  interface: w0\nbpf:\n  main_path: test/bpf/xdrop_main.elf\n  gate_path: test/bpf/xdrop_gate.elf\n  pinning: require\n  xdp_mode: generic\n  rate_limit_divisor: 1\n" + hcB05Auth + "fast_forward:\n  enabled: true\n  pairs:\n    - inbound: w0\n      outbound: l0\n      filter_on: inbound\n", "require", true},
		{"deprecated_auth", "auth:\n  node_api_key: test-only-hcb05-node-key\n  controller_url: http://127.0.0.1:18080\n  controller_sync_key: test-only-hcb05-legacy-key\n", "auto", false},
		{"legacy_bpf_path", "bpf: {path: test/legacy.elf}\n" + hcB05Auth, "auto", false},
		{"mixed_case", "BPF: {Pinning: require}\n" + hcB05Auth, "require", false},
		{"dotted_key", "bpf.pinning: auto\n" + hcB05Auth, "auto", false},
		{"dotted_override", "bpf.pinning: disable\n" + hcB05Auth, "disable", false},
		{"single_map_pair", "fast_forward:\n  enabled: true\n  pairs: {inbound: test-in, outbound: test-out, filter_on: inbound}\n" + hcB05Auth, "auto", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			body := tc.yaml
			if tc.name == "example" {
				data, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
				if err != nil {
					t.Fatal(err)
				}
				body = strings.ReplaceAll(string(data), "CHANGE_ME_NODE_KEY", "test-only-hcb05-node-key")
			}
			var logs bytes.Buffer
			writer := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(writer) })
			cfg, err := Load(hcB05ConfigFile(t, body))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if cfg.BPF.Pinning != tc.pinning {
				t.Errorf("pinning=%q want %q", cfg.BPF.Pinning, tc.pinning)
			}
			if tc.pair && (len(cfg.FastForward.Pairs) != 1 || cfg.FastForward.Pairs[0].FilterOn != "inbound") {
				t.Error("expected one pair with filter_on=inbound")
			}
			if tc.name == "legacy_bpf_path" && cfg.BPF.Path != "test/legacy.elf" {
				t.Errorf("legacy bpf.path=%q", cfg.BPF.Path)
			}
			warn := "[WARN] auth.controller_url / auth.controller_sync_key are deprecated and ignored (已废弃、忽略)"
			wantWarnings := 0
			if tc.name == "deprecated_auth" {
				wantWarnings = 1
			}
			if count := strings.Count(logs.String(), warn); count != wantWarnings {
				t.Errorf("deprecated warning count=%d want %d", count, wantWarnings)
			}
		})
	}
}
