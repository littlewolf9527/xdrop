package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// helper: write a temp config file and return its path. ResetForTest is
// crucial — viper's package-global state persists between tests and would
// otherwise leak SetDefault calls across cases. We also call it in the
// happy-path test to make sure the test doesn't pass for the wrong reason.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func resetViper() { viper.Reset() }

// TestConfig_StatsCacheDefaultsAppliedOnMissing is the upgrade-safety
// guarantee: a config.yaml that was perfectly valid pre-v2.6.3 (no
// stats_cache: section) MUST still load successfully after the upgrade,
// with all 7 stats_cache fields populated to their documented defaults.
func TestConfig_StatsCacheDefaultsAppliedOnMissing(t *testing.T) {
	resetViper()
	path := writeConfig(t, `
server:
  port: 8000
auth:
  external_api_key: "test-key"
  session_secret: "abcdef"
  web_username: "admin"
  web_password: "secret"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed (regression: missing stats_cache breaks upgrade): %v", err)
	}
	if cfg.StatsCache.RefreshIntervalSeconds != 5 {
		t.Fatalf("default refresh_interval_seconds = 5 expected, got %d", cfg.StatsCache.RefreshIntervalSeconds)
	}
	if cfg.StatsCache.StaleThresholdSeconds != 15 {
		t.Fatalf("default stale_threshold_seconds = 15 expected, got %d", cfg.StatsCache.StaleThresholdSeconds)
	}
	if cfg.StatsCache.PerNodeTimeoutSeconds != 2 {
		t.Fatalf("default per_node_timeout_seconds = 2 expected, got %d", cfg.StatsCache.PerNodeTimeoutSeconds)
	}
	if cfg.StatsCache.MaxConcurrency != 4 {
		t.Fatalf("default max_concurrency = 4 expected, got %d", cfg.StatsCache.MaxConcurrency)
	}
	if cfg.StatsCache.BackoffOnAllFailSeconds != 30 {
		t.Fatalf("default backoff_on_all_fail_seconds = 30 expected, got %d", cfg.StatsCache.BackoffOnAllFailSeconds)
	}
	if cfg.StatsCache.TopNCacheSize != 50 {
		t.Fatalf("default top_n_cache_size = 50 expected, got %d", cfg.StatsCache.TopNCacheSize)
	}
	if cfg.StatsCache.Disabled {
		t.Fatalf("default disabled = false expected")
	}
}

// TestConfig_StatsCacheValidationRejectsBadValues sweeps the validation
// branches. Each case rewrites a single field to an out-of-range value
// and asserts Load fails.
func TestConfig_StatsCacheValidationRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{
			"refresh_interval=0",
			`stats_cache: { refresh_interval_seconds: 0 }`,
		},
		{
			"refresh_interval>60",
			`stats_cache: { refresh_interval_seconds: 61 }`,
		},
		{
			"stale<=refresh",
			`stats_cache: { refresh_interval_seconds: 10, stale_threshold_seconds: 10 }`,
		},
		{
			"per_node_timeout>=refresh",
			`stats_cache: { refresh_interval_seconds: 5, stale_threshold_seconds: 15, per_node_timeout_seconds: 5 }`,
		},
		{
			"top_n<50",
			`stats_cache: { top_n_cache_size: 10 }`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetViper()
			path := writeConfig(t, c.yaml)
			if _, err := Load(path); err == nil {
				t.Fatalf("expected validation error for %s, got nil", c.name)
			}
		})
	}
}

// TestConfig_NoImportCycle is a structural check that proves config does
// not (transitively) depend on internal/service. Adding such a dependency
// would create a cycle (service already imports config) and prevent the
// build, but the cycle would only manifest at compile time of cmd/controller
// which is downstream of both packages — by then the breakage is far from
// the change that introduced it. This test fires immediately if any
// internal/config file gains a service import.
//
// Implementation: shell out to `go list -deps` and assert no service path
// appears. Using the Go tool here is robust against future restructures of
// the repo layout (the test doesn't bake in a specific module path).
func TestConfig_NoImportCycle(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./")
	cmd.Dir = "." // run inside internal/config
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasSuffix(line, "/controller/internal/service") {
			t.Fatalf("config imports service (cycle imminent): %s", line)
		}
	}
}

// TestConfig_LocalClockNoExternalDeps proves the rev10 commitment to NOT
// pull in clockwork or another third-party clock library. The cache uses
// an in-tree Clock interface; this test fails if anyone reintroduces an
// external dependency. We grep `go list -m -deps all` from the controller
// module rather than the source files, so vendored/required deps surface
// even when the import line lives behind a build tag.
func TestConfig_LocalClockNoExternalDeps(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "all")
	cmd.Dir = ".."
	cmd.Dir = filepath.Join("..", "..") // run at controller/ root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -m all failed: %v\n%s", err, out)
	}
	bannedSubstrings := []string{
		"jonboulle/clockwork",
		"benbjohnson/clock",
		"go-clock",
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, banned := range bannedSubstrings {
			if strings.Contains(line, banned) {
				t.Fatalf("third-party clock dependency leaked in: %s", line)
			}
		}
	}
}

// TestConfig_StatsCacheUserOverrideRespected confirms a user-supplied value
// survives the SetDefault layer. If we ever accidentally invert the order
// (Unmarshal then SetDefault) this test catches it: the user's 7 wouldn't
// be observable.
func TestConfig_StatsCacheUserOverrideRespected(t *testing.T) {
	resetViper()
	path := writeConfig(t, `
server:
  port: 8000
stats_cache:
  refresh_interval_seconds: 7
  stale_threshold_seconds: 30
  per_node_timeout_seconds: 3
  max_concurrency: 8
  backoff_on_all_fail_seconds: 45
  top_n_cache_size: 60
  disabled: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.StatsCache.RefreshIntervalSeconds != 7 {
		t.Fatalf("expected user override 7, got %d", cfg.StatsCache.RefreshIntervalSeconds)
	}
	if cfg.StatsCache.TopNCacheSize != 60 {
		t.Fatalf("expected user override 60, got %d", cfg.StatsCache.TopNCacheSize)
	}
	if !cfg.StatsCache.Disabled {
		t.Fatalf("expected disabled=true override")
	}
}
