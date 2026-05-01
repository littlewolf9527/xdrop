package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig        `mapstructure:"server"`
	Database    DatabaseConfig      `mapstructure:"database"`
	Auth        AuthConfig          `mapstructure:"auth"`
	Nodes       []NodeConfig        `mapstructure:"nodes"`
	Sync        SyncConfig          `mapstructure:"sync"`
	HealthCheck HealthCheckConfig   `mapstructure:"healthcheck"`
	SyncCheck   SyncCheckConfig     `mapstructure:"synccheck"`
	Rules       RulesConfig         `mapstructure:"rules"`
	Logging     LoggingConfig       `mapstructure:"logging"`
	StatsCache  StatsCacheRawConfig `mapstructure:"stats_cache"` // v2.6.3
}

// AuthConfig API authentication config
type AuthConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	ExternalAPIKey string `mapstructure:"external_api_key"` // external API requests (including Node→Controller sync)
	SessionSecret  string `mapstructure:"session_secret"`   // Web UI session signing secret
	WebUsername    string `mapstructure:"web_username"`     // Web UI login username
	WebPassword    string `mapstructure:"web_password"`     // Web UI login password
	SecureCookie   bool   `mapstructure:"secure_cookie"`    // Set Secure flag on session cookie (enable for HTTPS deployments)
}

// NodeConfig pre-configured node
type NodeConfig struct {
	Name     string `mapstructure:"name"`
	Endpoint string `mapstructure:"endpoint"`
	APIKey   string `mapstructure:"api_key"` // used when Controller sends requests to this Node
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type DatabaseConfig struct {
	Driver string `mapstructure:"driver"`
	DSN    string `mapstructure:"dsn"`
}

type SyncConfig struct {
	RetryCount    int           `mapstructure:"retry_count"`
	RetryInterval time.Duration `mapstructure:"retry_interval"`
	Timeout       time.Duration `mapstructure:"timeout"`
	Concurrent    int           `mapstructure:"concurrent"`
}

type HealthCheckConfig struct {
	Interval time.Duration `mapstructure:"interval"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

type SyncCheckConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

type RulesConfig struct {
	DefaultExpire   time.Duration `mapstructure:"default_expire"`
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
}

type LoggingConfig struct {
	Level string `mapstructure:"level"`
}

// StatsCacheRawConfig is the YAML representation of stats cache settings.
//
// v2.6.3 introduces an in-process aggregated rule-stats cache that periodically
// fans out to nodes in the background. All durations are stored as int seconds
// to avoid viper's "5" → 5ns trap that would happen if we used time.Duration.
// The wiring layer (cmd/controller/main.go) converts these to time.Duration
// before handing the runtime config to the service package.
//
// The config package intentionally does NOT import internal/service: service
// already imports config, so a reverse import would create a build cycle.
type StatsCacheRawConfig struct {
	RefreshIntervalSeconds  int  `mapstructure:"refresh_interval_seconds"`
	StaleThresholdSeconds   int  `mapstructure:"stale_threshold_seconds"`
	PerNodeTimeoutSeconds   int  `mapstructure:"per_node_timeout_seconds"`
	MaxConcurrency          int  `mapstructure:"max_concurrency"`
	BackoffOnAllFailSeconds int  `mapstructure:"backoff_on_all_fail_seconds"`
	TopNCacheSize           int  `mapstructure:"top_n_cache_size"`
	Disabled                bool `mapstructure:"disabled"`
}

// Validate checks the stats cache config for in-range values.
//
// All checks fire after viper.SetDefault has been applied, so a missing
// stats_cache: section in the user's config.yaml still results in valid
// defaults rather than zero-value rejections.
func (r StatsCacheRawConfig) Validate() error {
	if r.RefreshIntervalSeconds <= 0 || r.RefreshIntervalSeconds > 60 {
		return fmt.Errorf("stats_cache.refresh_interval_seconds must be 1-60, got %d", r.RefreshIntervalSeconds)
	}
	if r.StaleThresholdSeconds <= r.RefreshIntervalSeconds {
		return fmt.Errorf("stats_cache.stale_threshold_seconds (%d) must be > refresh_interval_seconds (%d)",
			r.StaleThresholdSeconds, r.RefreshIntervalSeconds)
	}
	if r.PerNodeTimeoutSeconds <= 0 || r.PerNodeTimeoutSeconds >= r.RefreshIntervalSeconds {
		return fmt.Errorf("stats_cache.per_node_timeout_seconds (%d) must be in (0, refresh_interval_seconds)",
			r.PerNodeTimeoutSeconds)
	}
	if r.MaxConcurrency <= 0 {
		return fmt.Errorf("stats_cache.max_concurrency must be > 0, got %d", r.MaxConcurrency)
	}
	if r.BackoffOnAllFailSeconds <= 0 {
		return fmt.Errorf("stats_cache.backoff_on_all_fail_seconds must be > 0, got %d", r.BackoffOnAllFailSeconds)
	}
	// top_n_cache_size must be >= the largest /rules/top?limit the API allows
	// (currently 50). If a smaller value were permitted, a legitimate limit=50
	// request would silently fall back to the full-scan slow path that D.4.5
	// is explicitly designed to avoid.
	if r.TopNCacheSize < 50 {
		return fmt.Errorf("stats_cache.top_n_cache_size must be >= 50 (matches /rules/top max limit), got %d",
			r.TopNCacheSize)
	}
	return nil
}

func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// set defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8000)
	viper.SetDefault("database.driver", "sqlite")
	viper.SetDefault("database.dsn", "./data/controller.db")
	viper.SetDefault("sync.retry_count", 3)
	viper.SetDefault("sync.retry_interval", "5s")
	viper.SetDefault("sync.timeout", "10s")
	viper.SetDefault("sync.concurrent", 10)
	viper.SetDefault("healthcheck.interval", "30s")
	viper.SetDefault("healthcheck.timeout", "5s")
	viper.SetDefault("rules.default_expire", "24h")
	viper.SetDefault("rules.cleanup_interval", "10m")
	viper.SetDefault("logging.level", "info")

	// stats_cache defaults (v2.6.3) — must be set BEFORE Unmarshal, otherwise
	// existing config.yaml files without a stats_cache: section get zero values
	// and Validate() rejects them, breaking upgrades on existing deployments.
	viper.SetDefault("stats_cache.refresh_interval_seconds", 5)
	viper.SetDefault("stats_cache.stale_threshold_seconds", 15)
	viper.SetDefault("stats_cache.per_node_timeout_seconds", 2)
	viper.SetDefault("stats_cache.max_concurrency", 4)
	viper.SetDefault("stats_cache.backoff_on_all_fail_seconds", 30)
	viper.SetDefault("stats_cache.top_n_cache_size", 50)
	viper.SetDefault("stats_cache.disabled", false)

	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("Config file not found, using defaults", "error", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if err := cfg.StatsCache.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func SetupLogging(level string) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})
	slog.SetDefault(slog.New(handler))
}
