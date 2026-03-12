package config

import (
	"log/slog"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	Database    DatabaseConfig    `mapstructure:"database"`
	Auth        AuthConfig        `mapstructure:"auth"`
	Nodes       []NodeConfig      `mapstructure:"nodes"`
	Sync        SyncConfig        `mapstructure:"sync"`
	HealthCheck HealthCheckConfig `mapstructure:"healthcheck"`
	SyncCheck   SyncCheckConfig   `mapstructure:"synccheck"`
	Rules       RulesConfig       `mapstructure:"rules"`
	Logging     LoggingConfig     `mapstructure:"logging"`
}

// AuthConfig API authentication config
type AuthConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	ExternalAPIKey string `mapstructure:"external_api_key"` // external API requests (including Node→Controller sync)
	SessionSecret  string `mapstructure:"session_secret"`   // Web UI session signing secret
	WebUsername    string `mapstructure:"web_username"`     // Web UI login username
	WebPassword    string `mapstructure:"web_password"`     // Web UI login password
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

	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("Config file not found, using defaults", "error", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
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
