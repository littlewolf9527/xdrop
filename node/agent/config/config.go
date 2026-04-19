package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/spf13/viper"
)

// placeholderPrefixes enumerates known example-config sentinel prefixes.
// Any credential starting with one of these is rejected at startup to
// prevent fresh deployments from running with known default credentials.
var placeholderPrefixes = []string{"CHANGE_ME", "change-me", "changeme", "REPLACE_ME"}

func looksLikePlaceholder(v string) bool {
	if v == "" {
		return false
	}
	upper := strings.ToUpper(v)
	for _, p := range placeholderPrefixes {
		if strings.HasPrefix(upper, strings.ToUpper(p)) {
			return true
		}
	}
	return false
}

// Config node configuration
type Config struct {
	Server      ServerConfig      `mapstructure:"server"`
	BPF         BPFConfig         `mapstructure:"bpf"`
	Auth        AuthConfig        `mapstructure:"auth"`
	FastForward FastForwardConfig `mapstructure:"fast_forward"`
}

// ServerConfig server configuration
type ServerConfig struct {
	Port      int    `mapstructure:"port"`
	Interface string `mapstructure:"interface"`
}

// BPFConfig BPF configuration
type BPFConfig struct {
	Path string `mapstructure:"path"`

	// Pinning controls whether BPF maps are pinned to /sys/fs/bpf/xdrop/ for
	// survival across agent restarts (Phase 3 of goebpf→cilium migration).
	//
	//   "auto"    — default; try pinning, silently fall back if /sys/fs/bpf is
	//               not mounted, EPERM, ENOSPC, or otherwise unusable. Rules
	//               still load, just without restart survival.
	//   "require" — fail startup if pinning cannot be enabled. Strict mode
	//               for production where restart survival is expected.
	//   "disable" — skip pinning entirely, matches pre-migration behaviour.
	Pinning string `mapstructure:"pinning"`
}

// AuthConfig authentication configuration
type AuthConfig struct {
	NodeAPIKey        string `mapstructure:"node_api_key"`        // verified when Controller sends requests to this Node
	ControllerSyncKey string `mapstructure:"controller_sync_key"` // used when Node syncs to Controller
	ControllerURL     string `mapstructure:"controller_url"`      // Controller address
}

// InterfacePair interface pair configuration (fast forward mode)
type InterfacePair struct {
	Inbound  string `mapstructure:"inbound"`   // inbound interface (WAN side)
	Outbound string `mapstructure:"outbound"`  // outbound interface (LAN side)
	FilterOn string `mapstructure:"filter_on"` // filter position: inbound / outbound / both
}

// FastForwardConfig fast forward mode configuration
type FastForwardConfig struct {
	Enabled bool            `mapstructure:"enabled"`
	Pairs   []InterfacePair `mapstructure:"pairs"`
}

// Load loads configuration
func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// set defaults
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.interface", "eth0")
	viper.SetDefault("bpf.path", "../bpf/xdrop.elf")
	viper.SetDefault("bpf.pinning", "auto")
	viper.SetDefault("fast_forward.enabled", false)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("Config file not found: %s, using defaults", configPath)
		} else {
			return nil, err
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// MustLoad loads configuration, exits on failure
func MustLoad(configPath string) *Config {
	cfg, err := Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	return cfg
}

// Validate validates configuration
func (c *Config) Validate() error {
	// Normalise + validate bpf.pinning. Empty string (no key in config.yaml)
	// maps to "auto" per the default set in Load() — this check covers
	// freshly-constructed configs that bypass viper.
	switch c.BPF.Pinning {
	case "", "auto", "require", "disable":
		// OK
	default:
		return fmt.Errorf("bpf.pinning must be one of auto|require|disable, got %q", c.BPF.Pinning)
	}

	// Reject placeholder credentials (CHANGE_ME_* etc.) from example configs.
	// Prevents fresh deployments from starting with known-to-be-default keys.
	if looksLikePlaceholder(c.Auth.NodeAPIKey) {
		return fmt.Errorf("auth.node_api_key still contains a placeholder value (%q); generate a real key before starting", c.Auth.NodeAPIKey)
	}
	// controller_sync_key only matters when the Node actively syncs to a Controller.
	// In pull-only / standalone deployments (no controller_url), the field is unused
	// and placeholder values should not block startup.
	if c.Auth.ControllerURL != "" && looksLikePlaceholder(c.Auth.ControllerSyncKey) {
		return fmt.Errorf("auth.controller_sync_key still contains a placeholder value (%q); generate a real key before starting (or leave controller_url empty for pull-only mode)", c.Auth.ControllerSyncKey)
	}

	// if fast_forward is enabled, validate fast_forward config
	if c.FastForward.Enabled {
		return c.ValidateFastForward()
	}

	// traditional mode: interface is required
	if c.Server.Interface == "" {
		return fmt.Errorf("server.interface is required in traditional mode")
	}
	return nil
}

// ValidateFastForward validates fast forward configuration
func (c *Config) ValidateFastForward() error {
	if !c.FastForward.Enabled {
		return nil
	}

	if len(c.FastForward.Pairs) == 0 {
		return fmt.Errorf("fast_forward.pairs is empty when enabled")
	}

	// current version supports only one pair
	if len(c.FastForward.Pairs) > 1 {
		return fmt.Errorf("fast_forward: only one pair is supported in this version")
	}

	pair := c.FastForward.Pairs[0]
	if pair.Inbound == "" {
		return fmt.Errorf("fast_forward.pairs[0].inbound is required")
	}
	if pair.Outbound == "" {
		return fmt.Errorf("fast_forward.pairs[0].outbound is required")
	}
	if pair.Inbound == pair.Outbound {
		return fmt.Errorf("fast_forward: inbound and outbound cannot be the same interface")
	}

	// validate filter_on value
	validFilterOn := map[string]bool{"inbound": true, "outbound": true, "both": true, "": true}
	if !validFilterOn[pair.FilterOn] {
		return fmt.Errorf("fast_forward.pairs[0].filter_on must be 'inbound', 'outbound', or 'both'")
	}

	return nil
}

// GetFilterOn returns the filter position, defaulting to inbound
func (p *InterfacePair) GetFilterOn() string {
	if p.FilterOn == "" {
		return "inbound"
	}
	return p.FilterOn
}
