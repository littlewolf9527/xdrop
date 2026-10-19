package config

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
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
	HitsRateLimit int    `mapstructure:"hits_rate_limit"`
	Port          int    `mapstructure:"port"`
	Interface     string `mapstructure:"interface"`
}

// BPFConfig BPF configuration
type BPFConfig struct {
	Path string `mapstructure:"path"` // deprecated: use MainPath + GatePath

	// Phase 8 dual-ELF: explicit paths for main and gate ELF files.
	MainPath string `mapstructure:"main_path"` // xdrop_main.elf (blacklist/CIDR/rate/anomaly)
	GatePath string `mapstructure:"gate_path"` // xdrop_gate.elf (whitelist 31-combo gate)

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
	// XDPMode selects auto (default), native (no fallback), or generic.
	XDPMode           string `mapstructure:"xdp_mode"`
	RateLimitDivisor  int    `mapstructure:"rate_limit_divisor"` // 0=system online CPUs; 1..4096=override
	IPv6DeepChainDrop *bool  `mapstructure:"ipv6_deep_chain_drop"`
}

// AuthConfig authentication configuration
type AuthConfig struct {
	NodeAPIKey string `mapstructure:"node_api_key"` // verified when Controller sends requests to this Node
	// deprecated: accepted and ignored; Load warns
	LegacyControllerURL string `mapstructure:"controller_url"`
	// deprecated: accepted and ignored; Load warns
	LegacyControllerSyncKey string `mapstructure:"controller_sync_key"`
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
	viper.SetDefault("server.hits_rate_limit", 20)
	viper.SetDefault("bpf.path", "../bpf/xdrop.elf")           // deprecated
	viper.SetDefault("bpf.main_path", "../bpf/xdrop_main.elf") // Phase 8
	viper.SetDefault("bpf.gate_path", "../bpf/xdrop_gate.elf") // Phase 8
	viper.SetDefault("bpf.pinning", "auto")
	viper.SetDefault("bpf.xdp_mode", "auto")
	viper.SetDefault("bpf.rate_limit_divisor", 0)
	viper.SetDefault("fast_forward.enabled", false)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("Config file not found: %s, using defaults", configPath)
		} else {
			return nil, err
		}
	} else if viper.ConfigFileUsed() != "" {
		data, err := os.ReadFile(viper.ConfigFileUsed())
		if err != nil {
			return nil, err
		}
		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		if err := checkConfigKeys(raw, reflect.TypeOf(Config{}), ""); err != nil {
			return nil, err
		}
	}

	if viper.InConfig("auth.controller_url") || viper.InConfig("auth.controller_sync_key") {
		log.Printf("[WARN] auth.controller_url / auth.controller_sync_key are deprecated and ignored (已废弃、忽略)")
	}

	// Get falls back to the default for a null leaf; inspect its parent first
	// so an explicitly empty value cannot silently become auto.
	if value, present := viper.GetStringMap("bpf")["rate_limit_divisor"]; present && value == nil {
		return nil, fmt.Errorf("bpf.rate_limit_divisor must be an integer in 0..4096")
	}
	switch viper.Get("bpf.rate_limit_divisor").(type) {
	case int, int64, uint64:
	default:
		return nil, fmt.Errorf("bpf.rate_limit_divisor must be an integer in 0..4096")
	}

	if value, present := viper.GetStringMap("bpf")["ipv6_deep_chain_drop"]; present {
		if _, ok := value.(bool); !ok {
			return nil, fmt.Errorf("bpf.ipv6_deep_chain_drop must be a boolean")
		}
	}
	var cfg Config
	if value, present := viper.GetStringMap("server")["hits_rate_limit"]; present && value == nil {
		return nil, fmt.Errorf("server.hits_rate_limit must be an integer in 1..1000")
	}
	switch viper.Get("server.hits_rate_limit").(type) {
	case int, int64, uint64:
	default:
		return nil, fmt.Errorf("server.hits_rate_limit must be an integer in 1..1000")
	}
	if err := viper.UnmarshalExact(&cfg); err != nil {
		return nil, err
	}

	if cfg.Server.HitsRateLimit < 1 || cfg.Server.HitsRateLimit > 1000 {
		return nil, fmt.Errorf("server.hits_rate_limit must be an integer in 1..1000")
	}
	return &cfg, nil
}

// checkConfigKeys checks the original YAML, including keys Viper drops when
// their values are null or empty maps. Value validation remains with Load.
func checkConfigKeys(value any, typ reflect.Type, path string) error {
	if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Struct {
		items, ok := value.([]any)
		if !ok {
			// mapstructure weakly decodes a single map as a one-element slice.
			items = []any{value}
		}
		for i, item := range items {
			if err := checkConfigKeys(item, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	}
	keys, ok := value.(map[string]any)
	if !ok {
		mixed, ok := value.(map[any]any)
		if !ok {
			return nil
		}
		keys = make(map[string]any, len(mixed))
		for key, child := range mixed {
			keys[fmt.Sprint(key)] = child
		}
	}
	for name, child := range keys {
		name = strings.ToLower(name)
		// Viper treats dots in YAML keys as path separators.
		if head, tail, dotted := strings.Cut(name, "."); dotted {
			name, child = head, map[string]any{tail: child}
		}
		childPath := name
		if path != "" {
			childPath = path + "." + name
		}
		var fieldType reflect.Type
		if typ.Kind() == reflect.Struct {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if strings.ToLower(field.Tag.Get("mapstructure")) == name {
					fieldType = field.Type
					break
				}
			}
		}
		if fieldType == nil {
			return fmt.Errorf("unknown config key %q", childPath)
		}
		if err := checkConfigKeys(child, fieldType, childPath); err != nil {
			return err
		}
	}
	return nil
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
	if c.Server.HitsRateLimit == 0 {
		c.Server.HitsRateLimit = 20 // directly constructed configurations retain defaults
	}
	if c.Server.HitsRateLimit < 1 || c.Server.HitsRateLimit > 1000 {
		return fmt.Errorf("server.hits_rate_limit must be an integer in 1..1000")
	}
	if c.BPF.RateLimitDivisor < 0 || c.BPF.RateLimitDivisor > 4096 {
		return fmt.Errorf("bpf.rate_limit_divisor must be an integer in 0..4096, got %d", c.BPF.RateLimitDivisor)
	}
	if c.BPF.XDPMode == "" {
		c.BPF.XDPMode = "auto"
	}
	switch c.BPF.XDPMode {
	case "auto", "native", "generic":
	default:
		return fmt.Errorf("bpf.xdp_mode must be one of auto|native|generic, got %q", c.BPF.XDPMode)
	}

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
	if strings.TrimSpace(c.Auth.NodeAPIKey) == "" {
		return fmt.Errorf("auth.node_api_key is empty; generate a real key before starting")
	}
	if c.Auth.NodeAPIKey != strings.Trim(c.Auth.NodeAPIKey, " \t\r\n\v\f") {
		return fmt.Errorf("auth.node_api_key has leading or trailing whitespace; HTTP clients cannot send it")
	}
	if looksLikePlaceholder(c.Auth.NodeAPIKey) {
		return fmt.Errorf("auth.node_api_key still contains a placeholder value (%q); generate a real key before starting", c.Auth.NodeAPIKey)
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
