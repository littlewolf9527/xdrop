// Package config loads the controller configuration fail-closed.
package config

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen        string
	Database      string
	SecretKeyFile string
}
type document struct {
	Listen            string    `yaml:"listen"`
	Database          string    `yaml:"database"`
	ReconcileInterval yaml.Node `yaml:"reconcile_interval"`
	Nodes             yaml.Node `yaml:"nodes"`
	SecretKeyFile     string    `yaml:"secret_key_file"`
}

func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, errors.New("cannot read configuration")
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	var raw document
	if err := d.Decode(&raw); err != nil {
		// Decoder errors may quote input values; never echo configuration text.
		return cfg, errors.New("invalid YAML configuration (empty, syntax, duplicate or unknown field)")
	}
	if raw.Nodes.Kind != 0 {
		return cfg, errors.New(`nodes moved to database; use the web UI or "node add"`)
	}
	if raw.ReconcileInterval.Kind != 0 {
		return cfg, errors.New("reconcile_interval moved to settings")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return cfg, errors.New("configuration must contain exactly one YAML document")
	}
	var problems []error
	add := func(message string) { problems = append(problems, errors.New(message)) }
	cfg.Listen, cfg.Database, cfg.SecretKeyFile = raw.Listen, raw.Database, raw.SecretKeyFile
	_, port, err := net.SplitHostPort(raw.Listen)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 {
		add("listen must be host:port with port 1..65535")
	}
	if !filepath.IsAbs(raw.Database) {
		add("database must be an absolute path")
	}
	if !filepath.IsAbs(raw.SecretKeyFile) {
		add("secret_key_file must be an absolute path")
	}
	if len(problems) > 0 {
		return Config{}, errors.Join(problems...)
	}
	return cfg, nil
}
