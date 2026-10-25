// Package config persists user settings and the journal of routes we own.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotConfigured is returned by Load before the first `init`.
var ErrNotConfigured = errors.New("not configured yet, run: vpnsplit init")

// Config is what the user chose: which adapter is which and what goes to corp.
type Config struct {
	Corp        string   `json:"corp_iface"`
	Home        string   `json:"home_iface"`
	CorpGateway string   `json:"corp_gateway,omitempty"` // optional, on-link if empty
	CorpDNS     string   `json:"corp_dns,omitempty"`     // used to resolve corp domains
	HomeDefault bool     `json:"home_default"`           // push everything else into home VPN
	Networks    []string `json:"networks"`
	Domains     []string `json:"domains"`
}

// New returns a Config with defaults.
func New() *Config { return &Config{HomeDefault: true} }

// Dir returns (and creates) the directory that holds config and state.
func Dir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "vpnsplit")
	return p, os.MkdirAll(p, 0o755)
}

func load(name string, v any) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func save(name string, v any) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, name+".tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// Load reads the config, or returns ErrNotConfigured if there is none.
func Load() (*Config, error) {
	c := New()
	if err := load("config.json", c); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotConfigured
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	return c, nil
}

// Save writes the config atomically.
func Save(c *Config) error { return save("config.json", c) }

// Remove deletes the config file (state is untouched).
func Remove() error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(dir, "config.json"))
}
