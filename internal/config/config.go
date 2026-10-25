// Package config persists user settings and the journal of routes we own.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Config is what the user chose: which adapter is which and what goes where.
//
// Corp and Home are selectors: "auto", a VPN client name ("Check Point",
// "Happ") or an exact adapter name. Client names survive reconnects, which on
// macOS hand out a new utunN every time.
type Config struct {
	Corp           string   `json:"corp_iface"`
	Home           string   `json:"home_iface"`
	CorpGateway    string   `json:"corp_gateway,omitempty"` // optional, on-link if empty
	CorpDNS        string   `json:"corp_dns,omitempty"`     // used to resolve corp domains; detected if empty
	SplitDNS       bool     `json:"split_dns"`              // macOS: corp zones resolve through corp DNS
	HomeDefault    bool     `json:"home_default"`           // push everything else into home VPN
	Networks       []string `json:"networks"`
	Domains        []string `json:"domains"`
	DirectNetworks []string `json:"direct_networks,omitempty"` // bypass every VPN
	DirectDomains  []string `json:"direct_domains,omitempty"`
}

// New returns a Config with defaults: both VPNs detected automatically.
func New() *Config { return &Config{Corp: "auto", Home: "auto", SplitDNS: true, HomeDefault: true} }

// Lists returns the network and domain lists of corp or direct rules.
func (c *Config) Lists(direct bool) (nets, domains *[]string) {
	if direct {
		return &c.DirectNetworks, &c.DirectDomains
	}
	return &c.Networks, &c.Domains
}

// Dir returns (and creates) the directory that holds config and state.
func Dir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(d, "vpnsplit")
	if err := os.MkdirAll(p, 0o755); err != nil {
		return "", err
	}
	giveBack(p)
	return p, nil
}

// WriteUserFile writes a file for the user; under sudo it still belongs to them.
func WriteUserFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	giveBack(path)
	return nil
}

// giveBack hands a file created under sudo back to the user who ran sudo, so
// the same config can still be edited without it.
func giveBack(path string) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if os.Geteuid() == 0 && err1 == nil && err2 == nil {
		_ = os.Chown(path, uid, gid)
	}
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
	giveBack(tmp)
	return os.Rename(tmp, filepath.Join(dir, name))
}

// LoadJSON and SaveJSON keep other small files (caches) next to the config.
func LoadJSON(name string, v any) error { return load(name, v) }
func SaveJSON(name string, v any) error { return save(name, v) }

// Load reads the config; without one it returns the defaults, which work as is.
func Load() (*Config, error) {
	c := New()
	if err := load("config.json", c); err != nil {
		if os.IsNotExist(err) {
			return c, nil
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
