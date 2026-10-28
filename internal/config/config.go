// Package config persists user settings and the journal of routes we own.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
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

	// lossy: Sanitize dropped or changed something that is still in the file
	// on disk. The next Save keeps a copy of that file first (see Save).
	lossy bool
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

// Dir returns (and creates) the user's directory that holds the config and
// caches. The state journal does not live here: it is in a protected system
// directory (see StateDir). Under sudo/pkexec this is the directory of the
// user who ran the tool, not root's.
func Dir() (string, error) {
	p, o, err := userDir()
	if err != nil {
		return "", err
	}
	if err := ensureUserDir(p, o); err != nil {
		return "", err
	}
	return p, nil
}

// WriteUserFile writes a file for the user; under sudo it still belongs to them.
// The file is replaced atomically and a symlink at path is never followed.
// Under sudo/pkexec only paths inside the home directory of the real user
// are accepted: root must not be used to write anywhere else.
func WriteUserFile(path string, data []byte) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link, refusing to write through it", path)
	}
	o := sudoOwner()
	if o != nil {
		if _, err := relInside(o.home, filepath.Dir(path)); err != nil {
			return err
		}
	}
	return writeFileAtomic(filepath.Dir(path), filepath.Base(path), data, 0o644, o)
}

func load(name string, v any) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	b, err := readRegular(filepath.Join(dir, name))
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
	_, o, _ := userDir()
	return writeFileAtomic(dir, name, b, 0o644, o)
}

// LoadJSON and SaveJSON keep other small files (caches) next to the config.
// Whatever LoadJSON returns comes from a user-writable file: validate it.
func LoadJSON(name string, v any) error { return load(name, v) }
func SaveJSON(name string, v any) error { return save(name, v) }

// SaveCache is SaveJSON for data that can be fetched again. It is skipped
// (without an error) where writing into the user's directory is unsafe for
// the process, see cacheWritable.
func SaveCache(name string, v any) error {
	if !cacheWritable() {
		return nil
	}
	return save(name, v)
}

// LoadChecked reads the config; without one it returns the defaults, which
// work as is. Every field is validated; invalid values are dropped and
// reported in warnings.
func LoadChecked() (c *Config, warnings []string, err error) {
	c = New()
	if err := load("config.json", c); err != nil {
		if os.IsNotExist(err) {
			return c, nil, nil
		}
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	return c, c.Sanitize(), nil
}

// Load is LoadChecked without the warnings.
func Load() (*Config, error) {
	c, _, err := LoadChecked()
	return c, err
}

// Save writes the config atomically. If loading dropped invalid values (see
// Sanitize) the file on disk still has them; it is copied to
// config.json.bak.<time> first, so nothing the user typed is lost silently.
func Save(c *Config) error {
	if c.lossy {
		if err := backupConfig(); err != nil {
			return fmt.Errorf("cannot back up config.json before overwriting it: %w", err)
		}
	}
	if err := save("config.json", c); err != nil {
		return err
	}
	c.lossy = false
	return nil
}

func backupConfig() error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	b, err := readRegular(filepath.Join(dir, "config.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_, o, _ := userDir()
	name := "config.json.bak." + time.Now().UTC().Format("20060102T150405")
	return writeFileAtomic(dir, name, b, 0o600, o)
}

// Remove deletes the config file (state is untouched).
func Remove() error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(dir, "config.json"))
}
