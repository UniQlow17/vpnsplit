// Package config persists user settings and the journal of routes we own.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	SplitDNS       bool     `json:"split_dns"`              // corp zones resolve through corp DNS
	Rest           string   `json:"rest,omitempty"`         // where the traffic no rule names goes: RestHome, RestDirect or RestKeep
	Networks       []string `json:"networks"`
	Domains        []string `json:"domains"`
	DirectNetworks []string `json:"direct_networks,omitempty"` // bypass every VPN
	DirectDomains  []string `json:"direct_domains,omitempty"`
	HomeNetworks   []string `json:"home_networks,omitempty"` // into the home VPN (the list that matters when the rest goes elsewhere)
	HomeDomains    []string `json:"home_domains,omitempty"`

	// HomeDefault is the setting of versions before Rest. It is read from an
	// old file only (Sanitize turns it into Rest and clears it).
	HomeDefault *bool `json:"home_default,omitempty"`

	// lossy: Sanitize dropped or changed something that is still in the file
	// on disk. The next Save keeps a copy of that file first (see Save).
	lossy bool
}

// New returns a Config with defaults: both VPNs detected automatically.
func New() *Config { return &Config{Corp: "auto", Home: "auto", SplitDNS: true, Rest: RestHome} }

// Where the traffic that no rule names goes (Config.Rest).
const (
	// RestHome: into the home VPN (0/1 + 128/1 through it, the DNS of the home VPN).
	RestHome = "home"
	// RestDirect: past every VPN, through the physical gateway (0/1 + 128/1
	// through it); the rules "through the home VPN" say what still goes there.
	RestDirect = "direct"
	// RestKeep: left to the VPN client and the OS; no default routes and no
	// DNS for the rest are set. This is what HomeDefault=false always meant.
	RestKeep = "keep"
)

// Where a rule sends traffic (the lists of Config).
const (
	DestCorp   = "corp"
	DestDirect = "direct"
	DestHome   = "home"
)

// ValidRest reports whether s is a value of Config.Rest.
func ValidRest(s string) bool { return s == RestHome || s == RestDirect || s == RestKeep }

// ParseRest understands the spellings of the CLI and returns the canonical value.
func ParseRest(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "home", "дом", "домашний", "vpn":
		return RestHome, nil
	case "direct", "напрямую":
		return RestDirect, nil
	case "keep", "client", "не-трогать", "не трогать":
		return RestKeep, nil
	}
	return "", fmt.Errorf("%q is not a value for rest (home, direct or keep)", clip(s))
}

// RestLabel names the setting for people.
func RestLabel(rest string, ru bool) string {
	switch rest {
	case RestDirect:
		if ru {
			return "Напрямую"
		}
		return "direct"
	case RestKeep:
		if ru {
			return "Не трогать (как настроил клиент)"
		}
		return "keep (as the VPN client set it up)"
	}
	if ru {
		return "Домашний VPN"
	}
	return "home VPN"
}

// Kinds returns the kinds of rules that matter with the setting Rest: corp
// always; direct where the rest does not go direct anyway; home where the rest
// does not go into the home VPN anyway.
func (c *Config) Kinds() []string {
	switch c.Rest {
	case RestDirect:
		return []string{DestCorp, DestHome}
	case RestKeep:
		return []string{DestCorp, DestDirect, DestHome}
	}
	return []string{DestCorp, DestDirect}
}

// ListsOf returns the network and domain lists of rules of a kind (DestCorp,
// DestDirect or DestHome); nil, nil for an unknown kind.
func (c *Config) ListsOf(kind string) (nets, domains *[]string) {
	switch kind {
	case DestCorp:
		return &c.Networks, &c.Domains
	case DestDirect:
		return &c.DirectNetworks, &c.DirectDomains
	case DestHome:
		return &c.HomeNetworks, &c.HomeDomains
	}
	return nil, nil
}

// Lists returns the network and domain lists of corp or direct rules.
func (c *Config) Lists(direct bool) (nets, domains *[]string) {
	if direct {
		return c.ListsOf(DestDirect)
	}
	return c.ListsOf(DestCorp)
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
	c.Rest = "" // a file without "rest" is one of an older version: Sanitize migrates home_default
	if err := load("config.json", c); err != nil {
		if os.IsNotExist(err) {
			return New(), nil, nil
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
