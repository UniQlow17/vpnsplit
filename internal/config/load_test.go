package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// userHome points the user config directory at a temporary one.
func userHome(t *testing.T) {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h, ".config"))
	t.Setenv("APPDATA", filepath.Join(h, "AppData"))
	t.Setenv("SUDO_USER", "")
	t.Setenv("PKEXEC_UID", "")
}

func TestSanitizeGarbageConfig(t *testing.T) {
	c := &Config{
		Corp: "bad\nname", Home: "Happ",
		CorpGateway: "1.1.1.1'; calc; '", CorpDNS: "10.1.1.1",
		Networks:       []string{"10.0.0.0/8", "evil.com", "10.0.0.1/8", "AS15632", "1.2.3.4'", "::/0"},
		Domains:        []string{"ok.example.com", nrptPayload, "10.0.0.0/8", "*.Wild.com", "../zshenv", "ok.example.com"},
		DirectNetworks: []string{"8.8.8.8", "a\tb"},
		DirectDomains:  []string{"bank.ru", "a b.ru", "пример.рф"},
	}
	warns := c.Sanitize()
	if c.Corp != "auto" || c.Home != "Happ" {
		t.Errorf("selectors: %q %q", c.Corp, c.Home)
	}
	if c.CorpGateway != "" || c.CorpDNS != "10.1.1.1" {
		t.Errorf("gateway %q dns %q", c.CorpGateway, c.CorpDNS)
	}
	eq := func(name string, got, want []string) {
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	eq("networks", c.Networks, []string{"10.0.0.0/8", "AS15632"})
	eq("domains", c.Domains, []string{"ok.example.com", "wild.com"})
	eq("direct networks", c.DirectNetworks, []string{"8.8.8.8/32"})
	eq("direct domains", c.DirectDomains, []string{"bank.ru"})
	if len(warns) < 8 {
		t.Errorf("expected a warning for every dropped value, got %d: %q", len(warns), warns)
	}
	for _, w := range warns {
		if strings.ContainsAny(w, "\n\t\x00") {
			t.Errorf("warning carries control characters: %q", w)
		}
	}
}

func TestLoadCheckedFromDisk(t *testing.T) {
	userHome(t)
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	junk := `{"corp_iface":"auto","corp_gateway":"x'y","domains":["a.x’}|out-null;calc","good.example.com"],"networks":["bogus"]}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(junk), 0o644); err != nil {
		t.Fatal(err)
	}
	c, warns, err := LoadChecked()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Domains) != 1 || c.Domains[0] != "good.example.com" || len(c.Networks) != 0 || c.CorpGateway != "" || len(warns) != 3 {
		t.Errorf("%+v %q", c, warns)
	}
	// not JSON at all is an error, not a silent default
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("\x00\x01 not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadChecked(); err == nil {
		t.Error("broken config must be an error")
	}
}

func TestLoadCheckedMissingGivesDefaults(t *testing.T) {
	userHome(t)
	c, warns, err := LoadChecked()
	if err != nil || len(warns) != 0 || c.Corp != "auto" || !c.HomeDefault {
		t.Errorf("%+v %q %v", c, warns, err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	userHome(t)
	c := New()
	c.Domains = []string{"example.com"}
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	got, warns, err := LoadChecked()
	if err != nil || len(warns) != 0 || len(got.Domains) != 1 {
		t.Errorf("%+v %q %v", got, warns, err)
	}
	dir, _ := Dir()
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestStateSanitize(t *testing.T) {
	s := &State{
		Routes: []Route{
			{Dest: "10.0.0.0/8", Iface: "tun0", Via: "corp"},
			{Dest: "10.0.0.0/8'; calc; '", Iface: "tun0"},
			{Dest: "10.0.0.0/8", Iface: "tun0", Gateway: "x"},
			{Dest: "10.0.0.0/8", Iface: "-D"},
		},
		Resolvers: []string{"corp.example.com", nrptPayload, "../x", "a b"},
		Sig:       "corp=a\nhome=b",
	}
	warns := s.Sanitize()
	// "corp.example.com" is only a valid entry on Windows, the rest never is
	if len(s.Routes) != 1 || len(s.Resolvers) > 1 || s.Sig != "" || len(warns) < 6 {
		t.Errorf("%+v %q", s, warns)
	}
}

func TestParseStateGarbage(t *testing.T) {
	if _, _, err := parseState([]byte("{{{")); err == nil {
		t.Error("expected error")
	}
	s, warns, err := parseState([]byte(`{"routes":[{"dest":"1.1.1.0/24","iface":"e"},{"dest":"x","iface":"e"}]}`))
	if err != nil || len(s.Routes) != 1 || len(warns) != 1 {
		t.Errorf("%+v %q %v", s, warns, err)
	}
}

func TestMerge(t *testing.T) {
	a := &State{Routes: []Route{{Dest: "1.1.1.0/24", Iface: "e"}}, Resolvers: []string{"z.com"}}
	b := &State{Routes: []Route{{Dest: "1.1.1.0/24", Iface: "e"}, {Dest: "2.2.2.0/24", Iface: "e"}}, Resolvers: []string{"z.com", "y.com"}, Sig: "s"}
	a.merge(b)
	if len(a.Routes) != 2 || len(a.Resolvers) != 2 || a.Sig != "s" {
		t.Errorf("%+v", a)
	}
}

// Dropping invalid rules must not lose them silently: the first Save after
// such a load keeps a copy of the file as it was.
func TestSaveAfterLossyLoadKeepsBackup(t *testing.T) {
	userHome(t)
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	orig := `{"corp_iface":"auto","home_iface":"auto","networks":[],"domains":["good.example.com","bad domain.example.com"]}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	c, warns, err := LoadChecked()
	if err != nil || len(warns) != 1 || len(c.Domains) != 1 {
		t.Fatalf("%+v %q %v", c, warns, err)
	}
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	baks, _ := filepath.Glob(filepath.Join(dir, "config.json.bak.*"))
	if len(baks) != 1 {
		t.Fatalf("backups: %v", baks)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != orig {
		t.Errorf("backup differs: %s", b)
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "bad domain") {
		t.Errorf("config still has the bad rule: %s", b)
	}
	// the second save has nothing more to protect
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	if baks, _ := filepath.Glob(filepath.Join(dir, "config.json.bak.*")); len(baks) != 1 {
		t.Errorf("another backup: %v", baks)
	}
}

func TestSaveOfCleanConfigMakesNoBackup(t *testing.T) {
	userHome(t)
	c := New()
	c.Domains = []string{"example.com"}
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	dir, _ := Dir()
	if baks, _ := filepath.Glob(filepath.Join(dir, "config.json.bak.*")); len(baks) != 0 {
		t.Errorf("unexpected backup: %v", baks)
	}
}
