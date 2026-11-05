package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// home_default=false never added anything for the rest of the traffic: it is
// "keep"; true pushed everything into the home VPN: it is "home".
func TestRestMigratesHomeDefault(t *testing.T) {
	for _, tc := range []struct {
		json string
		want string
		warn bool
	}{
		{`{"home_default": true}`, RestHome, true},
		{`{"home_default": false}`, RestKeep, true},
		{`{}`, RestHome, false},
		{`{"rest": "direct"}`, RestDirect, false},
		{`{"rest": "keep", "home_default": true}`, RestKeep, false}, // the new key wins
		{`{"rest": "nonsense"}`, RestHome, true},
	} {
		userHome(t)
		dir, err := Dir()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(tc.json), 0o644); err != nil {
			t.Fatal(err)
		}
		c, warns, err := LoadChecked()
		if err != nil || c.Rest != tc.want || (len(warns) > 0) != tc.warn || c.HomeDefault != nil {
			t.Errorf("%s: rest %q warns %q err %v", tc.json, c.Rest, warns, err)
			continue
		}
		// saved once, the old key is gone and nothing is migrated again
		if err := Save(c); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
		if strings.Contains(string(b), "home_default") {
			t.Errorf("%s: home_default is still in the file:\n%s", tc.json, b)
		}
		c2, warns, err := LoadChecked()
		if err != nil || c2.Rest != tc.want || len(warns) != 0 {
			t.Errorf("%s: after save: rest %q warns %q err %v", tc.json, c2.Rest, warns, err)
		}
	}
}

func TestRestKinds(t *testing.T) {
	for rest, want := range map[string][]string{
		RestHome:   {DestCorp, DestDirect},
		RestDirect: {DestCorp, DestHome},
		RestKeep:   {DestCorp, DestDirect, DestHome},
	} {
		if got := (&Config{Rest: rest}).Kinds(); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v, want %v", rest, got, want)
		}
	}
}

func TestParseRest(t *testing.T) {
	for in, want := range map[string]string{"home": RestHome, " Direct ": RestDirect, "keep": RestKeep, "напрямую": RestDirect} {
		if got, err := ParseRest(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := ParseRest("true"); err == nil {
		t.Error("a bool is not a value of rest")
	}
}

func TestHomeRulesAreSanitizedAndFiled(t *testing.T) {
	c := New()
	added, errs := c.ImportRules("[home]\n10.9.0.0/16\nvideo.example.com\n[corp]\n10.0.0.0/8\n[direct]\nbank.ru\n")
	if added != 4 || len(errs) != 0 || len(c.HomeNetworks) != 1 || len(c.HomeDomains) != 1 || len(c.DirectDomains) != 1 {
		t.Fatalf("%d %v %+v", added, errs, c)
	}
	if out := c.ExportRules(); !strings.Contains(out, "[home]\n10.9.0.0/16\nvideo.example.com") {
		t.Errorf("export:\n%s", out)
	}
	c.HomeNetworks = append(c.HomeNetworks, "evil.com", "::/0")
	c.HomeDomains = append(c.HomeDomains, "10.0.0.0/8", "a b")
	if w := c.Sanitize(); len(w) != 4 || len(c.HomeNetworks) != 1 || len(c.HomeDomains) != 1 {
		t.Errorf("%q %+v", w, c)
	}
}

func TestValidateRouteV6(t *testing.T) {
	ok := []Route{
		{Dest: "::/1", Iface: "wghome", Via: "home", Metric: 1},
		{Dest: "8000::/1", Iface: "wghome", Gateway: "fe80::1", Via: "home"},
	}
	for _, r := range ok {
		if err := ValidateRoute(r); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := []Route{
		{Dest: "::ffff:10.0.0.0/104", Iface: "x"},            // v4 in v6
		{Dest: "fe80::1%eth0/128", Iface: "x"},               // zone
		{Dest: "::/1", Iface: "x", Gateway: "10.0.0.1"},      // gateway of the other family
		{Dest: "10.0.0.0/8", Iface: "x", Gateway: "fe80::1"}, // and the other way
		{Dest: "::/1", Iface: "x", Gateway: "::"},            // unspecified next hop
		{Dest: "2001:db8::/32;calc", Iface: "x"},
	}
	for _, r := range bad {
		if ValidateRoute(r) == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestTun6Journal(t *testing.T) {
	s := &State{Tun6: &Tunnels6{Teredo: "client", SixToFour: "Automatic", ISATAP: "x; calc"}}
	if s.Empty() {
		t.Fatal("a journal with settings to restore is not empty")
	}
	w := s.Sanitize()
	if len(w) != 1 || s.Tun6.Teredo != "Client" || s.Tun6.SixToFour != "Automatic" || s.Tun6.ISATAP != "" {
		t.Errorf("%q %+v", w, s.Tun6)
	}
	s = &State{Tun6: &Tunnels6{Teredo: "bogus"}}
	s.Sanitize()
	if s.Tun6 != nil || !s.Empty() {
		t.Errorf("nothing valid is left: %+v", s.Tun6)
	}
}

func TestResolverEntryRoot(t *testing.T) {
	for goos, id := range map[string]string{"windows": ".", "linux": "domain wghome ."} {
		if !validResolverEntry(goos, id) {
			t.Errorf("%s: %q must be valid", goos, id)
		}
	}
	for goos, id := range map[string]string{"windows": "..", "linux": "domain wghome ..", "darwin": "/etc/resolver/."} {
		if validResolverEntry(goos, id) {
			t.Errorf("%s: %q must be invalid", goos, id)
		}
	}
}

// Sanitize on its own (not through the loader): the old key becomes the new one
// and is cleared, an empty "rest" with no old key is the default, a nonsense one
// is replaced, and every change is a warning.
func TestSanitizeMigratesRest(t *testing.T) {
	no, yes := false, true
	for _, tc := range []struct {
		name string
		c    Config
		want string
		warn bool
	}{
		{"false and no rest", Config{Corp: "auto", Home: "auto", HomeDefault: &no}, RestKeep, true},
		{"true and no rest", Config{Corp: "auto", Home: "auto", HomeDefault: &yes}, RestHome, true},
		{"no old key, no rest", Config{Corp: "auto", Home: "auto"}, RestHome, false},
		{"the new key wins", Config{Corp: "auto", Home: "auto", Rest: RestDirect, HomeDefault: &yes}, RestDirect, false},
		{"nonsense", Config{Corp: "auto", Home: "auto", Rest: "x; calc"}, RestHome, true},
	} {
		c := tc.c
		warns := c.Sanitize()
		if c.Rest != tc.want || c.HomeDefault != nil || (len(warns) > 0) != tc.warn {
			t.Errorf("%s: rest %q home_default %v warns %q", tc.name, c.Rest, c.HomeDefault, warns)
		}
		if c.lossy != tc.warn {
			t.Errorf("%s: lossy %v", tc.name, c.lossy)
		}
	}
}

// A migration that changed the meaning of a file counts as lossy: the first
// Save keeps a copy of the old file, and the second has nothing to keep.
func TestMigrationMakesABackupOnSave(t *testing.T) {
	userHome(t)
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	const orig = `{"corp_iface":"auto","home_iface":"auto","home_default":false}`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	c, warns, err := LoadChecked()
	if err != nil || c.Rest != RestKeep || len(warns) != 1 || !c.lossy {
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
		t.Errorf("the backup is not the old file: %s", b)
	}
	if err := Save(c); err != nil {
		t.Fatal(err)
	}
	if baks, _ = filepath.Glob(filepath.Join(dir, "config.json.bak.*")); len(baks) != 1 {
		t.Errorf("a second backup: %v", baks)
	}
	// a file that says nothing about the rest, with nothing else wrong, loses nothing
	if err := os.WriteFile(path, []byte(`{"corp_iface":"auto","home_iface":"auto"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, warns, err = LoadChecked()
	if err != nil || c.Rest != RestHome || len(warns) != 0 || c.lossy {
		t.Errorf("%+v %q %v", c, warns, err)
	}
}
