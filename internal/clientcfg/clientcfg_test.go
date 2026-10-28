package clientcfg

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidFakeRange(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" : refused
	}{
		{"198.18.0.0/15", "198.18.0.0/15"},
		{"198.18.0.1/16", "198.18.0.0/16"},
		{"28.0.0.0/8", "28.0.0.0/8"},
		{"240.0.0.0/4", ""}, // class E: reserved
		{"0.0.0.0/0", ""},   // far too wide
		{"0.0.0.0/1", ""},   // shorter than /8
		{"128.0.0.0/7", ""}, // shorter than /8
		{"10.0.0.0/8", ""},  // private
		{"10.1.2.0/24", ""}, // private
		{"192.168.0.0/16", ""},
		{"172.16.0.0/12", ""},
		{"172.20.0.0/16", ""},
		{"127.0.0.0/8", ""},
		{"169.254.0.0/16", ""},
		{"224.0.0.0/4", ""},
		{"100.64.0.0/10", ""},   // CGNAT, Tailscale
		{"100.100.0.0/16", ""},  // inside it
		{"192.0.0.0/24", ""},    // IETF protocol assignments
		{"198.51.100.0/24", ""}, // documentation
		{"203.0.113.9/32", ""},  // documentation: the stand answers from here
		{"203.0.113.0/24", ""},
		{"2001:db8::/32", ""}, // IPv6 is not taken
	}
	for _, c := range cases {
		got, ok := ValidFakeRange(netip.MustParsePrefix(c.in))
		if c.want == "" {
			if ok {
				t.Errorf("%s accepted as %s", c.in, got)
			}
			continue
		}
		if !ok || got.String() != c.want {
			t.Errorf("%s -> %v %v, want %s", c.in, got, ok, c.want)
		}
	}
	if _, ok := ValidFakeRange(netip.Prefix{}); ok {
		t.Error("zero prefix accepted")
	}
}

func TestParseSingBox(t *testing.T) {
	const cfg = `{
	  "inbounds": [
	    {"type": "mixed", "listen": "127.0.0.1"},
	    {"type": "tun", "strict_route": true, "auto_route": true}
	  ],
	  "dns": {"fakeip": {"enabled": true, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}}
	}`
	c, err := ParseSingBox([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Tun || !c.StrictRoute || !c.FakeIP || len(c.FakeRanges) != 1 || c.FakeRanges[0].String() != "198.18.0.0/15" {
		t.Errorf("got %+v", c)
	}

	// sing-box 1.12: a server of the type fakeip
	c, err = ParseSingBox([]byte(`{"inbounds":[{"type":"tun"}],"dns":{"servers":[{"tag":"f","type":"fakeip","inet4_range":"28.0.0.0/8"}]}}`))
	if err != nil || !c.Tun || c.StrictRoute || !c.FakeIP || len(c.FakeRanges) != 1 || c.FakeRanges[0].String() != "28.0.0.0/8" {
		t.Errorf("1.12 style: %+v %v", c, err)
	}

	// fakeip block that is not enabled
	c, _ = ParseSingBox([]byte(`{"dns":{"fakeip":{"enabled":false,"inet4_range":"28.0.0.0/8"}}}`))
	if c.FakeIP || len(c.FakeRanges) != 0 {
		t.Errorf("disabled fakeip taken: %+v", c)
	}
}

func TestParseSingBoxHostile(t *testing.T) {
	bad := []string{
		``, `null`, `[]`, `"x"`, `123`, `{`, `{"inbounds": `, "\x00\x01\x02",
		`{"inbounds": "tun"}`, `{"inbounds": [1, null, "tun", [], {"type": 5}]}`,
		`{"dns": []}`, `{"dns": {"fakeip": []}}`, `{"dns": {"fakeip": {"enabled": "yes"}}}`,
		strings.Repeat("[", 100000),
		`{"inbounds":[{"type":"tun","strict_route":"true"}]}`,
	}
	for _, s := range bad {
		c, err := ParseSingBox([]byte(s)) // must not panic
		if err == nil && (c.StrictRoute || len(c.FakeRanges) > 0) {
			t.Errorf("%.40q gave %+v", s, c)
		}
	}
	// ranges that must not be taken
	for _, r := range []string{"0.0.0.0/0", "0.0.0.0/4", "10.0.0.0/8", "192.168.0.0/16", "::/0", "fc00::/18", "x", "198.18.0.0/33", "198.18.0.0/-1", "1.2.3.4", ""} {
		c, err := ParseSingBox([]byte(`{"dns":{"fakeip":{"enabled":true,"inet4_range":"` + r + `"}}}`))
		if err != nil {
			t.Fatal(err)
		}
		if !c.FakeIP || len(c.FakeRanges) != 0 {
			t.Errorf("range %q: %+v", r, c)
		}
	}
	// the number of ranges is bounded
	var b strings.Builder
	b.WriteString(`{"dns":{"servers":[`)
	for i := 0; i < 100; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"type":"fakeip","inet4_range":"` + netip.AddrFrom4([4]byte{byte(20 + i), 0, 0, 0}).String() + `/8"}`)
	}
	b.WriteString(`]}}`)
	c, _ := ParseSingBox([]byte(b.String()))
	if len(c.FakeRanges) != MaxFakeRanges {
		t.Errorf("%d ranges", len(c.FakeRanges))
	}
}

func TestParseMihomo(t *testing.T) {
	const cfg = `# clash
mixed-port: 7890
proxies:
  - name: a
    type: ss
tun:
  enable: true
  stack: mixed
  strict-route: true   # comment
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 28.0.0.1/8
  nameserver:
    - 1.1.1.1
`
	c, err := ParseMihomo([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Tun || !c.StrictRoute || !c.FakeIP || len(c.FakeRanges) != 1 || c.FakeRanges[0].String() != "28.0.0.0/8" {
		t.Errorf("block form: %+v", c)
	}

	c, err = ParseMihomo([]byte("tun: {enable: true, strict-route: true}\ndns: {enable: true, enhanced-mode: 'fake-ip', fake-ip-range: \"198.19.0.1/16\"}\n"))
	if err != nil || !c.Tun || !c.StrictRoute || !c.FakeIP || len(c.FakeRanges) != 1 || c.FakeRanges[0].String() != "198.19.0.0/16" {
		t.Errorf("flow form: %+v %v", c, err)
	}

	// tun off: strict-route means nothing
	c, _ = ParseMihomo([]byte("tun:\n  enable: false\n  strict-route: true\n"))
	if c.Tun || c.StrictRoute {
		t.Errorf("disabled tun: %+v", c)
	}
	// redir-host, and a fake-ip-range in another section
	c, _ = ParseMihomo([]byte("dns:\n  enhanced-mode: redir-host\n  fake-ip-range: 28.0.0.0/8\nother:\n  enhanced-mode: fake-ip\n"))
	if c.FakeIP || len(c.FakeRanges) != 0 {
		t.Errorf("redir-host: %+v", c)
	}
	// keys deeper than the children of the section are not its own
	c, _ = ParseMihomo([]byte("dns:\n  fallback-filter:\n    enhanced-mode: fake-ip\n"))
	if c.FakeIP {
		t.Errorf("nested key taken: %+v", c)
	}
	// a range that is not valid: fake-ip is on, no range taken
	c, _ = ParseMihomo([]byte("dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-range: 0.0.0.0/0\n"))
	if !c.FakeIP || len(c.FakeRanges) != 0 {
		t.Errorf("wide range: %+v", c)
	}
	// the DNS section of Mihomo is off unless enable is true: fake-ip means nothing then
	for _, off := range []string{"dns:'+b+'n  enhanced-mode: fake-ip'+b+'n  fake-ip-range: 28.0.0.0/8'+b+'n", "dns:'+b+'n  enable: false'+b+'n  enhanced-mode: fake-ip'+b+'n  fake-ip-range: 28.0.0.0/8'+b+'n"} {
		if c, _ = ParseMihomo([]byte(off)); c.FakeIP || len(c.FakeRanges) != 0 {
			t.Errorf("fake-ip with the DNS off: %+v", c)
		}
	}
}

func TestParseMihomoHostile(t *testing.T) {
	bad := []string{
		"", "\x00\x00", "tun:\n\tenable: true\n", ":", ": :", "tun:", "tun: {", "tun: }", "dns:\n  :\n  :: :\n",
		"- - - -\n- tun:\n", strings.Repeat("a: b\n", 10), strings.Repeat(" ", 100000) + "x: y\n",
		"tun:\n" + strings.Repeat("  enable: true\n", 1000),
		"\"unterminated: 1\n", "tun: &a\n  enable: *a\n", "tun: |\n  enable: true\n",
	}
	for _, s := range bad {
		ParseMihomo([]byte(s)) // must not panic
	}
	if _, err := ParseMihomo([]byte("tun:\n\tenable: true\n")); err == nil {
		t.Error("tab in the indentation accepted")
	}
	if _, err := ParseMihomo([]byte("a\x00b")); err == nil {
		t.Error("binary accepted")
	}
	// a very long line is an error (or nothing), not a panic
	long := "dns:\n  enhanced-mode: fake-ip\n  x: " + strings.Repeat("y", 3<<20) + "\n"
	ParseMihomo([]byte(long))
	// the many lines are bounded
	many := strings.Repeat("k: v\n", maxYAMLLines+10) + "tun:\n  enable: true\n"
	if c, _ := ParseMihomo([]byte(many)); c.Tun {
		t.Error("lines past the limit were read")
	}
}

func TestParseScutilProxy(t *testing.T) {
	const out = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://example.test/proxy.pac
  SOCKSEnable : 1
  SOCKSPort : 7891
  SOCKSProxy : 127.0.0.1
}
`
	p := ParseScutilProxy(out)
	if !p.On() || !p.Enabled || p.Server != "127.0.0.1:7890, 127.0.0.1:7891" || p.PAC != "http://example.test/proxy.pac" || p.Source != "scutil" {
		t.Errorf("%+v", p)
	}
	if p := ParseScutilProxy("<dictionary> {\n  HTTPEnable : 0\n}\n"); p.On() || !p.Known {
		t.Errorf("off: %+v", p)
	}
	if p := ParseScutilProxy(""); p.Known || p.On() {
		t.Errorf("empty: %+v", p)
	}
	if p := ParseScutilProxy("HTTPEnable : 1\nHTTPProxy : \x1b[31mevil\nHTTPPort : 99999\n"); strings.ContainsRune(p.Server, 0x1b) {
		t.Errorf("control character kept: %q", p.Server)
	}
}

func TestParseGsettingsProxy(t *testing.T) {
	const manual = `org.gnome.system.proxy autoconfig-url ''
org.gnome.system.proxy mode 'manual'
org.gnome.system.proxy use-same-proxy true
org.gnome.system.proxy.http host '127.0.0.1'
org.gnome.system.proxy.http port 7890
org.gnome.system.proxy.https host ''
org.gnome.system.proxy.https port 0
org.gnome.system.proxy.socks host '127.0.0.1'
org.gnome.system.proxy.socks port 7891
`
	p := ParseGsettingsProxy(manual)
	if !p.On() || p.Server != "127.0.0.1:7890, 127.0.0.1:7891" {
		t.Errorf("manual: %+v", p)
	}
	p = ParseGsettingsProxy("org.gnome.system.proxy mode 'auto'\norg.gnome.system.proxy autoconfig-url 'http://x.test/p.pac'\n")
	if !p.On() || p.Enabled || p.PAC != "http://x.test/p.pac" {
		t.Errorf("auto: %+v", p)
	}
	if p := ParseGsettingsProxy("org.gnome.system.proxy mode 'none'\n"); p.On() || !p.Known {
		t.Errorf("none: %+v", p)
	}
	if p := ParseGsettingsProxy("garbage\n\n"); p.Known || p.On() {
		t.Errorf("garbage: %+v", p)
	}
	// manual with no host is not a proxy
	if p := ParseGsettingsProxy("org.gnome.system.proxy mode 'manual'\n"); p.On() {
		t.Errorf("manual without host: %+v", p)
	}
}

func TestWinINETProxy(t *testing.T) {
	if p := WinINETProxy(1, "127.0.0.1:7890", ""); !p.On() || p.Server != "127.0.0.1:7890" {
		t.Errorf("%+v", p)
	}
	if p := WinINETProxy(0, "127.0.0.1:7890", ""); p.On() {
		t.Errorf("disabled but on: %+v", p)
	}
	if p := WinINETProxy(1, "  ", ""); p.On() {
		t.Errorf("no server: %+v", p)
	}
	if p := WinINETProxy(0, "", "http://wpad/x.pac"); !p.On() || p.PAC == "" {
		t.Errorf("pac: %+v", p)
	}
	if p := WinINETProxy(1, "a\x1b[2Jb\n"+strings.Repeat("x", 500), ""); strings.ContainsAny(p.Server, "\x1b\n") || len(p.Server) > 200 {
		t.Errorf("not cleaned: %q", p.Server)
	}
}

func TestOvpn(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"client\nblock-outside-dns\nremote x 1194\n", true},
		{"  Block-Outside-DNS  \n", true},
		{"push \"block-outside-dns\"\n", true},
		{"# block-outside-dns\n; block-outside-dns\n", false},
		{"remote block-outside-dns 1194\n", false},
		{"", false},
		{"block-outside-dnsx\n", false},
	} {
		if got := OvpnBlocksOutsideDNS([]byte(c.in)); got != c.want {
			t.Errorf("%q: %v", c.in, got)
		}
	}
	if !OvpnLogPushedBlockOutsideDNS([]byte("PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.0.0.1,block-outside-dns,route 10.0.0.0'")) {
		t.Error("pushed option not found")
	}
	if OvpnLogPushedBlockOutsideDNS([]byte("block-outside-dns mentioned without a reply")) {
		t.Error("mention taken for a push")
	}
	OvpnBlocksOutsideDNS([]byte(strings.Repeat("x", 3<<20))) // a line over the buffer: no panic
}

func TestParseCiscoProfile(t *testing.T) {
	const xmlText = `<?xml version="1.0"?>
<AnyConnectProfile><ClientInitialization><AlwaysOn>true</AlwaysOn>
<ConnectFailurePolicy>Closed</ConnectFailurePolicy></ClientInitialization></AnyConnectProfile>`
	p, err := ParseCiscoProfile([]byte(xmlText))
	if err != nil || !p.FailClosed || !p.AlwaysOn {
		t.Errorf("%+v %v", p, err)
	}
	p, _ = ParseCiscoProfile([]byte(`<a><ConnectFailurePolicy>Open</ConnectFailurePolicy><AlwaysOn>false</AlwaysOn></a>`))
	if p.FailClosed || p.AlwaysOn {
		t.Errorf("open: %+v", p)
	}
	// broken, with entities and a bomb of nesting: no panic, no value
	for _, s := range []string{``, `<a>`, `<!DOCTYPE x [<!ENTITY a "bbbbbbbbbb">]><AlwaysOn>&a;&a;&a;</AlwaysOn>`, strings.Repeat("<a>", 200000), "\x00\x01", `<AlwaysOn>true`} {
		p, _ := ParseCiscoProfile([]byte(s))
		if p.FailClosed {
			t.Errorf("%.30q: %+v", s, p)
		}
	}
}

func TestTunFiles(t *testing.T) {
	has := func(l []fileSpec, client, suffix string) bool {
		for _, f := range l {
			if f.client == client && strings.HasSuffix(filepath.ToSlash(f.path), suffix) {
				return true
			}
		}
		return false
	}
	l := tunFiles("linux", "/home/u/.config", "/home/u", "")
	for _, w := range [][2]string{{"sing-box", "/.config/sing-box/config.json"}, {"Mihomo", "/.config/mihomo/config.yaml"}, {"sing-box", "/etc/sing-box/config.json"},
		{"Mihomo", "clash-verge.yaml"}} {
		if !has(l, w[0], w[1]) {
			t.Errorf("linux: no %v", w)
		}
	}
	l = tunFiles("windows", `C:\Users\u\AppData\Roaming`, `C:\Users\u`, `C:\ProgramData`)
	if !has(l, "sing-box", "ProgramData/sing-box/config.json") {
		t.Errorf("windows: %v", l)
	}
	if has(tunFiles("windows", "", "", ""), "sing-box", "/etc/sing-box/config.json") {
		t.Error("linux path on windows")
	}
	for _, f := range tunFiles("darwin", "/Users/u/Library/Application Support", "/Users/u", "") {
		if !strings.HasPrefix(filepath.ToSlash(f.path), "/") && !filepath.IsAbs(f.path) {
			t.Errorf("relative path %s", f.path)
		}
	}
}

func TestGlobUser(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.json", "b.json", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "d.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	fs := fsReader{bases: []string{dir}}
	got := fs.glob(dir, false, "*.json")
	if len(got) != 2 || filepath.Base(got[0]) != "a.json" {
		t.Errorf("%v", got)
	}
	if len(fs.glob(filepath.Join(dir, "nope"), false, "*")) != 0 {
		t.Error("missing directory listed")
	}
	if len(fs.glob(t.TempDir(), false, "*")) != 0 {
		t.Error("a directory outside the profile listed")
	}
}

func TestCleanText(t *testing.T) {
	if got := clean("a\x1b[31mb\x07", 80); strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("%q", got)
	}
	if got := clean(strings.Repeat("я", 500), 10); len([]rune(got)) > 14 {
		t.Errorf("not cut: %d", len([]rune(got)))
	}
}
