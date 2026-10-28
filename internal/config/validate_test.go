package config

import (
	"strings"
	"testing"
)

// the payload that closed the quote with a Unicode apostrophe in PowerShell
const nrptPayload = "a.x’}|out-null;calc;get-dnsclientnrptrule|?{’"

var badDomains = []string{
	nrptPayload,
	"a.x‘b.com", "a.x‚b.com", "a.x‛b.com", // PowerShell single quotes
	"a.x“b.com", "a.x”b.com",
	"a.com\tb.com", "a\tb.com", "a.com\r\nb.com", "a.com\x00",
	"../zshenv.com", "..", "a/../b.com", "a/b.com", "a\\b.com", "/etc/passwd",
	"a b.com", "a'b.com", "a\"b.com", "a;b.com", "a$b.com", "a`b.com",
	"a:b.com", "a%b.com", "a,b.com",
	"пример.рф", "bücher.de", "a​.com", // non-ASCII must come as punycode
	"-.", ".", ".a.com", "a..com", "*.", "**.a.com", "a.*.com",
	strings.Repeat("a", 64) + ".com",
	strings.Repeat("a.", 130) + "com",
}

func TestValidDomainRejects(t *testing.T) {
	for _, d := range badDomains {
		if ValidDomain(d) {
			t.Errorf("ValidDomain(%q) = true", d)
		}
		if _, _, err := NormalizeRule(d); err == nil {
			t.Errorf("NormalizeRule(%q) accepted it", d)
		}
	}
}

func TestValidDomainAccepts(t *testing.T) {
	for _, d := range []string{"example.com", "a-b.example.com", "xn--e1afmkfd.xn--p1ai", "*.example.com", "a", "10.example.com", strings.Repeat("a", 63) + ".com"} {
		if !ValidDomain(d) {
			t.Errorf("ValidDomain(%q) = false", d)
		}
	}
	if ValidZone("*.example.com") {
		t.Error("a zone must not have a wildcard")
	}
}

func TestNormalizeRuleStrict(t *testing.T) {
	tests := []struct {
		in    string
		isNet bool
		want  string
		ok    bool
	}{
		{"Example.COM.", false, "example.com", true},
		{"  *.Example.com ", false, "example.com", true},
		{"10.0.0.0/8", true, "10.0.0.0/8", true},
		{"::ffff:1.2.3.4", false, "", false},
		{"1.2.3.4/33", false, "", false},
		{"1.2.3.04", false, "", false}, // leading zero: ambiguous
		{"AS0", false, "", false},
		{"AS99999999999999", false, "", false},
		{"AS15632", true, "AS15632", true},
		{"fe80::1%eth0", false, "", false},
		{nrptPayload, false, "", false},
	}
	for _, tt := range tests {
		isNet, got, err := NormalizeRule(tt.in)
		if (err == nil) != tt.ok || got != tt.want || (tt.ok && isNet != tt.isNet) {
			t.Errorf("NormalizeRule(%q) = %v %q %v", tt.in, isNet, got, err)
		}
	}
}

func TestParseIPv4(t *testing.T) {
	for _, in := range []string{"1.2.3.4", "192.168.0.1"} {
		if got, err := ParseIPv4(in); err != nil || got != in {
			t.Errorf("ParseIPv4(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "1.2.3", "1.2.3.4.5", "::1", "::ffff:1.2.3.4", "1.2.3.4 ", "1.2.3.4'; calc; '",
		"1.2.3.4’", "1.2.3.4\n", "1.2.3.4/24", "01.2.3.4", "1.2.3.256", "fe80::1%eth0"} {
		if got, err := ParseIPv4(in); err == nil {
			t.Errorf("ParseIPv4(%q) = %q, want error", in, got)
		}
	}
}

func TestParseCIDR4(t *testing.T) {
	if got, err := ParseCIDR4("10.1.2.3/8"); err != nil || got != "10.0.0.0/8" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, in := range []string{"", "10.0.0.0", "10.0.0.0/33", "::/0", "10.0.0.0/8\n", "10.0.0.0/8'", "10.0.0.0/8’"} {
		if _, err := ParseCIDR4(in); err == nil {
			t.Errorf("ParseCIDR4(%q) accepted", in)
		}
	}
}

func TestValidIface(t *testing.T) {
	for _, s := range []string{"Ethernet", "Беспроводная сеть", "Wi-Fi 2", "utun3", "eth0"} {
		if !ValidIface(s) {
			t.Errorf("ValidIface(%q) = false", s)
		}
	}
	for _, s := range []string{"", "-rf", "a\nb", "a\x00b", "a\tb", "a b", strings.Repeat("x", 300), "a\xffb"} {
		if ValidIface(s) {
			t.Errorf("ValidIface(%q) = true", s)
		}
	}
}

func TestParseBool(t *testing.T) {
	for _, s := range []string{"true", "TRUE", "yes", "Yes", "1", "да", "Да", "on", " on "} {
		if v, err := ParseBool(s); err != nil || !v {
			t.Errorf("ParseBool(%q) = %v, %v", s, v, err)
		}
	}
	for _, s := range []string{"false", "no", "NO", "0", "нет", "Нет", "off"} {
		if v, err := ParseBool(s); err != nil || v {
			t.Errorf("ParseBool(%q) = %v, %v", s, v, err)
		}
	}
	for _, s := range []string{"", "maybe", "tru", "2", "yes please", "y"} {
		if _, err := ParseBool(s); err == nil {
			t.Errorf("ParseBool(%q) accepted", s)
		}
	}
}

func TestValidateRoute(t *testing.T) {
	good := []Route{
		{Dest: "10.0.0.0/8", Iface: "Ethernet", Gateway: "10.0.0.1", Via: "corp"},
		{Dest: "0.0.0.0/1", Iface: "Беспроводная сеть", Via: "home"},
	}
	for _, r := range good {
		if err := ValidateRoute(r); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := []Route{
		{Dest: "10.0.0.0/8'", Iface: "x"},
		{Dest: "10.0.0.0/8", Iface: ""},
		{Dest: "10.0.0.0/8", Iface: "-x"},
		{Dest: "10.0.0.0/8", Iface: "x", Gateway: "1.1.1.1'; calc; '"},
		{Dest: "10.0.0.0/8", Iface: "x", Gateway: "::1"},
		{Dest: "10.0.0.0/8", Iface: "x", Via: "elsewhere"},
		{Dest: "::/0", Iface: "x"},
	}
	for _, r := range bad {
		if err := ValidateRoute(r); err == nil {
			t.Errorf("ValidateRoute(%+v) accepted", r)
		}
	}
}

func TestValidResolverEntry(t *testing.T) {
	cases := []struct {
		goos, id string
		ok       bool
	}{
		{"windows", "corp.example.com", true},
		{"windows", nrptPayload, false},
		{"windows", "*.example.com", false},
		{"windows", "a b.com", false},
		{"darwin", "/etc/resolver/corp.example.com", true},
		{"darwin", "/etc/resolver/../zshenv", false},
		{"darwin", "/etc/resolver/../../Users/x/.zshenv", false},
		{"darwin", "/etc/zshenv", false},
		{"darwin", "/etc/resolver/a/b.com", false},
		{"darwin", "/etc/resolver/corp.com\n", false},
		{"linux", "dns tun0", true},
		{"linux", "domain tun0 corp.example.com", true},
		{"linux", "domain tun0 ../x", false},
		{"linux", "domain -x corp.com", false},
		{"linux", "domain tun0 corp.com extra", false},
		{"linux", "dns  tun0", false},
		{"linux", "rm tun0", false},
	}
	for _, c := range cases {
		if got := validResolverEntry(c.goos, c.id); got != c.ok {
			t.Errorf("validResolverEntry(%s, %q) = %v, want %v", c.goos, c.id, got, c.ok)
		}
	}
}

func TestUnderscoreInDomainLabels(t *testing.T) {
	for _, d := range []string{"_dmarc.example.com", "a_b.example.com", "*._tcp.example.com", "svc_1.corp_net.example.com"} {
		if !ValidDomain(d) {
			t.Errorf("ValidDomain(%q) = false", d)
		}
		if _, _, err := NormalizeRule(d); err != nil {
			t.Errorf("NormalizeRule(%q): %v", d, err)
		}
	}
	for _, z := range []string{"_dmarc.example.com", "corp_net.example.com"} {
		if !ValidZone(z) {
			t.Errorf("ValidZone(%q) = false", z)
		}
	}
	if ValidZone("*._tcp.example.com") {
		t.Error("a wildcard is not a zone")
	}
	if isNet, v, err := NormalizeRule(" _DMARC.Example.COM. "); err != nil || isNet || v != "_dmarc.example.com" {
		t.Errorf("%v %q %v", isNet, v, err)
	}
}

// Internationalized names are not converted (golang.org/x/net/idna is not a
// dependency); the error says what to do instead.
func TestIDNNeedsPunycode(t *testing.T) {
	for _, d := range []string{"пример.рф", "bücher.de"} {
		_, _, err := NormalizeRule(d)
		if err == nil || !strings.Contains(err.Error(), "punycode") {
			t.Errorf("%q: %v", d, err)
		}
	}
	if _, v, err := NormalizeRule("xn--e1afmkfd.xn--p1ai"); err != nil || v != "xn--e1afmkfd.xn--p1ai" {
		t.Errorf("%q %v", v, err)
	}
}

func TestValidIfaceRejectsLineSeparators(t *testing.T) {
	for _, s := range []string{"a b", "a b", "a�b", "a\nb", "-x", ""} {
		if ValidIface(s) {
			t.Errorf("ValidIface(%q) = true", s)
		}
	}
	for _, s := range []string{"Беспроводная сеть", "Ethernet 2", "utun3"} {
		if !ValidIface(s) {
			t.Errorf("ValidIface(%q) = false", s)
		}
	}
}
