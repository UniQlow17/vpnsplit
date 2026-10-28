package router

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func withFakeRanges(t *testing.T, list ...string) {
	t.Helper()
	var ps []netip.Prefix
	for _, s := range list {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	SetFakeRanges(ps)
	t.Cleanup(func() { SetFakeRanges(nil) })
}

// The range a client config names narrows the answers that are accepted.
func TestFakeRangesFromClientConfigs(t *testing.T) {
	a := netip.MustParseAddr("28.1.2.3")
	if badAddr(a) != "" || isFakeIP(a) {
		t.Fatal("28.1.2.3 is fake without a config")
	}
	withFakeRanges(t, "28.0.0.0/8")
	if why := badAddr(a); !strings.Contains(why, "28.0.0.0/8") {
		t.Errorf("not refused: %q", why)
	}
	if badAddr(netip.MustParseAddr("29.1.2.3")) != "" {
		t.Error("another address refused")
	}
	if !isFakeIP(netip.MustParseAddr("198.19.1.1")) {
		t.Error("the built-in range is gone")
	}

	m := &Manager{lookup: func(_ context.Context, _, d string) ([]netip.Addr, error) {
		return []netip.Addr{a, netip.MustParseAddr("93.184.216.34")}, nil
	}}
	var out strings.Builder
	cidrs, _ := m.resolveDomains([]string{"x.example"}, nil, nil, &out)
	if len(cidrs) != 1 || cidrs[0] != "93.184.216.34/32" {
		t.Errorf("cidrs %v", cidrs)
	}
	if !strings.Contains(out.String(), "x.example=28.1.2.3") {
		t.Errorf("not reported: %q", out.String())
	}
}

// Ranges that do not pass the check are not taken, whoever sets them.
func TestSetFakeRangesChecks(t *testing.T) {
	withFakeRanges(t, "0.0.0.0/0", "10.0.0.0/8", "128.0.0.0/1", "2001:db8::/32", "28.0.0.0/8")
	l := extraFake.Load()
	if l == nil || len(*l) != 1 || (*l)[0].p.String() != "28.0.0.0/8" {
		t.Errorf("%v", l)
	}
	if isFakeIP(netip.MustParseAddr("8.8.8.8")) || isFakeIP(netip.MustParseAddr("10.1.1.1")) {
		t.Error("an unchecked range is in force")
	}
	// the number is bounded
	var many []netip.Prefix
	for i := 0; i < 50; i++ {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(20 + i), 0, 0, 0}), 8))
	}
	SetFakeRanges(many)
	if l := extraFake.Load(); len(*l) > 8 {
		t.Errorf("%d ranges", len(*l))
	}
}
