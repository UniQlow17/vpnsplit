package router

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/netif"
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
	cidrs, _ := m.resolveDomains([]string{"x.example"}, nil, nil, false, &out)
	if len(cidrs) != 1 || cidrs[0] != "93.184.216.34/32" {
		t.Errorf("cidrs %v", cidrs)
	}
	if !strings.Contains(out.String(), "x.example=28.1.2.3") {
		t.Errorf("not reported: %q", out.String())
	}

	// an explicit server: the range of a config does not apply
	cidrs, _ = m.resolveDomains([]string{"x.example"}, []string{"9.9.9.9"}, nil, false, &out)
	if len(cidrs) != 2 {
		t.Errorf("explicit server, cidrs %v", cidrs)
	}
	// corp and home rules: a warning, the route is made
	cidrs, warns := m.resolveDomains([]string{"x.example"}, nil, nil, true, &out)
	if len(cidrs) != 2 || len(warns) != 1 || !strings.Contains(warns[0], "28.0.0.0/8") {
		t.Errorf("warnOnly: %v %v", cidrs, warns)
	}
	// the built-in range is dropped everywhere
	m.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.18.0.5")}, nil
	}
	if cidrs, _ = m.resolveDomains([]string{"x.example"}, []string{"9.9.9.9"}, nil, true, &out); len(cidrs) != 0 {
		t.Errorf("198.18/15 kept: %v", cidrs)
	}
}

// A range of a config does not remove the DNS of the provider.
func TestFakeRangeKeepsProviderDNS(t *testing.T) {
	withFakeRanges(t, "8.0.0.0/8")
	v := newAvoid()
	kept, notes := v.filterServers([]string{"8.8.8.8", "127.0.0.1"})
	if len(kept) != 1 || kept[0] != "8.8.8.8" || len(notes) != 1 {
		t.Errorf("kept %v notes %v", kept, notes)
	}
}

func TestClientRunningMetaHint(t *testing.T) {
	if clientRunning("Mihomo", []netif.Info{{Name: "Metadata Ethernet", Up: true, Addrs: []string{"10.0.0.2"}}}) {
		t.Error("a general word counts as a client")
	}
	if !clientRunning("Mihomo", []netif.Info{{Name: "Meta-1", Up: true, Addrs: []string{"198.18.0.1"}}}) {
		t.Error("meta- is not a hint")
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
