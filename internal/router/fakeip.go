package router

import (
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/UniQlow17/vpnsplit/internal/clientcfg"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// fakeRange is a fake-ip range of a client config with the client it came from.
type fakeRange struct {
	p      netip.Prefix
	client string // "Mihomo", "sing-box", "Hiddify": for the report, the path of the file is not shown
}

// extraFake holds the fake-ip ranges that client configs name (the
// fake-ip-range of mihomo, the inet4_range of sing-box), besides fakeIPNet.
// They only widen what is treated as "not the real address of a name", which
// means fewer routes are made: a wrong range cannot add a route. The ranges are
// checked again here (clientcfg.ValidFakeRange: IPv4, not shorter than /8, no
// private addresses). Set at the start of an apply, read by badAddr and
// resolveDomains (which have no Manager at hand).
//
// Only the answers of DNS are judged by them (isFakeIP): the addresses of DNS
// servers that the OS reports are not (badServer), so a range in a config can
// never remove a real server from the DNS plan.
var extraFake atomic.Pointer[[]fakeRange]

// SetFakeRanges replaces the fake-ip ranges taken from client configs; the
// ones that do not pass the check are dropped.
func SetFakeRanges(list []netip.Prefix) {
	rs := make([]fakeRange, 0, len(list))
	for _, p := range list {
		rs = append(rs, fakeRange{p: p, client: "client config"})
	}
	setFakeRanges(rs)
}

func setFakeRanges(list []fakeRange) {
	var ok []fakeRange
	for _, r := range list {
		if v, good := clientcfg.ValidFakeRange(r.p); good && len(ok) < clientcfg.MaxFakeRanges {
			ok = append(ok, fakeRange{v, r.client})
		}
	}
	extraFake.Store(&ok)
}

// clientProviders names, for a client whose config was read, the VPN clients
// (netif.Provider) whose adapter shows that the client is running: Hiddify
// runs the core of sing-box, and the other way round the adapter of one is
// sometimes named after the other.
var clientProviders = map[string][]string{
	"sing-box": {"sing-box", "Hiddify", "NekoBox"},
	"Hiddify":  {"Hiddify", "sing-box"},
	"Mihomo":   {"Clash"},
}

// clientNameHints are parts of the name of an adapter the client creates, for
// the case that the owner of the adapter could not be told.
var clientNameHints = map[string][]string{
	"sing-box": {"sing-box", "singbox"},
	"Hiddify":  {"hiddify"},
	"Mihomo":   {"mihomo", "clash", "meta"},
}

// clientRunning reports whether an adapter of the client is up.
func clientRunning(client string, ifs []netif.Info) bool {
	for _, i := range ifs {
		if !i.Connected() {
			continue
		}
		for _, p := range clientProviders[client] {
			if i.Provider == p {
				return true
			}
		}
		n := strings.ToLower(i.Name + " " + i.Desc)
		for _, h := range clientNameHints[client] {
			if strings.Contains(n, h) {
				return true
			}
		}
	}
	return false
}

// fakeRangesFor picks the fake-ip ranges that matter now: the ones of clients
// whose DNS is in fake-ip mode and whose adapter is up. The file of a client that
// is not running says nothing about what the DNS of this machine answers.
func fakeRangesFor(res clientcfg.Result, ifs []netif.Info) []fakeRange {
	var out []fakeRange
	for _, c := range res.Tun {
		if !c.FakeIP || len(c.FakeRanges) == 0 || !clientRunning(c.Client, ifs) {
			continue
		}
		for _, p := range c.FakeRanges {
			out = append(out, fakeRange{p, c.Client})
		}
	}
	return out
}

// fakeRangeOf names the fake-ip range that holds a ("" if none does); a range
// of a client config is named with the client.
func fakeRangeOf(a netip.Addr) string {
	a = a.Unmap()
	if fakeIPNet.Contains(a) {
		return fakeIPNet.String()
	}
	if l := extraFake.Load(); l != nil {
		for _, r := range *l {
			if r.p.Contains(a) {
				return r.p.String() + " from the " + r.client + " config"
			}
		}
	}
	return ""
}

// isFakeIP reports whether a is in a range that a fake-ip DNS answers from.
func isFakeIP(a netip.Addr) bool { return fakeRangeOf(a) != "" }
