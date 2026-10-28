// Package clientcfg reads, without changing anything, the settings of VPN
// clients and of the OS that matter for split tunnelling: the system proxy,
// the tun settings of sing-box, Hiddify and Mihomo, the DNS policy of Group
// Policy, directives of OpenVPN configs. What it returns is for warnings and
// for narrowing the fake-ip filter; nothing from the files reaches the
// journal or a command of the OS.
//
// The files of clients lie in the profile of the user, which the user (and
// whoever runs as the user) can write: they are untrusted input. They are read
// whole, with a size limit, through config.ReadRegularMax (a link, a device or
// a pipe is refused), and parsed by code that takes only the few keys it
// needs and returns values it checked itself.
package clientcfg

import (
	"net/netip"
	"strings"
)

// MaxConfigSize bounds a client config that is read (bigger ones are skipped).
const MaxConfigSize = 4 << 20

// MaxFakeRanges bounds how many fake-ip ranges are taken from all the files.
const MaxFakeRanges = 8

// TunCfg is what a client config says about its TUN and DNS.
type TunCfg struct {
	Client      string         // "sing-box", "Hiddify" or "Mihomo": where the file belongs
	Path        string         // the file read
	Tun         bool           // a tun inbound / tun section that is on
	StrictRoute bool           // strict_route / strict-route of an enabled TUN
	FakeIP      bool           // the DNS answers with fake addresses
	FakeRanges  []netip.Prefix // IPv4 ranges of the fake-ip DNS, checked by ValidFakeRange
}

// ValidFakeRange checks a fake-ip range that came from a file: an IPv4
// network not shorter than /8 (a wider one would make most of the Internet
// "fake"), and none that overlaps the private, loopback, link-local, multicast
// or reserved addresses (a fake range there would swallow the answers of real
// servers). The network is returned masked.
func ValidFakeRange(p netip.Prefix) (netip.Prefix, bool) {
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 32 {
		return netip.Prefix{}, false
	}
	p = p.Masked()
	for _, bad := range noFakeNets {
		if bad.Overlaps(p) {
			return netip.Prefix{}, false
		}
	}
	return p, true
}

var noFakeNets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT, Tailscale
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), // IETF protocol assignments
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.51.100.0/24"), // documentation (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation (TEST-NET-3)
	netip.MustParsePrefix("224.0.0.0/3"),     // multicast and the reserved class E, up to 255.255.255.255
}

// parseFakeRange reads "198.18.0.1/16" (host bits allowed, as mihomo writes it).
func parseFakeRange(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(trimQuotes(strings.TrimSpace(s)))
	if err != nil {
		return netip.Prefix{}, false
	}
	return ValidFakeRange(p)
}

func trimQuotes(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}
