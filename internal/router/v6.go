package router

import (
	"github.com/UniQlow17/vpnsplit/internal/config"
)

// V6Level says how much attention the IPv6 state needs.
type V6Level int

const (
	V6Quiet V6Level = iota // nothing to say
	V6Info                 // IPv6 is handled (goes into the home VPN)
	V6Leaks                // IPv6 goes around the home VPN: shown prominently
)

// V6Cap says whether the home VPN client takes the traffic by its own policy
// routing (Linux: "ip rule", see captured), and for which address families.
type V6Cap int

const (
	V6CapNone    V6Cap = iota // it does not: the halves 0/1 + 128/1 (and ::/1 + 8000::/1) are vpnsplit's
	V6CapBoth                 // IPv4 and IPv6 both go to the tunnel by its rules
	V6CapV4Only               // IPv4 goes to the tunnel by its rules, IPv6 does not
	V6CapUnknown              // IPv4 does, whether IPv6 does could not be read
)

// ruleReader6 is a Backend that can read the IPv6 policy rules (Linux).
type ruleReader6 interface {
	Rules6() ([]OSRule, error)
}

// v6CapOf finds out whether the home VPN client takes the traffic by its own
// rules, and if so whether it does that for IPv6 as well: a diverting rule of
// the IPv6 family whose table has a default route (::/0, or ::/1 and 8000::/1)
// through the home adapter.
func v6CapOf(b Backend, home string) V6Cap {
	routes, err := b.Routes()
	if err != nil {
		return V6CapNone
	}
	rules, err := b.Rules()
	if err != nil {
		return V6CapNone
	}
	tbl := newTable(routes)
	if _, ok := captured(rules, tbl, home); !ok {
		return V6CapNone
	}
	r6, ok := b.(ruleReader6)
	if !ok {
		return V6CapUnknown
	}
	rules6, err := r6.Rules6()
	if err != nil {
		return V6CapUnknown
	}
	for _, d := range diverting(rules6) {
		for _, r := range tbl.all {
			if r.Table == d.Table && r.Dest.Addr().Is6() && r.Dest.Bits() <= 1 && r.Iface == home {
				return V6CapBoth
			}
		}
	}
	return V6CapV4Only
}

// V6Status says what happens to IPv6 traffic with the current setting and
// adapters. IPv6 is not blocked: if the home VPN has a global address, ::/1 and
// 8000::/1 go through it (see buildPlan), or its client sends it there by its
// rules; if it has none, the IPv6 traffic of the physical adapter goes past the
// tunnel, and that is what is highlighted.
func V6Status(cfg *config.Config, e Env) (V6Level, string) {
	if cfg.Rest != config.RestHome || !e.HomeOK {
		return V6Quiet, ""
	}
	if !e.Home.HasV6() {
		if e.GWv6 {
			return V6Leaks, "IPv6 goes past the home VPN: the physical adapter has an IPv6 address and the home VPN has none"
		}
		return V6Quiet, ""
	}
	switch e.V6Cap {
	case V6CapBoth:
		return V6Info, "IPv6 goes into the home VPN by the rules of its client (it has a global IPv6 address)"
	case V6CapV4Only:
		if e.GWv6 {
			return V6Leaks, "IPv6 goes past the home VPN: its client sends only IPv4 into the tunnel by its rules, and the physical adapter has an IPv6 address"
		}
		return V6Quiet, ""
	case V6CapUnknown:
		return V6Info, "IPv6 is left to the home VPN client: vpnsplit cannot tell whether its rules take IPv6 into the tunnel"
	}
	if !v6Halves {
		if e.GWv6 {
			return V6Leaks, "IPv6 goes past the home VPN: routing IPv6 into the tunnel is not supported on macOS yet"
		}
		return V6Quiet, ""
	}
	return V6Info, "IPv6 goes into the home VPN (it has a global IPv6 address)"
}
