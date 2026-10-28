// Package netif lists network adapters and guesses which of them are VPNs
// and which VPN client owns them.
package netif

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Info describes one network adapter.
type Info struct {
	Name     string
	Index    int // OS interface index: a reconnected VPN of the same name usually gets a new one
	Desc     string
	Up       bool
	Addrs    []string
	Nets     []netip.Prefix // the IPv4 networks of the adapter (address and mask)
	Addrs6   []string       // global IPv6 addresses (not link-local, not unique-local)
	Kind     Kind
	Provider string // VPN client behind the adapter ("Check Point", "Happ"), if known
}

// Connected reports whether the adapter is up and has an IPv4 address.
func (i Info) Connected() bool { return i.Up && len(i.Addrs) > 0 }

// HasV6 reports whether the adapter is up and has a global IPv6 address.
func (i Info) HasV6() bool { return i.Up && len(i.Addrs6) > 0 }

// Label is how the adapter is shown to people: "Check Point (utun4)".
func (i Info) Label() string {
	if i.Provider == "" {
		return i.Name
	}
	return i.Provider + " (" + i.Name + ")"
}

// Kind is a best-effort guess of what an adapter is.
type Kind string

const (
	KindCorp     Kind = "corp?" // looks like Check Point
	KindVPN      Kind = "vpn"   // tunnel adapter (Happ/Incy/Blanc/WireGuard/...)
	KindVirtual  Kind = "virtual"
	KindPhysical Kind = "physical"
)

var (
	corpHints    = []string{"check point", "checkpoint", "cpvpn", "trac", "cscotun"}
	virtualHints = []string{"hyper-v", "vethernet", "docker", "vmware", "virtualbox", "bluetooth", "br-", "veth", "virbr", "awdl", "llw", "bridge", "anpi"}
	vpnHints     = []string{"happ", "xray", "incy", "blanc", "wintun", "wireguard", "sing-box", "singbox", "tap-windows", "tun", "utun", "wg", "ppp", "vpn", "nekoray", "v2ray", "clash"}
)

// Classify guesses the kind of an adapter from its name and description.
func Classify(text string) Kind {
	t := strings.ToLower(text)
	for _, h := range corpHints {
		if strings.Contains(t, h) {
			return KindCorp
		}
	}
	for _, h := range virtualHints {
		if strings.Contains(t, h) {
			return KindVirtual
		}
	}
	for _, h := range vpnHints {
		if strings.Contains(t, h) {
			return KindVPN
		}
	}
	return KindPhysical
}

// List returns all non-loopback adapters.
func List() ([]Info, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	descs := cachedDescriptions()
	var out []Info
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		info := Info{Name: i.Name, Index: i.Index, Desc: descs[i.Name], Up: i.Flags&net.FlagUp != 0}
		if as, err := i.Addrs(); err == nil {
			for _, a := range as {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					info.Addrs = append(info.Addrs, ipn.IP.String())
					if pf, ok := netip.AddrFromSlice(ipn.IP.To4()); ok {
						if ones, _ := ipn.Mask.Size(); ones > 0 && ones < 32 {
							info.Nets = append(info.Nets, netip.PrefixFrom(pf, ones).Masked())
						}
					}
				}
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() == nil {
					if ip, ok := netip.AddrFromSlice(ipn.IP); ok && isGlobalV6(ip) {
						info.Addrs6 = append(info.Addrs6, ip.String())
					}
				}
			}
		}
		info.Kind = Classify(info.Name + " " + info.Desc)
		if p, ok := findProvider(info.Name + " " + info.Desc); ok {
			info.Provider, info.Kind = p.Name, p.Role
		}
		out = append(out, info)
	}
	own := cachedOwners(out)
	for n := range out {
		if name := own[out[n].Name]; name != "" {
			out[n].Provider, out[n].Kind = ownerKind(name)
		}
	}
	return out, nil
}

// Find returns the adapter with this exact name.
func Find(name string) (Info, bool) {
	ifs, err := List()
	if err != nil {
		return Info{}, false
	}
	return FindIn(ifs, name)
}

// FindIn is Find in a list that was read already.
func FindIn(ifs []Info, name string) (Info, bool) {
	for _, i := range ifs {
		if i.Name == name {
			return i, true
		}
	}
	return Info{}, false
}

// Resolve finds the connected adapter for a selector: "auto" (or empty) picks
// a connected adapter of the given kind, anything else is a VPN client name
// ("Check Point", "Happ") or an exact adapter name. The adapter named skip is
// never returned, so the home VPN cannot resolve to the corp one.
func Resolve(sel string, kind Kind, skip string) (Info, bool) {
	ifs, err := List()
	if err != nil {
		return Info{}, false
	}
	return resolve(ifs, sel, kind, skip)
}

// ResolveIn is Resolve in a list that was read already.
func ResolveIn(ifs []Info, sel string, kind Kind, skip string) (Info, bool) {
	return resolve(ifs, sel, kind, skip)
}

var (
	descMu   sync.Mutex
	descAt   time.Time
	descVals map[string]string

	ownMu   sync.Mutex
	ownAt   time.Time
	ownKey  string
	ownVals map[string]string
)

// cachedDescriptions avoids spawning PowerShell on every refresh.
func cachedDescriptions() map[string]string {
	descMu.Lock()
	defer descMu.Unlock()
	if descVals == nil || time.Since(descAt) > 30*time.Second {
		descVals, descAt = descriptions(), time.Now()
	}
	return descVals
}

// cachedOwners finds who owns the tunnels (owners_<os>.go, then a guess for
// the rest); it re-runs when adapters change and every few seconds.
func cachedOwners(ifs []Info) map[string]string {
	var parts []string
	for _, i := range ifs {
		if len(i.Addrs) > 0 {
			parts = append(parts, i.Name+"="+strings.Join(i.Addrs, ","))
		}
	}
	sort.Strings(parts)
	key := strings.Join(parts, ";")
	ownMu.Lock()
	defer ownMu.Unlock()
	if ownVals == nil || ownKey != key || time.Since(ownAt) > 5*time.Second {
		res, procs := owners(ifs)
		if res == nil {
			res = map[string]string{}
		}
		guessOwners(res, ifs, procs)
		ownVals, ownAt, ownKey = res, time.Now(), key
	}
	return ownVals
}

// isGlobalV6 reports whether ip is a global unicast IPv6 address: not
// link-local, not unique-local (fc00::/7), not loopback or multicast.
func isGlobalV6(ip netip.Addr) bool {
	return ip.Is6() && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsPrivate()
}
