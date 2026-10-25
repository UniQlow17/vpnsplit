// Package netif lists network adapters and guesses which of them are VPNs
// and which VPN client owns them.
package netif

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Info describes one network adapter.
type Info struct {
	Name     string
	Desc     string
	Up       bool
	Addrs    []string
	Kind     Kind
	Provider string // VPN client behind the adapter ("Check Point", "Happ"), if known
}

// Connected reports whether the adapter is up and has an IPv4 address.
func (i Info) Connected() bool { return i.Up && len(i.Addrs) > 0 }

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
		info := Info{Name: i.Name, Desc: descs[i.Name], Up: i.Flags&net.FlagUp != 0}
		if as, err := i.Addrs(); err == nil {
			for _, a := range as {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					info.Addrs = append(info.Addrs, ipn.IP.String())
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
