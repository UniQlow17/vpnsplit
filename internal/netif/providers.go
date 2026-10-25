package netif

import (
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// provider is a VPN client recognised by its process path, bundle id,
// service name or adapter description.
type provider struct {
	Name  string
	Role  Kind     // KindCorp or KindVPN
	Match []string // lowercase substrings
}

var providers = []provider{
	{"Check Point", KindCorp, []string{"check point", "checkpoint", "endpoint security vpn", "endpoint connect", "tracsrv", "tunsnx", "snx"}},
	{"Cisco Secure Client", KindCorp, []string{"cisco", "anyconnect", "vpnagentd", "cscotun"}},
	{"FortiClient", KindCorp, []string{"forticlient", "fortitray", "fctservctl"}},
	{"GlobalProtect", KindCorp, []string{"globalprotect", "pangp", "gpd0"}},
	{"Ivanti Secure Access", KindCorp, []string{"ivanti", "pulse secure"}},
	{"Happ", KindVPN, []string{"happ"}},
	{"BlancVPN", KindVPN, []string{"blancvpn", "blanc"}},
	{"Incy", KindVPN, []string{"incy"}},
	{"Hiddify", KindVPN, []string{"hiddify"}},
	{"AmneziaVPN", KindVPN, []string{"amnezia"}},
	{"Outline", KindVPN, []string{"outline"}},
	{"NekoBox", KindVPN, []string{"nekoray", "nekobox"}},
	{"Clash", KindVPN, []string{"clash", "mihomo"}},
	{"sing-box", KindVPN, []string{"sing-box", "singbox", "sfm"}},
	{"WireGuard", KindVPN, []string{"wireguard"}},
	{"OpenVPN", KindVPN, []string{"openvpn", "tunnelblick", "tap-windows"}},
}

// findProvider returns the known VPN client mentioned in text.
func findProvider(text string) (provider, bool) {
	t := strings.ToLower(text)
	for _, p := range providers {
		for _, m := range p.Match {
			if strings.Contains(t, m) {
				return p, true
			}
		}
	}
	return provider{}, false
}

// ownerKind is the kind of an adapter whose owner is called name.
func ownerKind(name string) (string, Kind) {
	if p, ok := findProvider(name); ok {
		return p.Name, p.Role
	}
	if Classify(name) == KindCorp {
		return name, KindCorp
	}
	return name, KindVPN // whatever owns a tunnel is a VPN of some sort
}

// Auto is the adapter selector that picks a connected VPN of the right kind.
const Auto = "auto"

// IsAuto reports whether sel asks for automatic detection.
func IsAuto(sel string) bool { return sel == "" || strings.EqualFold(sel, Auto) }

// resolve picks the connected adapter for a selector: "auto" takes the first
// adapter of the given kind (preferring recognised VPN clients), anything else
// matches a client name ("Check Point") or an exact adapter name ("utun4").
func resolve(ifs []Info, sel string, kind Kind, skip string) (Info, bool) {
	var best Info
	found := false
	for _, i := range ifs {
		if !i.Connected() || i.Name == skip {
			continue
		}
		if !IsAuto(sel) {
			if strings.EqualFold(sel, i.Name) || strings.EqualFold(sel, i.Provider) {
				return i, true
			}
			continue
		}
		if i.Kind == kind && (!found || best.Provider == "" && i.Provider != "") {
			best, found = i, true
		}
	}
	return best, found
}

// appName turns a process path into the name of the app it belongs to:
// "/Applications/Happ.app/Contents/MacOS/core/xray" -> "Happ".
func appName(path string) string {
	if i := strings.Index(path, ".app/"); i >= 0 {
		return filepath.Base(path[:i])
	}
	return filepath.Base(path)
}

// systemPath reports whether a process belongs to macOS itself
// (iCloud, Continuity and friends keep a few utuns of their own).
func systemPath(path string) bool {
	return strings.HasPrefix(path, "/System/") || strings.HasPrefix(path, "/usr/libexec/")
}

// claim records the process at path as the owner of iface.
func claim(res map[string]string, iface, path string) {
	if path == "" || systemPath(path) {
		return
	}
	if p, ok := findProvider(path); ok {
		res[iface] = p.Name
	} else {
		res[iface] = appName(path)
	}
}

// guessOwners matches tunnels nobody claimed to VPN clients that are running:
// proxy-style addresses to proxy clients (Happ, sing-box...), the rest to
// corporate clients. Clients already seen on an adapter are not reused.
func guessOwners(res map[string]string, ifs []Info, procs []string) {
	seen := map[string]bool{}
	for _, name := range res {
		seen[name] = true
	}
	for _, i := range ifs {
		seen[i.Provider] = true
	}
	var corp, proxy []string
	for _, path := range procs {
		if p, ok := findProvider(path); ok && !seen[p.Name] {
			seen[p.Name] = true
			if p.Role == KindCorp {
				corp = append(corp, p.Name)
			} else {
				proxy = append(proxy, p.Name)
			}
		}
	}
	sort.Strings(corp)
	sort.Strings(proxy)
	var left []Info
	for _, i := range ifs {
		if _, done := res[i.Name]; !done && i.Connected() && i.Provider == "" && i.Kind == KindVPN {
			left = append(left, i)
		}
	}
	sort.Slice(left, func(a, b int) bool { return left[a].Name < left[b].Name })
	for _, i := range left {
		pool := &corp
		if proxyAddr(i.Addrs[0]) {
			pool = &proxy
		}
		if len(*pool) > 0 {
			res[i.Name], *pool = (*pool)[0], (*pool)[1:]
		}
	}
}

// parseNMActive maps devices to connection names for VPN and WireGuard lines
// of `nmcli -t -f NAME,TYPE,DEVICE connection show --active`.
func parseNMActive(out string) map[string]string {
	res := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(strings.ReplaceAll(l, "\\:", "\x00"), ":")
		if len(f) != 3 || f[2] == "" || f[1] != "vpn" && f[1] != "wireguard" {
			continue
		}
		res[f[2]] = strings.ReplaceAll(f[0], "\x00", ":")
	}
	return res
}

// parseFdinfoIff returns the adapter of a /dev/net/tun descriptor ("iff:\ttun0").
func parseFdinfoIff(info string) string {
	for _, l := range strings.Split(info, "\n") {
		if v, ok := strings.CutPrefix(l, "iff:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// proxyAddr reports whether a tunnel address looks like one of the
// link-local / benchmark ranges proxy clients (xray, sing-box) put on their
// TUN, as opposed to an address handed out by a corporate VPN gateway.
func proxyAddr(addr string) bool {
	ip := net.ParseIP(addr)
	for _, c := range []string{"169.254.0.0/16", "198.18.0.0/15", "172.19.0.0/30"} {
		if _, n, _ := net.ParseCIDR(c); ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// ncService is one VPN from `scutil --nc list`.
type ncService struct {
	ID, Name, Bundle string
	Connected        bool
}

// parseNCList parses lines like
//
//   - (Connected)   C5EF...74 VPN (com.blancvpn.app) "BlancVPN"   [VPN:com.blancvpn.app]
func parseNCList(out string) []ncService {
	var res []ncService
	for _, l := range strings.Split(out, "\n") {
		op, cl := strings.Index(l, "("), strings.Index(l, ")")
		if op < 0 || cl < op {
			continue
		}
		f := strings.Fields(l[cl+1:])
		if len(f) < 2 {
			continue
		}
		s := ncService{ID: f[0], Connected: l[op+1:cl] == "Connected"}
		if a, b := strings.Index(l, "\""), strings.LastIndex(l, "\""); a >= 0 && b > a {
			s.Name = l[a+1 : b]
		}
		if a := strings.Index(l[cl+1:], "("); a >= 0 {
			rest := l[cl+1+a+1:]
			if b := strings.Index(rest, ")"); b >= 0 {
				s.Bundle = rest[:b]
			}
		}
		res = append(res, s)
	}
	return res
}

// parseSCValue returns the value of "key : value" in scutil output.
func parseSCValue(out, key string) string {
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), " : "); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseLsofUtun maps utun unit numbers to the pid holding them, from
// `lsof -F pn` output ("p318", "n[ctl com.apple.net.utun_control id 5 unit 226]").
// utun_control unit N is the adapter utun(N-1).
func parseLsofUtun(out string) map[string]int {
	res := map[string]int{}
	pid := 0
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "p"):
			pid, _ = strconv.Atoi(l[1:])
		case strings.HasPrefix(l, "n") && strings.Contains(l, "utun_control"):
			f := strings.Fields(strings.TrimSuffix(l, "]"))
			if len(f) < 2 || f[len(f)-2] != "unit" {
				continue
			}
			if u, err := strconv.Atoi(f[len(f)-1]); err == nil && u > 0 {
				res["utun"+strconv.Itoa(u-1)] = pid
			}
		}
	}
	return res
}

// parsePS maps pid to executable path from `ps -axo pid=,comm=`.
func parsePS(out string) map[int]string {
	res := map[int]string{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		p, path, ok := strings.Cut(l, " ")
		if !ok {
			continue
		}
		if pid, err := strconv.Atoi(p); err == nil {
			res[pid] = strings.TrimSpace(path)
		}
	}
	return res
}
