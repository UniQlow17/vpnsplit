// Package router adds and removes OS routes and keeps a journal of them.
//
// Only routes recorded in the journal are ever removed; the system default
// route and the VPN clients' own routes are never modified.
package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/ripe"
)

// Where a route sends traffic.
const (
	ViaCorp   = "corp"
	ViaHome   = "home"
	ViaDirect = "direct"
)

// errExists is returned by addRoute when the route is already in the table
// (a VPN client or the OS set it up). It is detected without reading
// localized command output where the OS allows it.
var errExists = errors.New("route already exists")

// errNotOurs is returned by DelRoute for a route that is in the table but does
// not look like the one the journal describes (somebody else's route to the
// same place). It stays; the entry is dropped from the journal and the report
// says so (Report.Left). Callers that only want the route gone ignore it.
var errNotOurs = errors.New("not ours")

// ignoreNotOurs: for callers that only want the route gone, a route that is not
// ours is not theirs to remove, and that is all right.
func ignoreNotOurs(err error) error {
	if errors.Is(err, errNotOurs) {
		return nil
	}
	return err
}

// errResolverExists is returned by addResolver when a DNS entry for the zone
// is already there and is not ours: it stays as it is, which is no failure.
var errResolverExists = errors.New("DNS entry already exists")

// ifaceByName finds an adapter by its exact name in the list of the OS. found
// is false only if the list was read and has no such adapter; an error means
// the list could not be read, which says nothing about the adapter.
func ifaceByName(name string) (index int, found bool, err error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0, false, fmt.Errorf("list of adapters: %w", err)
	}
	for _, i := range ifs {
		if i.Name == name {
			return i.Index, true, nil
		}
	}
	return 0, false, nil
}

// Gateway is the physical uplink (Wi-Fi, Ethernet) used by direct routes.
type Gateway struct{ Iface, Router string }

// Env is what is connected right now.
type Env struct {
	Corp, Home     netif.Info
	CorpOK, HomeOK bool
	GW             Gateway
	GWOK           bool
}

// Any reports whether at least one VPN is connected.
func (e Env) Any() bool { return e.CorpOK || e.HomeOK }

// Detect finds the configured VPN adapters and the physical gateway.
func Detect(cfg *config.Config) Env {
	var e Env
	e.Corp, e.CorpOK = netif.Resolve(cfg.Corp, netif.KindCorp, "")
	e.Home, e.HomeOK = netif.Resolve(cfg.Home, netif.KindVPN, e.Corp.Name)
	e.GW, e.GWOK = physicalGateway()
	return e
}

// Sig identifies the adapters and rules routes are applied for; when it
// changes (a VPN reconnected on another adapter, another Wi-Fi, new rules)
// the routes must be applied again.
func Sig(cfg *config.Config, e Env) string {
	b, _ := json.Marshal(cfg)
	h := fnv.New32a()
	h.Write(b)
	return fmt.Sprintf("corp=%s home=%s gw=%s/%s cfg=%x",
		ident(e.CorpOK, e.Corp), ident(e.HomeOK, e.Home), e.GW.Iface, e.GW.Router, h.Sum32())
}

// Sync decides what keeps routes in line with what is connected: apply when
// something changed since the last apply, reset when no VPN is left.
func Sync(cfg *config.Config, e Env, st *config.State) (apply, reset bool) {
	if !e.Any() {
		return false, !st.Empty()
	}
	return Sig(cfg, e) != st.Sig, false
}

// Apply brings the routing in line with cfg and what is connected: corp
// rules go through the corp VPN, direct rules past every VPN and, if
// configured, everything else through the home VPN. Whatever is not
// connected is skipped. It does not start from scratch: what is in place
// stays, what is missing is added and what is ours but not wanted any more
// is removed (see reconcile). Progress goes to w. The Manager must own the
// journal (see Acquire).
func (m *Manager) Apply(cfg *config.Config, w io.Writer) error {
	if err := m.requireOwner(); err != nil {
		return err
	}
	if err := m.begin(); err != nil {
		return err
	}
	defer m.unlockSem()
	e := m.detect(cfg)
	if !e.Any() {
		return fmt.Errorf("no VPN is connected: connect the corporate and/or home VPN first")
	}
	return m.applyEnv(cfg, e, w)
}

func (m *Manager) applyEnv(cfg *config.Config, e Env, w io.Writer) error {
	show := func(role, sel string, ok bool, i netif.Info) {
		if ok {
			fmt.Fprintf(w, "%s: %s\n", role, i.Label())
		} else {
			fmt.Fprintf(w, "%s: not connected (%s), its rules are skipped\n", role, sel)
		}
	}
	show("corp VPN", cfg.Corp, e.CorpOK, e.Corp)
	show("home VPN", cfg.Home, e.HomeOK, e.Home)
	if e.GWOK {
		fmt.Fprintf(w, "direct:   %s via %s\n", e.GW.Iface, e.GW.Router)
	} else if len(cfg.DirectNetworks)+len(cfg.DirectDomains) > 0 {
		fmt.Fprintln(w, "direct:   no Wi-Fi/Ethernet gateway found, direct rules are skipped")
	}
	st, _, status := m.store.Load()
	if err := statusErr(status); err != nil {
		return err
	}
	tbl, rs := m.readTables()
	if bp := bootstrapPlan(cfg, e, tbl, rs); bp != nil {
		m.notePlanned(bp.routes)
		// the corp DNS must be reachable before the corp domains are resolved
		if err := m.reconcile(st, bp, tbl, rs, pendingSig, true, io.Discard); err != nil {
			return err
		}
		if st, _, status = m.store.Load(); statusErr(status) != nil {
			return statusErr(status)
		}
		tbl, rs = m.readTables()
	}
	p := m.buildPlan(cfg, e, st, tbl, rs, w)
	m.notePlanned(p.routes)
	for _, s := range p.warns {
		fmt.Fprintf(w, "  ! %s\n", s)
	}
	return m.reconcile(st, p, tbl, rs, Sig(cfg, e), false, w)
}

// readTables reads the routing table and the policy rules. What cannot be
// read is marked unknown: the journal is then taken for the truth.
func (m *Manager) readTables() (*table, *ruleSet) {
	tbl, rs := &table{byKey: map[rkey]OSRoute{}}, &ruleSet{}
	if routes, err := m.b.Routes(); err == nil {
		tbl = newTable(routes)
	}
	if rules, err := m.b.Rules(); err == nil {
		rs = newRuleSet(rules)
	}
	return tbl, rs
}

// expandNets replaces autonomous systems ("AS49675") with the networks they
// announce according to RIPE; plain networks pass through.
func expandNets(rules []string, w io.Writer) []string {
	var out []string
	for _, r := range rules {
		if !config.IsAS(r) {
			out = append(out, r)
			continue
		}
		nets, fetched, err := ripe.Prefixes(r)
		if err != nil {
			fmt.Fprintf(w, "  ! %s: %v\n", r, err)
			continue
		}
		note := ""
		if time.Since(fetched) > 24*time.Hour {
			note = fmt.Sprintf(" (RIPE unreachable, list from %s)", fetched.Format("2006-01-02"))
		}
		fmt.Fprintf(w, "%s: %d networks from RIPE%s\n", r, len(nets), note)
		out = append(out, nets...)
	}
	return out
}

// validServers keeps the IPv4 addresses (canonical form) of what the OS
// reported as DNS servers: they end up in commands and files.
func validServers(in []string) []string {
	var out []string
	for _, s := range in {
		if ip, err := config.ParseIPv4(strings.TrimSpace(s)); err == nil {
			out = config.AddUnique(out, ip)
		}
	}
	return out
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// parseDefaultGW finds the physical default gateway in `netstat -rn` (macOS)
// or `ip route show default` (Linux) output: the first default route whose
// gateway is an IPv4 address on a non-VPN, non-virtual adapter.
func parseDefaultGW(out string) (Gateway, bool) {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || f[0] != "default" {
			continue
		}
		gw, iface := f[1], f[3]
		if f[1] == "via" && len(f) >= 5 && f[3] == "dev" { // linux: default via GW dev IFACE
			gw, iface = f[2], f[4]
		}
		if ip := net.ParseIP(gw); ip == nil || ip.To4() == nil {
			continue
		}
		if netif.Classify(iface) == netif.KindPhysical {
			return Gateway{Iface: iface, Router: gw}, true
		}
	}
	return Gateway{}, false
}

func resolveDomains(parent context.Context, domains []string, dns string, w io.Writer) []string {
	res := net.DefaultResolver
	if dns != "" {
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dns, "53"))
		}}
	}
	var cidrs []string
	for _, d := range domains {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		ips, err := res.LookupIP(ctx, "ip4", d)
		cancel()
		if err != nil {
			fmt.Fprintf(w, "  ! cannot resolve %s: %v\n", d, err)
			continue
		}
		for _, ip := range ips {
			cidrs = config.AddUnique(cidrs, ip.String()+"/32")
		}
	}
	return cidrs
}

// parseSCArray returns the items of "key : <array> { 0 : a  1 : b }" in scutil output.
func parseSCArray(out, key string) []string {
	var res []string
	in := false
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case !in:
			in = strings.HasPrefix(l, key+" : <array>")
		case l == "}":
			return res
		default:
			if _, v, ok := strings.Cut(l, " : "); ok {
				res = append(res, strings.TrimSpace(v))
			}
		}
	}
	return res
}

// resolverMarker tags per-domain DNS files written by vpnsplit, so files
// written by anything else are never touched.
const resolverMarker = "# added by vpnsplit, removed by `vpnsplit reset`"

// parseResolvectl returns the values of `resolvectl dns|domain <link>`
// output: "Link 5 (tun0): 10.226.0.5 10.224.0.5".
func parseResolvectl(out string) []string {
	_, v, ok := strings.Cut(out, "): ")
	if !ok {
		return nil
	}
	return strings.Fields(v)
}

// parseResolvConf returns nameservers and search domains of resolv.conf.
func parseResolvConf(s string) (servers, search []string) {
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if ip := net.ParseIP(f[1]); ip != nil && ip.To4() != nil {
				servers = append(servers, f[1])
			}
		case "search", "domain":
			search = append(search, f[1:]...)
		}
	}
	return servers, search
}

// ident is how an adapter takes part in Sig: its name, its index (a VPN that
// reconnects under the same name usually gets a new one, and its routes went
// with the old adapter) and a hash of its addresses (the journal keeps Sig as
// one bounded string).
func ident(ok bool, i netif.Info) string {
	if !ok {
		return "-"
	}
	addrs := append([]string(nil), i.Addrs...)
	sort.Strings(addrs) // the OS may list the same addresses in another order
	h := fnv.New32a()
	h.Write([]byte(strings.Join(addrs, ",")))
	return fmt.Sprintf("%s#%d@%x", i.Name, i.Index, h.Sum32())
}
