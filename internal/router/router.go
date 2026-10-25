// Package router adds and removes OS routes and keeps a journal of them.
//
// Only routes recorded in the journal are ever removed; the system default
// route and the VPN clients' own routes are never modified.
package router

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
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
	name := func(ok bool, i netif.Info) string {
		if !ok {
			return "-"
		}
		return i.Name
	}
	return fmt.Sprintf("corp=%s home=%s gw=%s/%s cfg=%x",
		name(e.CorpOK, e.Corp), name(e.HomeOK, e.Home), e.GW.Iface, e.GW.Router, h.Sum32())
}

// Sync decides what keeps routes in line with what is connected: apply when
// something changed since the last apply, reset when no VPN is left.
func Sync(cfg *config.Config, e Env, st *config.State) (apply, reset bool) {
	if !e.Any() {
		return false, !st.Empty()
	}
	return Sig(cfg, e) != st.Sig, false
}

// Reset removes every route and DNS file recorded in the journal. Entries
// that could not be removed stay in the journal for the next try.
// It needs no config, so it works even if config.json is broken or missing.
func Reset() (removed int, errs []error) {
	st := config.LoadState()
	keep := &config.State{}
	for _, r := range st.Routes {
		if err := delRoute(r); err != nil {
			errs = append(errs, err)
			keep.Routes = append(keep.Routes, r)
			continue
		}
		removed++
	}
	for _, p := range st.Resolvers {
		if err := delResolver(p); err != nil {
			errs = append(errs, err)
			keep.Resolvers = append(keep.Resolvers, p)
			continue
		}
		removed++
	}
	if len(st.Resolvers) > 0 {
		flushDNS()
	}
	if !st.Empty() {
		_ = config.SaveState(keep)
	}
	return
}

// Apply sends corp rules through the corp VPN, direct rules past every VPN,
// and, if configured, everything else through the home VPN. Whatever is not
// connected is skipped. Progress goes to w.
func Apply(cfg *config.Config, w io.Writer) error {
	e := Detect(cfg)
	if !e.Any() {
		return fmt.Errorf("no VPN is connected: connect the corporate and/or home VPN first")
	}
	if n, errs := Reset(); len(errs) > 0 {
		return fmt.Errorf("could not clear previous routes: %v", errs[0])
	} else if n > 0 {
		fmt.Fprintf(w, "cleared %d previous entries\n", n)
	}
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

	// write-ahead journal: each entry is saved before it is created, and only
	// what was really created stays, so reset never removes routes that the
	// VPN clients set up themselves
	st := &config.State{Sig: Sig(cfg, e)}
	if err := config.SaveState(st); err != nil {
		return err
	}
	added, kept, failed := 0, 0, 0
	add := func(r config.Route) {
		st.Routes = append(st.Routes, r)
		if err := config.SaveState(st); err != nil {
			fmt.Fprintf(w, "  ! journal: %v\n", err)
			failed++
			st.Routes = st.Routes[:len(st.Routes)-1]
			return
		}
		err := addRoute(r)
		if err == nil {
			added++
			fmt.Fprintf(w, "  + %-18s -> %-6s %s\n", r.Dest, r.Via, r.Iface)
			return
		}
		st.Routes = st.Routes[:len(st.Routes)-1]
		_ = config.SaveState(st)
		if strings.Contains(strings.ToLower(err.Error()), "exists") {
			kept++
			fmt.Fprintf(w, "  = %-18s already routed by the system or a VPN client, left as is\n", r.Dest)
			return
		}
		failed++
		fmt.Fprintf(w, "  ! %s via %s: %v\n", r.Dest, r.Iface, err)
	}

	if e.CorpOK {
		corp := func(dest string) {
			add(config.Route{Dest: dest, Iface: e.Corp.Name, Gateway: cfg.CorpGateway, Via: ViaCorp})
		}
		servers, zones := corpDNS(e.Corp.Name)
		if cfg.CorpDNS != "" {
			servers = []string{cfg.CorpDNS}
			corp(cfg.CorpDNS + "/32") // the corp DNS itself must be reachable through corp
		}
		if len(servers) > 0 {
			fmt.Fprintf(w, "corp DNS: %s\n", strings.Join(servers, ", "))
		}
		for _, n := range expandNets(cfg.Networks, w) {
			corp(n)
		}
		if len(cfg.Domains) > 0 {
			fmt.Fprintln(w, "resolving corp domains...")
			for _, ip := range resolveDomains(cfg.Domains, first(servers), w) {
				corp(ip)
			}
		}
		if cfg.SplitDNS && len(servers) > 0 {
			splitDNS(st, e.Corp.Name, servers, append(zones, cfg.Domains...), cfg.DirectDomains, w)
		}
	}
	if e.GWOK {
		direct := func(dest string) {
			add(config.Route{Dest: dest, Iface: e.GW.Iface, Gateway: e.GW.Router, Via: ViaDirect})
		}
		for _, n := range expandNets(cfg.DirectNetworks, w) {
			direct(n)
		}
		if len(cfg.DirectDomains) > 0 {
			fmt.Fprintln(w, "resolving direct domains...")
			for _, ip := range resolveDomains(cfg.DirectDomains, "", w) {
				direct(ip)
			}
		}
	}
	if e.HomeOK && cfg.HomeDefault {
		// two halves of the address space beat the default route without touching it
		for _, d := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			add(config.Route{Dest: d, Iface: e.Home.Name, Via: ViaHome})
		}
	}
	fmt.Fprintf(w, "done: %d routes added, %d already in place, %d failed. Undo anytime with: vpnsplit reset\n", added, kept, failed)
	return nil
}

// splitDNS makes the OS resolve corp zones through the corp DNS, so they keep
// working when the home VPN replaces the system DNS (BlancVPN does). How is
// up to the OS (dns_<os>.go): resolverPlan lists the entries to create, each
// is journaled before it is created, like routes.
func splitDNS(st *config.State, iface string, servers, zones, skip []string, w io.Writer) {
	var clean []string
	done := map[string]bool{}
	for _, s := range skip {
		done[s] = true
	}
	for _, z := range zones {
		z = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(z), "~"), ".")
		if z != "" && !done[z] {
			done[z] = true
			clean = append(clean, z)
		}
	}
	plan := resolverPlan(iface, servers, clean)
	for _, id := range plan {
		st.Resolvers = append(st.Resolvers, id)
		if err := config.SaveState(st); err != nil {
			fmt.Fprintf(w, "  ! journal: %v\n", err)
			return
		}
		if err := addResolver(id, servers); err != nil {
			st.Resolvers = st.Resolvers[:len(st.Resolvers)-1]
			_ = config.SaveState(st)
			fmt.Fprintf(w, "  = %s: %v\n", id, err)
			continue
		}
		fmt.Fprintf(w, "  + %-18s -> corp DNS\n", id)
	}
	if len(plan) > 0 {
		flushDNS()
	}
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

func resolveDomains(domains []string, dns string, w io.Writer) []string {
	res := net.DefaultResolver
	if dns != "" {
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dns, "53"))
		}}
	}
	var cidrs []string
	for _, d := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
