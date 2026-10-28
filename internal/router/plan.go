package router

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// ViaPin marks a host route that keeps the server of a VPN reachable through
// the physical gateway while the home VPN takes the default route.
const ViaPin = "pin"

// plan is what the routing should look like: the desired state that
// reconcile brings the OS to.
type plan struct {
	routes []config.Route
	rules  []config.Rule
	dns    *dnsPlan
	warns  []string
}

// dnsPlan is the set of per-domain DNS entries for the corp zones.
type dnsPlan struct {
	iface   string
	servers []string
	ids     []string
}

// sig identifies the DNS plan: the entries stay as they are while it does not change.
func (d *dnsPlan) sig() string {
	if d == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s|%s", d.iface, strings.Join(d.servers, ","), strings.Join(d.ids, ","))
}

// Policy routing (Linux). A VPN client may send everything into its own
// table by "ip rule" (sing-box: pref 9000 not fwmark 2022 lookup 2022;
// mihomo, Tailscale: their own tables). The main table, where routes would
// normally go, is then not looked at before the client's rule. Our routes for
// corp and direct networks go into a table of our own (config.OwnTable) and one
// rule of ours, "lookup <our table>" with no selector, at a preference before
// the client's, makes it visible. A packet that finds no route there (the
// corp tunnel is down and its routes went with it) goes on to the client's
// rules, as if vpnsplit were not there; "to <prefix> lookup main" would send
// it to the default route of the main table, around the client.
//
// The two halves 0/1 + 128/1 and the pins stay in the main table: they only
// exist where no client takes the default route by rules, and a rule that
// looks up our table first must not see them, or the client's own packets to
// its server would be caught by the halves.
const (
	// rulePrefBase is where our rule goes when no client rule is that early.
	rulePrefBase = 5000
	// the preference of the main table's own rule; nothing at or after it diverts traffic
	prefMainRule = 32766
)

// ruleDiverts reports whether r sends all traffic (except, maybe, the marked
// packets of a client's own sockets) to a table other than main, before the
// main table is consulted. A rule with a selector (a positive fwmark, a uid
// range, an interface, a port...) sends only some traffic and does not count.
func ruleDiverts(r OSRule) bool {
	return r.ToTable && !r.Ours && r.Table != RuleTableMain && r.Table != 255 && r.Table != 253 &&
		r.Pref > 0 && r.Pref < prefMainRule && r.Suppress < 0 && r.matchesAll()
}

// diverting returns the rules of VPN clients (or anybody) that send traffic
// to a table other than main before the main table is consulted.
func diverting(rules []OSRule) []OSRule {
	var out []OSRule
	for _, r := range rules {
		if ruleDiverts(r) {
			out = append(out, r)
		}
	}
	return out
}

// mainVisibleBefore reports whether a rule that looks up the main table, and
// does not hide routes of the lengths we use, comes before pref: wg-quick's
// "lookup main suppress_prefixlength 0". Our routes are found then without
// rules of ours.
func mainVisibleBefore(rules []OSRule, pref, minBits int) bool {
	for _, r := range rules {
		if r.ToTable && !r.Ours && r.Table == RuleTableMain && r.Pref < pref &&
			!r.hasSel() && r.Suppress < minBits {
			return true
		}
	}
	return false
}

// planRules returns the rule (none or one) that makes our table visible past
// the policy routing of the VPN clients, and a remark if there is something
// to say. prefixes are the networks that would go into the table.
func planRules(rules []OSRule, prefixes []netip.Prefix) (out []config.Rule, note string) {
	return planRulesIn(rules, prefixes, config.OwnTable)
}

// planRulesIn is planRules for the routing table n.
func planRulesIn(rules []OSRule, prefixes []netip.Prefix, n int) (out []config.Rule, note string) {
	div := diverting(rules)
	if len(div) == 0 || len(prefixes) == 0 {
		return nil, ""
	}
	minPref, minBits := div[0].Pref, 32
	for _, d := range div {
		minPref = min(minPref, d.Pref)
	}
	for _, p := range prefixes {
		minBits = min(minBits, p.Bits())
	}
	if mainVisibleBefore(rules, minPref, minBits) {
		return nil, fmt.Sprintf("a VPN client sends traffic to its own table from pref %d, but the main table is consulted before: no rules needed", minPref)
	}
	pref := rulePrefBase
	if pref >= minPref {
		pref = minPref - 1 // the line of the client's rules is crossed: still before the first of them
	}
	if pref < 1 {
		return nil, fmt.Sprintf("a VPN client's policy rule at pref %d cannot be overtaken: corp and direct routes may not work", minPref)
	}
	out = []config.Rule{{Table: n, Pref: pref}}
	return out, fmt.Sprintf("a VPN client sends traffic to its own table from pref %d: %d routes go to table %d, rule \"lookup %d\" added at pref %d",
		minPref, len(prefixes), n, n, pref)
}

// captured reports whether the home VPN client already sends everything into
// the tunnel by its policy rules: a diverting rule whose table has a default
// route (or the two halves of it) through the home adapter. 0/1 + 128/1 in
// the main table are redundant then, and harmful: packets of the client
// itself, which its rules let through to the main table, would be caught by
// them and sent into the tunnel.
func captured(rules []OSRule, tbl *table, home string) (int, bool) {
	if tbl == nil || !tbl.known {
		return 0, false
	}
	for _, d := range diverting(rules) {
		for _, r := range tbl.all {
			if r.Table == d.Table && r.Dest.Bits() <= 1 && r.Iface == home {
				return d.Table, true
			}
		}
	}
	return 0, false
}

// planPins decides what to do about the servers of VPNs, whose packets must
// stay off the tunnels. A corp rule that covers the address of a server would
// send its packets into the corp tunnel (or, in our table, past the client's
// own host route): it is dropped, with a warning. With pin set (0/1 + 128/1
// go to the home tunnel) a server also needs a host route through the
// physical gateway: if the table has one already (the client added it) nothing
// is added, otherwise the route is added when there is a gateway.
func planPins(gw Gateway, gwOK bool, tbl *table, cands []netip.Addr, corp []netip.Prefix, pin bool) (pins []config.Route, drop map[netip.Prefix]bool, warns []string) {
	drop = map[netip.Prefix]bool{}
	for _, a := range cands {
		host := netip.PrefixFrom(a, 32)
		pinned := false
		if tbl != nil && tbl.known {
			for _, r := range tbl.routes {
				if r.Dest == host && netif.Classify(r.Iface) == netif.KindPhysical {
					pinned = true
					break
				}
			}
		}
		for _, c := range corp {
			if c.Contains(a) {
				drop[c] = true
				warns = append(warns, fmt.Sprintf("corp rule %s covers %s, the address of a VPN server: not applied, the tunnel must not carry its own packets", c, a))
			}
		}
		if pin && !pinned && gwOK {
			pins = append(pins, config.Route{Dest: host.String(), Iface: gw.Iface, Gateway: gw.Router, Via: ViaPin, Metric: ownMetric})
		}
	}
	return pins, drop, warns
}

// pinnedHosts counts /32 routes through physical adapters: what clients add
// to keep their servers off their own tunnel.
func pinnedHosts(tbl *table) int {
	n := 0
	if tbl == nil || !tbl.known {
		return 0
	}
	for _, r := range tbl.routes {
		if r.Dest.Bits() == 32 && r.Iface != "" && netif.Classify(r.Iface) == netif.KindPhysical {
			n++
		}
	}
	return n
}

// endpointCandidates are the addresses of the servers of the VPNs that must
// stay off the tunnels. Nothing reliable tells them on every OS: a WireGuard
// peer needs genetlink, and the sockets of a client are not tied to its
// adapter. What clients pin themselves is known: a /32 route through a
// physical adapter and a next hop, which is not the gateway itself and not a
// route of ours (a pin of ours from an earlier apply says nothing about the
// client). The list is empty for a client that keeps its packets off the tunnel
// by a mark and adds no route.
func endpointCandidates(e Env, tbl *table, st *config.State) []netip.Addr {
	if tbl == nil || !tbl.known {
		return nil
	}
	mine := map[netip.Prefix]bool{}
	if st != nil {
		for _, r := range st.Routes {
			if r.Via == ViaPin {
				if p, err := netip.ParsePrefix(r.Dest); err == nil {
					mine[p.Masked()] = true
				}
			}
		}
	}
	gw := addrOrZero(e.GW.Router)
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, r := range tbl.routes {
		a := r.Dest.Addr()
		if r.Dest.Bits() != 32 || !r.Gateway.IsValid() || r.Iface == "" || netif.Classify(r.Iface) != netif.KindPhysical ||
			a == gw || mine[r.Dest] || (routesTagged && r.Ours) || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// buildPlan works out what routing should be for the connected VPNs and the
// rules of cfg. Whatever needs the network (RIPE, DNS) happens here, before
// anything in the OS is touched.
func (m *Manager) buildPlan(cfg *config.Config, e Env, st *config.State, tbl *table, rs *ruleSet, w io.Writer) *plan {
	p := &plan{}
	seen := map[string]int{} // dest -> index in p.routes
	add := func(r config.Route) {
		r.Metric = ownMetric
		if err := config.ValidateRoute(r); err != nil {
			p.warns = append(p.warns, fmt.Sprintf("%s: %v", r.Dest, err))
			return
		}
		r.Dest, _ = config.ParseCIDR4(r.Dest) // canonical: a prefix is one entry however it is written
		if i, ok := seen[r.Dest]; ok {
			if p.routes[i].Via != r.Via {
				fmt.Fprintf(w, "  = %-18s is both %s and %s: %s wins\n", r.Dest, p.routes[i].Via, r.Via, p.routes[i].Via)
			}
			return
		}
		seen[r.Dest] = len(p.routes)
		p.routes = append(p.routes, r)
	}

	var corpPrefixes []netip.Prefix
	var corpRoutes []config.Route
	if e.CorpOK {
		corp := func(dest string) {
			corpRoutes = append(corpRoutes, config.Route{Dest: dest, Iface: e.Corp.Name, Gateway: cfg.CorpGateway, Via: ViaCorp})
		}
		servers, zones := m.dnsOf(e.Corp.Name)
		servers = validServers(servers)
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
			for _, ip := range resolveDomains(m.ctx, cfg.Domains, first(servers), w) {
				corp(ip)
			}
		}
		if cfg.SplitDNS && len(servers) > 0 {
			p.dns = cleanZones(e.Corp.Name, servers, append(zones, cfg.Domains...), cfg.DirectDomains)
		}
	}

	var directRoutes []config.Route
	if e.GWOK {
		direct := func(dest string) {
			directRoutes = append(directRoutes, config.Route{Dest: dest, Iface: e.GW.Iface, Gateway: e.GW.Router, Via: ViaDirect})
		}
		for _, n := range expandNets(cfg.DirectNetworks, w) {
			direct(n)
		}
		if len(cfg.DirectDomains) > 0 {
			fmt.Fprintln(w, "resolving direct domains...")
			for _, ip := range resolveDomains(m.ctx, cfg.DirectDomains, "", w) {
				direct(ip)
			}
		}
	}

	var rules []OSRule
	if rs != nil && rs.known {
		rules = rs.all
	}
	homeFull := e.HomeOK && cfg.HomeDefault
	if homeFull {
		if t, ok := captured(rules, tbl, e.Home.Name); ok {
			homeFull = false
			fmt.Fprintf(w, "home VPN: its own policy routing (table %d) already sends everything into the tunnel, 0/1 + 128/1 not added\n", t)
		}
	}

	// the servers of VPNs: no corp rule over them; with the halves, a pin each
	var pins []config.Route
	for _, r := range corpRoutes {
		if pf, err := netip.ParsePrefix(r.Dest); err == nil {
			corpPrefixes = append(corpPrefixes, pf.Masked())
		}
	}
	cands := endpointCandidates(e, tbl, st)
	if len(cands) > 0 || homeFull {
		var drop map[netip.Prefix]bool
		var warns []string
		pins, drop, warns = planPins(e.GW, e.GWOK, tbl, cands, corpPrefixes, homeFull)
		p.warns = append(p.warns, warns...)
		if len(drop) > 0 {
			var kept []config.Route
			for _, r := range corpRoutes {
				if pf, err := netip.ParsePrefix(r.Dest); err == nil && drop[pf.Masked()] {
					continue
				}
				kept = append(kept, r)
			}
			corpRoutes = kept
		}
	}
	if homeFull && tbl != nil && tbl.known && len(pins) == 0 && pinnedHosts(tbl) == 0 {
		p.warns = append(p.warns, "endpoint not pinned: no /32 route to a VPN server through the physical gateway was found; "+
			"if the VPN client does not keep its own packets off the tunnel, 0/1 + 128/1 may loop them into it")
	}

	for _, r := range corpRoutes {
		add(r)
	}
	for _, r := range directRoutes {
		add(r)
	}
	for _, r := range pins {
		add(r)
	}
	if homeFull {
		// two halves of the address space beat the default route without touching it
		for _, d := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			add(config.Route{Dest: d, Iface: e.Home.Name, Via: ViaHome})
		}
	}

	var pfx []netip.Prefix
	for _, r := range p.routes {
		if r.Via == ViaCorp || r.Via == ViaDirect {
			if pf, err := netip.ParsePrefix(r.Dest); err == nil {
				pfx = append(pfx, pf)
			}
		}
	}
	p.rules, p.warns = policyFor(p.routes, pfx, tbl, rs, rules, p.warns, w)
	return p
}

// policyFor works out the rule for the routes of corp and direct networks and
// moves them into our table when the rule is needed.
func policyFor(routes []config.Route, pfx []netip.Prefix, tbl *table, rs *ruleSet, rules []OSRule, warns []string, w io.Writer) ([]config.Rule, []string) {
	n, free := pickOwnTable(tbl, rs)
	out, note := planRulesIn(rules, pfx, n)
	if len(out) > 0 && !free {
		return nil, append(warns, fmt.Sprintf("routing tables %d-%d are all used by something else: corp and direct routes stay in the main table, "+
			"a VPN client's policy rules may hide them", config.OwnTable, config.OwnTableLast))
	}
	if note != "" {
		fmt.Fprintln(w, note)
	}
	if len(out) > 0 {
		for i := range routes {
			if routes[i].Via == ViaCorp || routes[i].Via == ViaDirect {
				routes[i].Table = n
			}
		}
	}
	return out, warns
}

// cleanZones prepares the zones for the per-domain DNS entries: lower case,
// valid, without the zones that go direct.
func cleanZones(iface string, servers, zones, skip []string) *dnsPlan {
	var clean []string
	done := map[string]bool{}
	for _, s := range skip {
		done[s] = true
	}
	for _, z := range zones {
		z = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(z), "~"), ".")
		if z != "" && !done[z] && config.ValidZone(z) {
			done[z] = true
			clean = append(clean, z)
		}
	}
	ids := resolverPlan(iface, servers, clean)
	if len(ids) == 0 {
		return nil
	}
	return &dnsPlan{iface: iface, servers: servers, ids: ids}
}

// bootstrapPlan is the part of the plan the rest depends on: corp domains
// are resolved through the corp DNS, so a route to it (and, with policy
// routing, a rule) must exist before the full plan can be made. nil if no
// corp domain needs resolving.
func bootstrapPlan(cfg *config.Config, e Env, tbl *table, rs *ruleSet) *plan {
	if !e.CorpOK || cfg.CorpDNS == "" || len(cfg.Domains) == 0 {
		return nil
	}
	r := config.Route{Dest: cfg.CorpDNS + "/32", Iface: e.Corp.Name, Gateway: cfg.CorpGateway, Via: ViaCorp, Metric: ownMetric}
	if config.ValidateRoute(r) != nil {
		return nil
	}
	p := &plan{routes: []config.Route{r}}
	if rs != nil && rs.known {
		p.rules, p.warns = policyFor(p.routes, pfx1(r.Dest), tbl, rs, rs.all, nil, io.Discard)
	}
	return p
}

func pfx1(s string) []netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return nil
	}
	return []netip.Prefix{p.Masked()}
}
