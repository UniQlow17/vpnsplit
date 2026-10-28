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
	dns    *dnsPlan // the corp zones, to the corp DNS
	direct *dnsPlan // the zones that go direct, to the DNS of the provider (with the rest going home)
	rest   *dnsPlan // everything else ("."), to the DNS of the home VPN
	tun6   bool     // Windows: Teredo, 6to4 and ISATAP are turned off
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

// dnsItem is one DNS entry to make and the servers it points to.
type dnsItem struct {
	id      string
	servers []string
}

// dnsItems lists every DNS entry of the plan: the corp zones, then the one for the rest.
func (p *plan) dnsItems() []dnsItem {
	var out []dnsItem
	for _, g := range []*dnsPlan{p.dns, p.direct, p.rest} {
		if g == nil {
			continue
		}
		for _, id := range g.ids {
			out = append(out, dnsItem{id, g.servers})
		}
	}
	return out
}

// dnsIDs are the ids of dnsItems.
func (p *plan) dnsIDs() []string {
	var ids []string
	for _, it := range p.dnsItems() {
		ids = append(ids, it.id)
	}
	return ids
}

// dnsSig identifies all the DNS entries of the plan (one signature per group,
// ";" between them).
func (p *plan) dnsSig() string {
	var parts []string
	for _, g := range []*dnsPlan{p.dns, p.direct, p.rest} {
		if g != nil {
			parts = append(parts, g.sig())
		}
	}
	return strings.Join(parts, ";")
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
			if r.Table == d.Table && r.Dest.Addr().Is4() && r.Dest.Bits() <= 1 && r.Iface == home {
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
// to keep their servers off their own tunnel. Routes of ours (the journal lists
// them, or the OS tags them) are not a client's.
func pinnedHosts(tbl *table, st *config.State) int {
	n := 0
	if tbl == nil || !tbl.known {
		return 0
	}
	mine := mineRoutes(st)
	for _, r := range tbl.routes {
		if r.Dest.Addr().Is4() && r.Dest.Bits() == 32 && r.Iface != "" && netif.Classify(r.Iface) == netif.KindPhysical && !isMine(r, mine) {
			n++
		}
	}
	return n
}

// mineRoutes are the destinations of the journal: pins, /32 routes to DNS
// servers and the rest, ours and not a client's.
func mineRoutes(st *config.State) map[netip.Prefix]bool {
	mine := map[netip.Prefix]bool{}
	if st != nil {
		for _, r := range st.Routes {
			if p, err := netip.ParsePrefix(r.Dest); err == nil {
				mine[p.Masked()] = true
			}
		}
	}
	return mine
}

// isMine reports whether an OS route is ours: Linux tags ours, on Windows and
// macOS the journal is compared.
func isMine(r OSRoute, mine map[netip.Prefix]bool) bool {
	return mine[r.Dest] || (routesTagged && r.Ours)
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
	mine := mineRoutes(st) // pins, and the /32 routes to DNS servers: ours, not a client's
	gw := addrOrZero(e.GW.Router)
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, r := range tbl.routes {
		a := r.Dest.Addr()
		if !r.Dest.Addr().Is4() || r.Dest.Bits() != 32 || !r.Gateway.IsValid() || r.Iface == "" || netif.Classify(r.Iface) != netif.KindPhysical ||
			a == gw || isMine(r, mine) || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// fakeIPNet is the range (RFC 2544, 198.18.0.0/15) that a "fake-ip" DNS (Clash,
// sing-box, some other clients) answers from: an address that exists only inside
// the client, to be turned back into the real name there. A route to it, or a
// rule that takes it for the real address of the name, would be wrong.
var fakeIPNet = netip.MustParsePrefix("198.18.0.0/15")

// ownTableRoute reports whether r goes into our table when the rule that makes
// the table visible is needed: routes of the corp and direct kinds (the
// halves of "the rest goes direct" included) and the user's rules of the home
// kind. The halves of the home tunnel stay in main (see the comment at rulePrefBase).
func ownTableRoute(r config.Route) bool {
	switch r.Via {
	case ViaCorp, ViaDirect:
		return true
	case ViaHome:
		p, err := netip.ParsePrefix(r.Dest)
		return err == nil && p.Addr().Is4() && p.Bits() > 1
	}
	return false
}

// dnsMemo remembers what the OS said about DNS servers during one apply: the
// answer takes a PowerShell call or a tool run, and the bootstrap and the full
// plan both need it.
type dnsMemo struct {
	dns  map[string][2][]string
	phys map[string][]string
}

func newDNSMemo() *dnsMemo {
	return &dnsMemo{dns: map[string][2][]string{}, phys: map[string][]string{}}
}

func (m *Manager) dnsOfMemo(iface string) (servers, zones []string) {
	if m.memo == nil {
		return m.dnsOf(iface)
	}
	if v, ok := m.memo.dns[iface]; ok {
		return v[0], v[1]
	}
	servers, zones = m.dnsOf(iface)
	m.memo.dns[iface] = [2][]string{servers, zones}
	return servers, zones
}

func (m *Manager) physDNSMemo(iface string) []string {
	if m.physDNS == nil {
		return nil
	}
	if m.memo == nil {
		return validServers(m.physDNS(iface))
	}
	if v, ok := m.memo.phys[iface]; ok {
		return v
	}
	v := validServers(m.physDNS(iface))
	m.memo.phys[iface] = v
	return v
}

// corpServers are the DNS servers of the corp VPN: the one the user set, or what
// the corp client put on its adapter.
func (m *Manager) corpServers(cfg *config.Config, e Env) (servers, zones []string) {
	servers, zones = m.dnsOfMemo(e.Corp.Name)
	servers = validServers(servers)
	if cfg.CorpDNS != "" {
		servers = []string{cfg.CorpDNS}
	}
	return servers, zones
}

// directServers are the DNS servers of the provider on the physical adapter,
// the ones that may resolve the domains that go direct.
func (m *Manager) directServers(e Env) []string {
	if !e.GWOK {
		return nil
	}
	return m.physDNSMemo(e.GW.Iface)
}

// hostRoutes makes a /32 route to each server through the adapter (and the
// next hop, if there is one), except to the next hop itself: that one is
// reached on the link. A server in one of the networks of the adapter (onlink)
// is reached on the link too: its route has no next hop.
func hostRoutes(servers []string, iface, gateway, via string, onlink []netip.Prefix) []config.Route {
	var out []config.Route
	for _, s := range servers {
		if s == gateway {
			continue
		}
		gw := gateway
		if a, err := netip.ParseAddr(s); err == nil {
			for _, n := range onlink {
				if n.Contains(a) {
					gw = ""
					break
				}
			}
		}
		out = append(out, config.Route{Dest: s + "/32", Iface: iface, Gateway: gw, Via: via})
	}
	return out
}

// badServer says why the address of a DNS server that the OS reported cannot
// be used for a route or a DNS entry ("" when it is fine): it is not an address
// of one host in the network (loopback, link-local, multicast...). A fake-ip range
// is not a reason here: it describes what a DNS answers, and a server the OS
// itself reports (the DNS of the TUN of a client, 198.18.0.2) is a real one.
func badServer(a netip.Addr) string {
	a = a.Unmap()
	switch {
	case !a.IsValid():
		return "not an address"
	case a.IsLoopback():
		return "loopback"
	case a.IsUnspecified():
		return "unspecified"
	case a.IsMulticast():
		return "multicast"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "broadcast"
	}
	return ""
}

// badAddr says why no route and no DNS entry is made for the address a (""
// when it is fine) that a DNS answered: it is not an address of one host in the
// network, or it is the fake one of a client.
func badAddr(a netip.Addr) string {
	if w := badServer(a); w != "" {
		return w
	}
	if a = a.Unmap(); isFakeIP(a) {
		return "in the fake-ip range (" + fakeRangeOf(a) + ")"
	}
	return ""
}

// avoid is what the addresses of the provider's DNS and the answers for the
// names that go direct must stay clear of: a /32 route to one of them would
// cut into what another rule or a tunnel needs.
type avoid struct {
	addrs map[netip.Addr]string
	nets  []avoidNet
}

type avoidNet struct {
	p   netip.Prefix
	why string
}

func newAvoid() *avoid { return &avoid{addrs: map[netip.Addr]string{}} }

func (v *avoid) addAddrs(why string, list ...string) {
	for _, s := range list {
		if a, err := netip.ParseAddr(s); err == nil {
			if _, dup := v.addrs[a]; !dup {
				v.addrs[a] = why
			}
		}
	}
}

func (v *avoid) addAddrList(why string, list []netip.Addr) {
	for _, a := range list {
		if _, dup := v.addrs[a]; !dup {
			v.addrs[a] = why
		}
	}
}

func (v *avoid) addNets(why string, list ...netip.Prefix) {
	for _, p := range list {
		v.nets = append(v.nets, avoidNet{p.Masked(), why})
	}
}

// why says why a has to be left alone ("" if it does not).
func (v *avoid) why(a netip.Addr) string {
	a = a.Unmap()
	if w := badAddr(a); w != "" {
		return w
	}
	if w, ok := v.addrs[a]; ok {
		return w
	}
	for _, n := range v.nets {
		if n.p.Contains(a) {
			return n.why
		}
	}
	return ""
}

// filterServers drops the DNS servers of the provider that must be left alone;
// a note says why for each.
func (v *avoid) filterServers(servers []string) (kept, notes []string) {
	for _, s := range servers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if w := v.why(a); w != "" {
			notes = append(notes, fmt.Sprintf("the DNS server %s of the provider is %s: no direct route to it, it is not asked about the names that go direct", s, w))
			continue
		}
		kept = append(kept, s)
	}
	return kept, notes
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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
		pf, _ := config.ParseCIDR(r.Dest)
		r.Dest = pf.String() // canonical: a prefix is one entry however it is written
		if i, ok := seen[r.Dest]; ok {
			if p.routes[i].Via != r.Via {
				fmt.Fprintf(w, "  = %-18s is both %s and %s: %s wins\n", r.Dest, p.routes[i].Via, r.Via, p.routes[i].Via)
			}
			return
		}
		seen[r.Dest] = len(p.routes)
		p.routes = append(p.routes, r)
	}
	kinds := cfg.Kinds()
	unused := 0 // rules of a kind that does not matter with this setting of the rest
	for _, k := range []string{config.DestDirect, config.DestHome} {
		if !has(kinds, k) {
			n, d := cfg.ListsOf(k)
			unused += len(*n) + len(*d)
		}
	}
	if unused > 0 {
		fmt.Fprintf(w, "%d rules of a kind that has no meaning with \"rest: %s\" are kept in the config and not applied\n", unused, cfg.Rest)
	}

	restHome := e.HomeOK && cfg.Rest == config.RestHome
	cands := endpointCandidates(e, tbl, st)
	var homeDNS []string // the DNS of the home VPN: no provider's /32 may point at it
	if e.HomeOK {
		homeDNS, _ = m.dnsOfMemo(e.Home.Name)
		homeDNS = validServers(homeDNS)
	}

	var corpPrefixes []netip.Prefix
	var corpRoutes []config.Route
	var corpSrv []string
	if e.CorpOK {
		corp := func(dest string) {
			corpRoutes = append(corpRoutes, config.Route{Dest: dest, Iface: e.Corp.Name, Gateway: cfg.CorpGateway, Via: ViaCorp})
		}
		servers, zones := m.corpServers(cfg, e)
		corpSrv = servers
		for _, s := range servers {
			corp(s + "/32") // the corp DNS itself must be reachable through corp
		}
		if len(servers) > 0 {
			fmt.Fprintf(w, "corp DNS: %s\n", strings.Join(servers, ", "))
		}
		for _, n := range expandNets(cfg.Networks, w) {
			corp(n)
		}
		if len(cfg.Domains) > 0 {
			fmt.Fprintln(w, "resolving corp domains...")
			ips, dropped := m.resolveDomains(cfg.Domains, servers, nil, w)
			p.warns = append(p.warns, dropped...)
			for _, ip := range ips {
				corp(ip)
			}
		}
		if cfg.SplitDNS && len(servers) > 0 {
			p.dns = cleanZones(e.Corp.Name, servers, append(zones, cfg.Domains...), cfg.DirectDomains, journalResolvers(st))
		}
	}
	for _, r := range corpRoutes {
		if pf, err := netip.ParsePrefix(r.Dest); err == nil {
			corpPrefixes = append(corpPrefixes, pf.Masked())
		}
	}

	// the rules "through the home VPN" come before the direct ones are worked out:
	// an address that is both must not get a /32 around the tunnel
	var homeRoutes []config.Route
	var homePrefixes []netip.Prefix
	if e.HomeOK && has(kinds, config.DestHome) {
		home := func(dest string) {
			homeRoutes = append(homeRoutes, config.Route{Dest: dest, Iface: e.Home.Name, Via: ViaHome})
		}
		for _, n := range expandNets(cfg.HomeNetworks, w) {
			home(n)
		}
		if len(cfg.HomeDomains) > 0 {
			fmt.Fprintln(w, "resolving home domains...")
			ips, dropped := m.resolveDomains(cfg.HomeDomains, nil, nil, w)
			p.warns = append(p.warns, dropped...)
			for _, ip := range ips {
				home(ip)
			}
		}
		for _, r := range homeRoutes {
			homePrefixes = append(homePrefixes, pfx1(r.Dest)...)
		}
	} else if !e.HomeOK && has(kinds, config.DestHome) && len(cfg.HomeNetworks)+len(cfg.HomeDomains) > 0 {
		fmt.Fprintln(w, "home VPN is not connected, its rules are skipped")
	}

	var directRoutes []config.Route
	if e.GWOK && has(kinds, config.DestDirect) {
		direct := func(dest string) {
			directRoutes = append(directRoutes, config.Route{Dest: dest, Iface: e.GW.Iface, Gateway: e.GW.Router, Via: ViaDirect})
		}
		for _, n := range expandNets(cfg.DirectNetworks, w) {
			direct(n)
		}
		if len(cfg.DirectDomains) > 0 {
			av := newAvoid()
			av.addAddrs("the corp DNS server", corpSrv...)
			av.addAddrs("the DNS server of the home VPN", homeDNS...)
			av.addAddrList("the address of a VPN server", cands)
			av.addNets("covered by a corp rule", corpPrefixes...)
			av.addNets("covered by a rule through the home VPN", homePrefixes...)
			// the names that go direct are asked of the DNS of the provider, not of
			// whatever the system would pick (that may be a VPN's)
			servers, notes := av.filterServers(m.directServers(e))
			p.warns = append(p.warns, notes...)
			if len(servers) > 0 {
				fmt.Fprintf(w, "direct DNS (provider): %s\n", strings.Join(servers, ", "))
				directRoutes = append(directRoutes, hostRoutes(servers, e.GW.Iface, e.GW.Router, ViaDirect, e.GWNets)...)
			} else if len(notes) == 0 {
				p.warns = append(p.warns, "the DNS servers of the provider are unknown: the domains that go direct are resolved by the system resolver")
			} else {
				p.warns = append(p.warns, "no DNS server of the provider is usable: the domains that go direct are resolved by the system resolver")
			}
			fmt.Fprintln(w, "resolving direct domains...")
			ips, dropped := m.resolveDomains(cfg.DirectDomains, servers, av.why, w)
			p.warns = append(p.warns, dropped...)
			for _, ip := range ips {
				direct(ip)
			}
			// with the rest going home the applications must ask the same server, or they
			// get another address than the one the route was made for
			if restHome && len(servers) > 0 {
				p.direct = cleanZones(e.GW.Iface, servers, cfg.DirectDomains, nil, journalResolvers(st))
			}
		}
	}

	var rules []OSRule
	if rs != nil && rs.known {
		rules = rs.all
	}
	homeFull := restHome
	if homeFull {
		if t, ok := captured(rules, tbl, e.Home.Name); ok {
			homeFull = false
			fmt.Fprintf(w, "home VPN: its own policy routing (table %d) already sends everything into the tunnel, 0/1 + 128/1 not added\n", t)
		}
	}
	restDirect := cfg.Rest == config.RestDirect && e.GWOK
	if cfg.Rest == config.RestDirect && !e.GWOK {
		p.warns = append(p.warns, "the rest of the traffic should go direct, but no Wi-Fi/Ethernet gateway was found")
	}
	if restDirect {
		for _, r := range foreignHalves(tbl, st, e.GW.Iface) {
			p.warns = append(p.warns, fmt.Sprintf("%s is routed through %s by somebody else: the rest may not go direct if that route wins", r.Dest, r.Iface))
		}
	}

	// the servers of VPNs: no corp rule over them; with the halves, a pin each
	var pins []config.Route
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
	if homeFull && tbl != nil && tbl.known && len(pins) == 0 && pinnedHosts(tbl, st) == 0 {
		p.warns = append(p.warns, "endpoint not pinned: no /32 route to a VPN server through the physical gateway was found; "+
			"if the VPN client does not keep its own packets off the tunnel, 0/1 + 128/1 may loop them into it")
	}

	for _, r := range corpRoutes {
		add(r)
	}
	for _, r := range directRoutes {
		add(r)
	}
	for _, r := range homeRoutes {
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
		// the same for IPv6, when the home VPN has any: otherwise it would go
		// around the tunnel (see V6Status). Not on macOS until it is tried there.
		if e.Home.HasV6() && v6Halves {
			for _, d := range []string{"::/1", "8000::/1"} {
				add(config.Route{Dest: d, Iface: e.Home.Name, Via: ViaHome})
			}
		}
	}
	if restDirect {
		for _, d := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			add(config.Route{Dest: d, Iface: e.GW.Iface, Gateway: e.GW.Router, Via: ViaDirect})
		}
	}

	// the DNS of everything else: the home VPN's, wherever the home VPN takes the rest
	switch {
	case !restHome:
	case !restDNS:
		p.warns = append(p.warns, "this OS cannot send the rest of the DNS queries to the home VPN: they stay with the system")
	case m.oneShot:
		p.warns = append(p.warns, "the DNS of the rest of the traffic is not sent to the home VPN by \"apply\": if the home VPN fell, "+
			"all the names would stop resolving until \"reset\"; use \"run\" or \"watch\" for it")
	case e.CorpOK && p.dns == nil:
		p.warns = append(p.warns, "the corp zones are not set up (split DNS is off, or the corp DNS or its zones are unknown): "+
			"the DNS of the rest of the traffic is not sent to the home VPN, it would take the corp names too")
	case len(homeDNS) == 0:
		p.warns = append(p.warns, "the DNS servers of the home VPN are unknown: the DNS of the rest of the traffic stays with the system")
	default:
		if ids := resolverPlan(e.Home.Name, homeDNS, []string{"."}, journalResolvers(st)); len(ids) > 0 {
			fmt.Fprintf(w, "home DNS: %s (for everything else)\n", strings.Join(homeDNS, ", "))
			p.rest = &dnsPlan{iface: e.Home.Name, servers: homeDNS, ids: ids}
		} else {
			p.warns = append(p.warns, "the system cannot send the rest of the DNS queries to the home VPN (no systemd-resolved)")
		}
	}
	if restHome && m.canTun6() {
		p.tun6 = true
	}

	var pfx []netip.Prefix
	for _, r := range p.routes {
		if ownTableRoute(r) {
			if pf, err := netip.ParsePrefix(r.Dest); err == nil && pf.Addr().Is4() {
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
			if ownTableRoute(routes[i]) {
				routes[i].Table = n
			}
		}
	}
	return out, warns
}

// cleanZones prepares the zones for the per-domain DNS entries: lower case,
// valid, without the zones that go direct.
func cleanZones(iface string, servers, zones, skip, journal []string) *dnsPlan {
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
	ids := resolverPlan(iface, servers, clean, journal)
	if len(ids) == 0 {
		return nil
	}
	return &dnsPlan{iface: iface, servers: servers, ids: ids}
}

// bootstrapPlan is the part of the plan the rest depends on: the domains are
// resolved through the corp DNS (corp ones) and the DNS of the provider (direct
// ones), so a route to each of them must exist before the full plan can be
// made, and with policy routing a rule too. nil if no domain needs resolving
// that way.
func (m *Manager) bootstrapPlan(cfg *config.Config, e Env, st *config.State, tbl *table, rs *ruleSet) *plan {
	var routes []config.Route
	add := func(list []config.Route) {
		for _, r := range list {
			r.Metric = ownMetric
			if config.ValidateRoute(r) == nil {
				routes = append(routes, r)
			}
		}
	}
	var corpSrv, homeDNS []string
	if e.CorpOK {
		corpSrv, _ = m.corpServers(cfg, e)
	}
	if e.HomeOK {
		homeDNS, _ = m.dnsOfMemo(e.Home.Name)
		homeDNS = validServers(homeDNS)
	}
	if e.CorpOK && len(cfg.Domains) > 0 {
		add(hostRoutes(corpSrv, e.Corp.Name, cfg.CorpGateway, ViaCorp, nil))
	}
	if e.GWOK && len(cfg.DirectDomains) > 0 && has(cfg.Kinds(), config.DestDirect) {
		// the same servers the full plan will ask (see buildPlan): not the corp DNS, not the home VPN's
		av := newAvoid()
		av.addAddrs("the corp DNS server", corpSrv...)
		av.addAddrs("the DNS server of the home VPN", homeDNS...)
		av.addAddrList("the address of a VPN server", endpointCandidates(e, tbl, st))
		// the networks written out are known without asking RIPE
		if e.CorpOK {
			av.addNets("covered by a corp rule", literalNets(cfg.Networks)...)
		}
		if e.HomeOK && has(cfg.Kinds(), config.DestHome) {
			av.addNets("covered by a rule through the home VPN", literalNets(cfg.HomeNetworks)...)
		}
		servers, _ := av.filterServers(m.directServers(e))
		add(hostRoutes(servers, e.GW.Iface, e.GW.Router, ViaDirect, e.GWNets))
	}
	if len(routes) == 0 {
		return nil
	}
	p := &plan{routes: routes}
	if rs != nil && rs.known {
		var pfx []netip.Prefix
		for _, r := range routes {
			pfx = append(pfx, pfx1(r.Dest)...)
		}
		p.rules, p.warns = policyFor(p.routes, pfx, tbl, rs, rs.all, nil, io.Discard)
	}
	return p
}

// literalNets are the networks of rules that are written out (an autonomous
// system needs RIPE, and is not among them).
func literalNets(rules []string) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range rules {
		if config.IsAS(r) {
			continue
		}
		if pf, err := config.ParseCIDR(r); err == nil {
			out = append(out, pf.Masked())
		}
	}
	return out
}

func pfx1(s string) []netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return nil
	}
	return []netip.Prefix{p.Masked()}
}

// foreignHalves lists the routes of the two halves of the address space (0/1
// and 128/1) in the main table that are neither ours nor through the adapter
// iface: a VPN client that takes the default route that way competes with ours.
func foreignHalves(tbl *table, st *config.State, iface string) []OSRoute {
	if tbl == nil || !tbl.known {
		return nil
	}
	mine := map[netip.Prefix]string{}
	if st != nil {
		for _, r := range st.Routes {
			if p, err := netip.ParsePrefix(r.Dest); err == nil {
				mine[p.Masked()] = r.Iface
			}
		}
	}
	var out []OSRoute
	for _, r := range tbl.routes {
		if !r.Dest.Addr().Is4() || r.Dest.Bits() != 1 || r.Iface == iface || (routesTagged && r.Ours) || mine[r.Dest] == r.Iface {
			continue
		}
		out = append(out, r)
	}
	return out
}

// journalResolvers lists the DNS entries of the journal (nil for no journal).
func journalResolvers(st *config.State) []string {
	if st == nil {
		return nil
	}
	return st.Resolvers
}
