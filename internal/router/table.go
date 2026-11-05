package router

import (
	"errors"
	"net/netip"
	"sort"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// ErrNoTable is returned by Backend.Routes on an OS whose routing table is
// not read natively: the journal is then the only record of what is there.
var ErrNoTable = errors.New("the routing table cannot be read on this OS")

// OSRoute is one IPv4 unicast route as the OS reports it.
type OSRoute struct {
	Dest     netip.Prefix
	Iface    string // adapter name as netif knows it; "" if unknown
	IfIndex  int
	Gateway  netip.Addr // invalid: on-link
	Metric   int        // the route's own metric (Windows: without the interface metric)
	Table    int        // 0: the main table (Linux: other tables are listed too, by number)
	IfMetric int        // Windows: the metric of the adapter, added to Metric by the OS
	Ours     bool       // carries our tag (Linux: protocol); false where nothing marks routes
	NotOurs  bool       // Windows: the protocol or origin of the route is not what we create; such a route is never ours
	Proto    int        // Linux: rtm_protocol; Windows: NL_ROUTE_PROTOCOL
	Origin   int        // Windows: NL_ROUTE_ORIGIN
	LUID     uint64     // Windows: the locally unique id of the adapter
}

// OSRule is one IPv4 policy routing rule (Linux).
type OSRule struct {
	Pref     int
	Table    int          // routing table of an "lookup" rule; RuleTableMain = main
	Dest     netip.Prefix // invalid: any
	Src      netip.Prefix // invalid: any
	Suppress int          // suppress_prefixlength, -1: none
	ToTable  bool         // the action is "lookup table"
	Fwmark   bool         // selects by fwmark (and mask)
	Inv      bool         // FIB_RULE_INVERT: the selectors are negated ("not fwmark X")
	OtherSel bool         // any other selector or filter: interface, uid range, ip protocol, port, tos, l3mdev, suppress_ifgroup
	Ours     bool         // carries our protocol tag
}

// hasSel reports whether the rule matches only some of the packets because of
// its selectors (a source or destination prefix counts too).
func (r OSRule) hasSel() bool {
	return r.Fwmark || r.Inv || r.OtherSel || r.Src.IsValid() || r.Dest.IsValid()
}

// matchesAll reports whether every packet reaches the action of the rule,
// except the packets that carry a mark the rule is told to skip ("not
// fwmark X": the marked packets of a VPN client's own sockets). A positive
// fwmark, a uid range, an interface or a port narrows the rule to some
// traffic, and the rest passes it by.
func (r OSRule) matchesAll() bool {
	if r.Src.IsValid() || r.Dest.IsValid() || r.OtherSel {
		return false
	}
	return r.Fwmark == r.Inv // no selector at all, or "not fwmark"
}

// RuleTableMain is the number of the main routing table.
const RuleTableMain = 254

// rkey identifies a route by what makes it ours or somebody else's.
type rkey struct {
	dest   netip.Prefix
	iface  string
	gw     netip.Addr
	metric int
	table  int // 0: main
}

func addrOrZero(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil || a.IsUnspecified() {
		return netip.Addr{}
	}
	return a
}

// keyOf is the identity of a journal or planned route.
func keyOf(r config.Route) rkey {
	p, _ := netip.ParsePrefix(r.Dest)
	return rkey{dest: p.Masked(), iface: r.Iface, gw: addrOrZero(r.Gateway), metric: r.EffMetric(), table: r.Table}
}

func (o OSRoute) key() rkey {
	return rkey{dest: o.Dest.Masked(), iface: o.Iface, gw: o.Gateway, metric: o.Metric, table: o.Table}
}

// toRoute is the journal form of a route found in the table.
func (o OSRoute) toRoute() config.Route {
	r := config.Route{Dest: o.Dest.Masked().String(), Iface: o.Iface, Metric: o.Metric, Table: o.Table}
	if o.Gateway.IsValid() {
		r.Gateway = o.Gateway.String()
	}
	return r
}

// table is the routing table, indexed: the main one and, on Linux, ours.
type table struct {
	known  bool
	routes []OSRoute // main table only
	byKey  map[rkey]OSRoute
	all    []OSRoute // every table
}

// holdsOurs: routes of these tables are looked after (found, adopted, removed).
func holdsOurs(t int) bool { return t == 0 || config.IsOwnTable(t) }

func newTable(all []OSRoute) *table {
	t := &table{known: true, all: all, byKey: map[rkey]OSRoute{}}
	for _, r := range all {
		if !holdsOurs(r.Table) {
			continue
		}
		if r.Table == 0 {
			t.routes = append(t.routes, r)
		}
		t.byKey[r.key()] = r
	}
	return t
}

// has reports whether the route is in the table as ours: same destination,
// adapter, next hop, metric and routing table and, where the OS tags routes,
// our tag. Journal routes written before the tag existed are accepted without it.
func (t *table) has(r config.Route) bool {
	if t == nil || !t.known {
		return false
	}
	o, ok := t.byKey[keyOf(r)]
	return ok && !o.NotOurs && (!routesTagged || r.Legacy() || o.Ours)
}

// ours lists the routes that carry our tag, in the main table and in ours. A
// route whose metric is not the one we use is never listed: the tag alone does
// not make it ours (a route that was copied, or tagged by hand, with metric 0
// would otherwise be removed as if it were an old route without a metric).
func (t *table) ours() []OSRoute {
	if !routesTagged {
		return nil
	}
	return t.taggedOurs()
}

// taggedOurs is ours without asking whether the OS tags routes at all.
func (t *table) taggedOurs() []OSRoute {
	if t == nil || !t.known {
		return nil
	}
	var out []OSRoute
	for _, r := range t.all {
		if holdsOurs(r.Table) && r.Ours && r.Metric == ownMetric {
			out = append(out, r)
		}
	}
	return out
}

// ownTableFree reports whether nobody else uses the routing table n: no route
// without our tag and no rule that is not ours looks into it.
func ownTableFree(t *table, rs *ruleSet, n int) bool {
	if t != nil && t.known {
		for _, r := range t.all {
			if r.Table == n && !r.Ours {
				return false
			}
		}
	}
	if rs != nil && rs.known {
		for _, r := range rs.all {
			if r.ToTable && r.Table == n && !r.Ours {
				return false
			}
		}
	}
	return true
}

// pickOwnTable chooses the table for our routes: the first free one of
// 247-250 (config.OwnTable is taken by somebody else more often than one would
// think). ok is false when all are in use.
func pickOwnTable(t *table, rs *ruleSet) (n int, ok bool) {
	for n = config.OwnTable; n <= config.OwnTableLast; n++ {
		if ownTableFree(t, rs, n) {
			return n, true
		}
	}
	return config.OwnTable, false
}

// ruleKey identifies a rule we created.
type ruleKey struct {
	table int
	pref  int
}

func ruleKeyOf(r config.Rule) ruleKey { return ruleKey{r.Table, r.Pref} }

// isOurShape reports whether o has the shape of the rule we create: "lookup
// <our table>" with our tag and no selector.
func (o OSRule) isOurShape() (ruleKey, bool) {
	if !o.Ours || !o.ToTable || !config.IsOwnTable(o.Table) || o.hasSel() || o.Suppress >= 0 {
		return ruleKey{}, false
	}
	return ruleKey{o.Table, o.Pref}, true
}

// ruleSet is the policy rules of the OS, indexed by the key of our rules.
type ruleSet struct {
	known bool
	all   []OSRule
	ours  map[ruleKey]OSRule
}

func newRuleSet(all []OSRule) *ruleSet {
	s := &ruleSet{known: true, all: all, ours: map[ruleKey]OSRule{}}
	for _, r := range all {
		if k, ok := r.isOurShape(); ok {
			s.ours[k] = r
		}
	}
	return s
}

func (s *ruleSet) has(r config.Rule) bool {
	if s == nil || !s.known {
		return false
	}
	_, ok := s.ours[ruleKeyOf(r)]
	return ok
}

// gatewayFrom picks the physical uplink among the default routes: the one
// with the lowest total metric whose adapter is not a VPN or virtual one.
func gatewayFrom(rs []OSRoute) (Gateway, bool) {
	var defs []OSRoute
	for _, r := range rs {
		if r.Table == 0 && r.Dest.Addr().Is4() && r.Dest.Bits() == 0 && r.Gateway.IsValid() && r.Iface != "" {
			defs = append(defs, r)
		}
	}
	sort.SliceStable(defs, func(i, j int) bool { return defs[i].Metric+defs[i].IfMetric < defs[j].Metric+defs[j].IfMetric })
	for _, r := range defs {
		if netif.Classify(r.Iface) == netif.KindPhysical {
			return Gateway{Iface: r.Iface, Router: r.Gateway.String()}, true
		}
	}
	return Gateway{}, false
}
