package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// The baseline: what the system looked like before vpnsplit changed anything
// (config.Snapshot, taken by Acquire). The end of a session removes what the
// journal lists and then compares the system with the baseline: whatever is new
// and ours (journal, our mark, a route of an old version that a plan of ours
// covers) is removed, the rest is only reported. A VPN client's route is never
// removed, however it came to be: that would break its tunnel.

// winOwnMetric is ownMetric of Windows and linOwnMetric that of Linux; the
// routes of those builds carry them.
const (
	winOwnMetric = 3
	linOwnMetric = 1
)

// The rule that rules all the others: a comparison with the snapshot never
// removes what may be a VPN client's or the user's. What is left is reported.
// A route is removed only when
//   - the journal lists it (this run's, one removed earlier in this run, or the
//     journal of an old version that this run picked up), or
//   - it carries the mark of the Linux build (protocol 247 in the main table or
//     in one of ours, with our metric), or
//   - on Windows, where no field tells a route of ours (metric 3 + NETMGMT +
//     Manual is only a candidate), it is exactly a route of this session's plan
//     and was not found in place at apply;
// and, unless the journal lists it, it is neither a route on an adapter of a
// recognized VPN client nor a prefix of /1 or shorter. A default route never goes.

// OSResolver is one per-domain DNS entry of the OS (Windows: an NRPT rule,
// macOS: a file of /etc/resolver).
type OSResolver struct {
	ID     string
	Detail string
	Ours   bool
}

// resolverLister is a Backend that can list the per-domain DNS entries.
type resolverLister interface {
	ListResolvers() ([]OSResolver, error)
}

// snapshotStore is a Store that keeps the snapshot as well.
type snapshotStore interface {
	LoadSnapshot() (*config.Snapshot, error)
	SaveSnapshot(*config.Snapshot) error
	RemoveSnapshot() error
	LoadPlanNotes(taken string) (*config.PlanNotes, error)
	SavePlanNotes(*config.PlanNotes) error
}

func (fileStore) LoadSnapshot() (*config.Snapshot, error) { return config.LoadSnapshot() }
func (fileStore) SaveSnapshot(s *config.Snapshot) error   { return config.SaveSnapshot(s) }
func (fileStore) RemoveSnapshot() error                   { return config.RemoveSnapshot() }
func (fileStore) LoadPlanNotes(taken string) (*config.PlanNotes, error) {
	return config.LoadPlanNotes(taken)
}
func (fileStore) SavePlanNotes(n *config.PlanNotes) error { return config.SavePlanNotes(n) }

// osState is what the OS holds right now (or held, in a snapshot).
type osState struct {
	routes         []OSRoute
	routesKnown    bool
	routesErr      error
	rules          []OSRule
	rulesKnown     bool
	resolvers      []OSResolver
	resolversKnown bool
}

// within runs f and gives up waiting for it when ctx ends (the OS calls cannot be interrupted).
func within[T any](ctx context.Context, f func() (T, error)) (T, error) {
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- res{err: fmt.Errorf("internal error: %v", r)}
			}
		}()
		v, err := f()
		ch <- res{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var z T
		return z, ctx.Err()
	}
}

// readOS reads the tables of the OS. What cannot be read is marked unknown.
func (m *Manager) readOS(ctx context.Context, withDNS bool) osState {
	var s osState
	if routes, err := within(ctx, m.b.Routes); err == nil {
		// only the tables vpnsplit works in: the main one and its own (the rest
		// are the clients' policy routing, not part of the comparison)
		kept := routes[:0:0]
		for _, r := range routes {
			if holdsOurs(r.Table) {
				kept = append(kept, r)
			}
		}
		s.routes, s.routesKnown = kept, true
	} else {
		s.routesErr = err
	}
	if rules, err := within(ctx, m.b.Rules); err == nil {
		s.rules, s.rulesKnown = rules, true
	}
	if l, ok := m.b.(resolverLister); ok && withDNS {
		if res, err := within(ctx, l.ListResolvers); err == nil {
			s.resolvers, s.resolversKnown = res, true
		}
	}
	return s
}

// ---- the keys by which two states are compared

// routeID is how a route is told from another one in a comparison: the adapter
// by NAME (a reconnected adapter has another index and LUID but is the same
// adapter), the rest as the OS keys it, plus the metric.
type routeID struct {
	table  int
	dest   netip.Prefix
	gw     netip.Addr
	iface  string
	metric int
}

func idOf(o OSRoute) routeID {
	name := o.Iface
	if name == "" {
		name = fmt.Sprintf("#%d", o.IfIndex)
	}
	return routeID{table: o.Table, dest: o.Dest.Masked(), gw: o.Gateway, iface: name, metric: o.Metric}
}

func snapRouteOf(o OSRoute) config.SnapRoute {
	r := config.SnapRoute{Dest: o.Dest.Masked().String(), Iface: o.Iface, IfIndex: o.IfIndex, LUID: o.LUID,
		Metric: o.Metric, Table: o.Table, Proto: o.Proto, Origin: o.Origin}
	if o.Gateway.IsValid() {
		r.Gateway = o.Gateway.String()
	}
	return r
}

func osRouteOf(r config.SnapRoute) (OSRoute, bool) {
	p, err := netip.ParsePrefix(r.Dest)
	if err != nil {
		return OSRoute{}, false
	}
	return OSRoute{Dest: p, Iface: r.Iface, IfIndex: r.IfIndex, LUID: r.LUID, Gateway: addrOrZero(r.Gateway),
		Metric: r.Metric, Table: r.Table, Proto: r.Proto, Origin: r.Origin}, true
}

type ruleID struct {
	pref, table, suppress    int
	src, dest                netip.Prefix
	toTable, fwmark, inv, ot bool
}

func ruleIDOf(r OSRule) ruleID {
	return ruleID{pref: r.Pref, table: r.Table, suppress: r.Suppress, src: r.Src, dest: r.Dest,
		toTable: r.ToTable, fwmark: r.Fwmark, inv: r.Inv, ot: r.OtherSel}
}

func snapRuleOf(r OSRule) config.SnapRule {
	s := config.SnapRule{Pref: r.Pref, Table: r.Table, Suppress: r.Suppress, ToTable: r.ToTable, Fwmark: r.Fwmark, Inv: r.Inv, Other: r.OtherSel}
	if r.Src.IsValid() {
		s.Src = r.Src.String()
	}
	if r.Dest.IsValid() {
		s.Dest = r.Dest.String()
	}
	return s
}

func osRuleOf(s config.SnapRule) OSRule {
	r := OSRule{Pref: s.Pref, Table: s.Table, Suppress: s.Suppress, ToTable: s.ToTable, Fwmark: s.Fwmark, Inv: s.Inv, OtherSel: s.Other}
	r.Src, _ = netip.ParsePrefix(s.Src)
	r.Dest, _ = netip.ParsePrefix(s.Dest)
	return r
}

// ---- whose a route is

type markKind int

const (
	markNone   markKind = iota // nothing says it is ours
	markOurs                   // carries the mark we create routes with
	markLegacy                 // has the shape of a route of an older version (metric 1, no mark)
)

// routeMark tells what a route's own fields say about who made it. goos selects
// the rules of the OS; the function is the same on every build so that it can be
// tested everywhere.
//
//   - windows: protocol NETMGMT + origin Manual (what CreateIpForwardEntry2 and
//     route.exe give) with metric 3 is a candidate (a client or the user can
//     make the very same route: see addExtraRoute); with metric 1 it has the
//     shape of what the route.exe of the old versions created;
//   - linux: rtm_protocol 247 in the main table or one of ours, with our
//     metric, is ours; metric 1 with no protocol of a client (boot, or 0) in the
//     main table is the shape of what `ip route add` of the old versions made;
//   - darwin: the table is not read.
func routeMark(goos string, o OSRoute) markKind {
	switch goos {
	case "windows":
		if o.Proto == mibNetMgmt && o.Origin == 0 {
			switch o.Metric {
			case winOwnMetric:
				return markOurs
			case config.LegacyMetric:
				return markLegacy
			}
		}
	case "linux":
		if (o.Ours || o.Proto == routeProto) && holdsOurs(o.Table) && o.Metric == linOwnMetric {
			return markOurs
		}
		if o.Table == 0 && o.Metric == config.LegacyMetric && (o.Proto == 3 || o.Proto == 0) {
			return markLegacy
		}
	}
	return markNone
}

// mibNetMgmt is MIB_IPPROTO_NETMGMT, the protocol of `route add` and our routes.
const mibNetMgmt = 3

// ---- the comparison

// BaseDiff is one difference from the baseline.
type BaseDiff struct {
	Kind string // "route", "rule", "dns"
	Text string
	Who  string // the adapter and the client behind it, if known
	Why  string // for a route that is ours but could not be removed: the reason
	Ours bool   // it is ours (it could not be removed, or it was not tried)
}

// Baseline is the result of a comparison with the snapshot.
type Baseline struct {
	Checked bool   // the system was compared with a snapshot
	Note    string // when not: why (English)
	Approx  bool   // the snapshot was taken while the journal listed entries
	Removed []BaseDiff
	Extra   []BaseDiff // there now, not in the snapshot
	Missing []BaseDiff // in the snapshot, not there now
	Cut     bool       // time ran out: the comparison is not complete
	Live    bool       // a look at a running session (nothing was removed): what is ours is simply applied
	// ReportOnly: the snapshot could not be trusted enough to remove anything by
	// it (Why says why, in English): the differences are only listed.
	ReportOnly bool
	Why        string
}

// Differences is the number of differences left.
func (b Baseline) Differences() int { return len(b.Extra) + len(b.Missing) }

// Restored reports whether the system is back to the baseline.
func (b Baseline) Restored() bool {
	return b.Checked && !b.Cut && !b.ReportOnly && b.Differences() == 0
}

// delItem is something ours that is not in the baseline and must go.
type delItem struct {
	diff   BaseDiff
	route  config.Route
	rule   config.Rule
	id     string
	reason string
}

type compareIn struct {
	goos    string
	snap    *config.Snapshot
	cur     osState
	journal []config.Route // what the journal lists (and listed before it was emptied)
	jRules  []config.Rule
	jRes    []string
	hint    map[string]bool // routes (destination|adapter|next hop|table) of the plans of vpnsplit
	kept    map[string]bool // routes that were found in place and left as somebody else's
	// provider names the VPN client behind an adapter ("" if none is known to be
	// there); nil: not asked. It may start tools, so it is called only when a
	// route is about to be removed that the journal does not list.
	provider func(iface string) string
}

type compareOut struct {
	del            []delItem
	extra, missing []BaseDiff
	unknown        string // why the comparison cannot be made
}

// printable makes text that came from the OS (adapter names, DNS rules) safe to
// put on a terminal or into a log: control characters, which could move the
// cursor or recolor the screen, become '?', and a long text is cut.
func printable(s string) string {
	const max = 256
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == utf8.RuneError {
			return '?'
		}
		return r
	}, s)
}

func routeText(o OSRoute) string {
	var b strings.Builder
	b.WriteString(o.Dest.Masked().String())
	if o.Gateway.IsValid() {
		b.WriteString(" via " + o.Gateway.String())
	}
	if o.Iface != "" {
		b.WriteString(" dev " + printable(o.Iface))
	} else {
		fmt.Fprintf(&b, " if#%d", o.IfIndex)
	}
	fmt.Fprintf(&b, " metric %d", o.Metric)
	if o.Table != 0 {
		fmt.Fprintf(&b, " table %d", o.Table)
	}
	if o.Proto != 0 || o.Origin != 0 {
		fmt.Fprintf(&b, " proto %d", o.Proto)
		if o.Origin != 0 {
			fmt.Fprintf(&b, " origin %d", o.Origin)
		}
	}
	return b.String()
}

func ruleText(r OSRule) string {
	s := fmt.Sprintf("pref %d", r.Pref)
	if r.Src.IsValid() {
		s += " from " + r.Src.String()
	}
	if r.Dest.IsValid() {
		s += " to " + r.Dest.String()
	}
	if r.Fwmark {
		s += " fwmark"
	}
	if r.ToTable {
		s += fmt.Sprintf(" lookup %d", r.Table)
	}
	return s
}

// who names the adapter of an extra entry and the client behind it.
func (in compareIn) who(iface string) string {
	if iface == "" {
		return ""
	}
	return "adapter " + printable(iface)
}

// compare works out what is new, what is gone and which of the new entries are
// ours. It changes nothing.
func compare(in compareIn) compareOut {
	var out compareOut
	if in.snap == nil {
		out.unknown = "no snapshot"
		return out
	}
	jid := map[routeID]config.Route{}
	for _, r := range in.journal {
		p, err := netip.ParsePrefix(r.Dest)
		if err != nil {
			continue
		}
		jid[routeID{table: r.Table, dest: p.Masked(), gw: addrOrZero(r.Gateway), iface: r.Iface, metric: r.EffMetric()}] = r
	}

	if in.snap.RoutesKnown && in.cur.routesKnown {
		have := map[routeID]int{}
		for _, sr := range in.snap.Routes {
			if o, ok := osRouteOf(sr); ok {
				have[idOf(o)]++
			}
		}
		for _, o := range in.cur.routes {
			id := idOf(o)
			if have[id] > 0 {
				have[id]--
				continue
			}
			out.addExtraRoute(in, o, jid)
		}
		for _, sr := range in.snap.Routes {
			o, ok := osRouteOf(sr)
			if !ok {
				continue
			}
			id := idOf(o)
			if have[id] > 0 {
				have[id]--
				out.missing = append(out.missing, BaseDiff{Kind: "route", Text: routeText(o), Who: in.who(o.Iface)})
			}
		}
	}

	if in.snap.RulesKnown && in.cur.rulesKnown {
		have := map[ruleID]int{}
		for _, sr := range in.snap.Rules {
			have[ruleIDOf(osRuleOf(sr))]++
		}
		for _, o := range in.cur.rules {
			id := ruleIDOf(o)
			if have[id] > 0 {
				have[id]--
				continue
			}
			d := BaseDiff{Kind: "rule", Text: ruleText(o)}
			if k, ok := o.isOurShape(); ok {
				d.Ours = true
				out.del = append(out.del, delItem{diff: d, rule: config.Rule{Table: k.table, Pref: k.pref}})
				continue
			}
			out.extra = append(out.extra, d)
		}
		for _, sr := range in.snap.Rules {
			r := osRuleOf(sr)
			id := ruleIDOf(r)
			if have[id] > 0 {
				have[id]--
				out.missing = append(out.missing, BaseDiff{Kind: "rule", Text: ruleText(r)})
			}
		}
	}

	if in.snap.ResolversKnown && in.cur.resolversKnown {
		have := map[string]int{}
		for _, sr := range in.snap.Resolvers {
			have[sr.ID+"\x00"+sr.Detail]++
		}
		inJ := map[string]bool{}
		for _, id := range in.jRes {
			inJ[id] = true
		}
		for _, o := range in.cur.resolvers {
			k := o.ID + "\x00" + o.Detail
			if have[k] > 0 {
				have[k]--
				continue
			}
			d := BaseDiff{Kind: "dns", Text: printable(strings.TrimSpace(o.ID + " " + o.Detail))}
			// Windows: only a rule with our comment (the journal's word alone would
			// let a rule of somebody else with the same namespace go)
			if o.Ours || (in.goos != "windows" && inJ[o.ID]) {
				d.Ours = true
				out.del = append(out.del, delItem{diff: d, id: o.ID})
				continue
			}
			out.extra = append(out.extra, d)
		}
		for _, sr := range in.snap.Resolvers {
			k := sr.ID + "\x00" + sr.Detail
			if have[k] > 0 {
				have[k]--
				out.missing = append(out.missing, BaseDiff{Kind: "dns", Text: printable(strings.TrimSpace(sr.ID + " " + sr.Detail))})
			}
		}
	}
	return out
}

// addExtraRoute decides whether a route that is not in the baseline is ours.
// It is when
//   - (a) the journal lists it and it carries our mark (or, for an entry of an
//     old version, has the shape of one),
//   - (b) Linux: it carries our protocol tag in the main table or one of ours,
//     with our metric; Windows: it carries our mark (metric 3, NETMGMT, Manual)
//     and is exactly a route of this session's plan (destination, adapter, next
//     hop and table) that was not found in place and left alone at apply. The
//     mark alone is only a candidate on Windows: nothing stops a client or the
//     user from making the same route.
//
// A route of the old versions' shape (metric 1 with no mark) is removed only if
// the journal of an old version, picked up in this run, lists it: Check Point
// puts thousands of routes of that very shape into the table.
//
// Whatever the reason, a route the journal does not list stays if its adapter
// belongs to a recognized VPN client or its prefix is /1 or shorter (the halves
// of a full tunnel); a default route always stays.
func (out *compareOut) addExtraRoute(in compareIn, o OSRoute, jid map[routeID]config.Route) {
	d := BaseDiff{Kind: "route", Text: routeText(o), Who: in.who(o.Iface)}
	mark := routeMark(in.goos, o)
	jr, listed := jid[idOf(o)]
	if o.Dest.Bits() == 0 { // a default route is never ours to remove
		out.extra = append(out.extra, d)
		return
	}
	key := osKey(o)
	var reason string
	sure := true // the route is ours beyond doubt, whether or not it can be removed
	switch {
	case listed && mark == markOurs:
		reason = "in the journal"
	case listed && mark == markLegacy && jr.Legacy():
		reason = "in the journal (old version)"
	case listed:
		// the journal says it is ours, but the mark is not: it is somebody's route to
		// the same place. It stays, and the report says why.
		d.Why = "the journal lists a route there, but its protocol/origin/metric are not ours"
		out.extra = append(out.extra, d)
		return
	case mark == markOurs && in.goos != "windows":
		reason = "carries the mark of vpnsplit"
	case mark == markOurs && in.hint[key] && !in.kept[key]:
		reason = "carries our mark and is the very route of our plan"
		sure = false
	default:
		out.extra = append(out.extra, d)
		return
	}
	if !listed {
		why := ""
		if o.Dest.Bits() <= 1 {
			why = "not in the journal and as wide as the halves of a full tunnel: not removed"
		} else if in.provider != nil && o.Iface != "" {
			if p := in.provider(o.Iface); p != "" {
				why = "not in the journal, and the adapter belongs to the VPN client " + p + ": not removed"
			}
		}
		if why != "" {
			d.Why, d.Ours = why, sure
			out.extra = append(out.extra, d)
			return
		}
	}
	if o.Iface == "" {
		d.Why = "ours (" + reason + "), but the adapter has no name: not removed"
		d.Ours = true
		out.extra = append(out.extra, d)
		return
	}
	r := config.Route{Dest: o.Dest.Masked().String(), Iface: o.Iface, Metric: o.Metric, Table: o.Table}
	if o.Gateway.IsValid() {
		r.Gateway = o.Gateway.String()
	}
	if mark == markLegacy {
		r.Metric = 0 // the form of the journal of old versions: matched on metric 1 and no mark
	}
	d.Ours = true
	out.del = append(out.del, delItem{diff: d, route: r, reason: reason})
}

// ---- sweep: compare, remove what is ours, compare again

// sweepOpts says what a sweep may do.
type sweepOpts struct {
	dns bool   // read the per-domain DNS entries too (slow on Windows: PowerShell)
	fix bool   // remove what is ours
	why string // fix is off for a reason that the report must give (not a plain look at a running session)
}

// hintSet is the routes of the plans of vpnsplit since the snapshot was taken,
// and the ones found in place and left alone.
func (m *Manager) hintSet() (hint, kept map[string]bool) {
	hint, kept = map[string]bool{}, map[string]bool{}
	m.mu.Lock()
	for d := range m.planned {
		hint[d] = true
	}
	for d := range m.kept {
		kept[d] = true
	}
	m.mu.Unlock()
	return hint, kept
}

// osKey and routeKey name a route by destination, adapter, next hop and
// table, the identity the OS gives it (the metric is not part of it on Windows).
func osKey(o OSRoute) string {
	gw := ""
	if o.Gateway.IsValid() {
		gw = o.Gateway.String()
	}
	return o.Dest.Masked().String() + "|" + o.Iface + "|" + gw + "|" + strconv.Itoa(o.Table)
}

func routeKey(r config.Route) string {
	p, err := netip.ParsePrefix(r.Dest)
	if err != nil {
		return ""
	}
	gw := ""
	if a := addrOrZero(r.Gateway); a.IsValid() {
		gw = a.String()
	}
	return p.Masked().String() + "|" + r.Iface + "|" + gw + "|" + strconv.Itoa(r.Table)
}

// providers is the lookup of the VPN client behind each adapter: made once, on
// first use (it may start tools), within ctx.
type providers struct {
	m     *Manager
	ctx   context.Context
	once  sync.Once
	names map[string]string
}

func (p *providers) get() map[string]string {
	p.once.Do(func() {
		p.names, _ = within(p.ctx, func() (map[string]string, error) { return p.m.providerOf(), nil })
	})
	return p.names
}

// of names the client behind an adapter, "" if there is none. When the lookup
// cannot be made the answer is a placeholder that keeps routes in place: not
// knowing is no reason to remove.
func (p *providers) of(iface string) string {
	names := p.get()
	if names == nil {
		return "(unknown: the list of adapters could not be read)"
	}
	return names[iface]
}

// sweep compares the system with snap and, with o.fix, removes the new
// entries that are ours. The journal is read for what it lists now; what was
// removed from it earlier in this run is remembered in m.jhint.
func (m *Manager) sweep(ctx context.Context, snap *config.Snapshot, st *config.State, o sweepOpts) Baseline {
	why := o.why
	if snap.ReportOnly {
		o.fix = false
		if why == "" {
			why = snap.Why
			if why == "" {
				why = "the snapshot may only be reported"
			}
		}
	}
	b := Baseline{Approx: snap.Approx, Live: !o.fix && why == "", ReportOnly: why != "", Why: why}
	if st == nil {
		st = &config.State{}
	}
	m.mu.Lock()
	journal := append(append([]config.Route(nil), m.jhint...), st.Routes...)
	jres := append(append([]string(nil), m.jhintRes...), st.Resolvers...)
	m.mu.Unlock()
	in := compareIn{goos: m.goos, snap: snap, journal: journal, jRules: st.Rules, jRes: jres}
	in.hint, in.kept = m.hintSet()
	var prov *providers
	if m.providerOf != nil {
		prov = &providers{m: m, ctx: ctx}
		in.provider = prov.of
	}
	cur := m.readOS(ctx, o.dns)
	if !cur.routesKnown {
		b.Note = noTableNote
		if cur.routesErr != nil && !errors.Is(cur.routesErr, ErrNoTable) {
			b.Note += ": " + cur.routesErr.Error()
		}
		if ctx.Err() != nil {
			b.Cut = true
		}
		return b
	}
	if o.dns && !cur.resolversKnown && snap.ResolversKnown && ctx.Err() != nil {
		b.Cut = true
		return b
	}
	in.cur = cur
	res := compare(in)
	failed := map[string]string{}
	done := map[string]bool{}
	recompared := true
	if o.fix && len(res.del) > 0 && ctx.Err() == nil {
		errs := runAll(ctx, res.del, removeWorkers, func(it delItem) error {
			switch it.diff.Kind {
			case "route":
				if err := config.ValidateRoute(it.route); err != nil {
					return err
				}
				return ignoreNotOurs(m.b.DelRoute(it.route))
			case "rule":
				return m.b.DelRule(it.rule)
			}
			if !config.ValidResolverEntry(it.id) {
				return fmt.Errorf("invalid DNS entry %q", it.id)
			}
			return m.b.DelResolver(it.id)
		})
		for i, it := range res.del {
			k := it.diff.Kind + " " + it.diff.Text
			if errs[i] != nil {
				failed[k] = "not removed: " + errs[i].Error()
				continue
			}
			done[k] = true
			b.Removed = append(b.Removed, it.diff)
		}
		recompared = false
		if ctx.Err() == nil {
			in.cur = m.readOS(ctx, o.dns)
			if in.cur.routesKnown {
				res = compare(in)
				recompared = true
			} else {
				b.Cut = true
			}
		} else {
			b.Cut = true
		}
	}
	b.Checked = true
	b.Extra = append(b.Extra, res.extra...)
	for _, it := range res.del { // ours and still there: not fix mode, or the removal failed
		d := it.diff
		k := d.Kind + " " + d.Text
		if !recompared && done[k] {
			continue // removed; the table was not read again, so it is not "left"
		}
		if w := failed[k]; w != "" {
			d.Why = w
		} else if d.Why == "" && o.fix {
			d.Why = "not removed"
		}
		b.Extra = append(b.Extra, d)
	}
	b.Missing = res.missing
	if ctx.Err() != nil {
		b.Cut = true
	}
	m.attribute(ctx, prov, &b)
	sortDiffs(b.Extra)
	sortDiffs(b.Missing)
	return b
}

func sortDiffs(d []BaseDiff) {
	sort.SliceStable(d, func(i, j int) bool { return d[i].Kind+d[i].Text < d[j].Kind+d[j].Text })
}

// attribute names the client behind the adapter of each extra entry: the lookup
// may start tools, so it is done once, only if there is something to name, and
// not past the deadline.
func (m *Manager) attribute(ctx context.Context, prov *providers, b *Baseline) {
	need := false
	for _, d := range b.Extra {
		if d.Kind == "route" && d.Who != "" {
			need = true
		}
	}
	if !need || prov == nil || ctx.Err() != nil {
		return
	}
	names := prov.get()
	if names == nil {
		return
	}
	for i, d := range b.Extra {
		if d.Kind != "route" || !strings.HasPrefix(d.Who, "adapter ") {
			continue
		}
		name := strings.TrimPrefix(d.Who, "adapter ")
		if p := names[name]; p != "" {
			b.Extra[i].Who = fmt.Sprintf("adapter %s / client %s", name, p)
		}
	}
	for i, d := range b.Missing {
		if d.Kind != "route" || !strings.HasPrefix(d.Who, "adapter ") {
			continue
		}
		name := strings.TrimPrefix(d.Who, "adapter ")
		if p := names[name]; p != "" {
			b.Missing[i].Who = fmt.Sprintf("adapter %s / client %s", name, p)
		}
	}
}

// ---- the text

const noTableNote = "the routing table cannot be read"

// maxShown is how many differences a one-line summary names.
const maxShown = 5

func word(ru bool, en, rus string) string {
	if ru {
		return rus
	}
	return en
}

// Describe is the outcome in a few lines for the end of a session.
func (b Baseline) Describe(ru bool) string {
	switch {
	case !b.Checked && b.Cut:
		return word(ru, "the comparison with the state before the start did not finish (out of time); the next start finishes it",
			"сверка с состоянием до запуска не закончилась (не хватило времени); следующий запуск доделает")
	case !b.Checked:
		if b.Note == "" || b.Note == "no snapshot" || b.Note == noTableNote {
			return "" // nothing to say: this OS does not offer the table, or there is no baseline
		}
		return word(ru, "not compared with the state before the start: ", "не сверено с состоянием до запуска: ") + b.Note
	case b.Restored():
		return word(ru, "Restored to the state before the start", "Восстановлено как до запуска")
	case b.ReportOnly && b.Differences() == 0:
		return word(ru, "No differences found, but nothing could be removed or verified: "+b.Why,
			"Отличий не найдено, но проверка неполная, удалять было нечего или нельзя: "+whyRu(b.Why))
	}
	var ours, foreign, gone []BaseDiff
	for _, d := range b.Extra {
		if d.Ours {
			ours = append(ours, d)
		} else {
			foreign = append(foreign, d)
		}
	}
	gone = b.Missing
	list := func(ds []BaseDiff) string {
		var names []string
		for _, d := range ds {
			if len(names) == maxShown {
				names = append(names, "...")
				break
			}
			s := d.Text
			if d.Who != "" {
				s += " (" + d.Who + ")"
			}
			if d.Why != "" {
				s += " [" + d.Why + "]"
			}
			names = append(names, s)
		}
		return " [" + strings.Join(names, "; ") + "]"
	}
	head := word(ru, "Differences left", "Осталось отличий")
	if b.Live {
		head = word(ru, "Differences now", "Сейчас отличий")
	}
	s := fmt.Sprintf("%s: %d", head, b.Differences())
	if b.ReportOnly {
		s += word(ru, " (report only, nothing was removed: "+b.Why+")", " (только отчёт, ничего не удалялось: "+whyRu(b.Why)+")")
	}
	if len(foreign) > 0 {
		s += word(ru, fmt.Sprintf("; not set by vpnsplit: %d", len(foreign)), fmt.Sprintf("; поставлено не vpnsplit: %d", len(foreign))) + list(foreign)
	}
	if len(ours) > 0 {
		switch {
		case b.ReportOnly:
			s += word(ru, fmt.Sprintf("; ours, left as they are: %d", len(ours)), fmt.Sprintf("; наши, оставлены как есть: %d", len(ours))) + list(ours)
		case b.Live:
			s += word(ru, fmt.Sprintf("; applied by vpnsplit (removed when the session ends): %d", len(ours)),
				fmt.Sprintf("; применено vpnsplit (снимется при выходе): %d", len(ours)))
		default:
			s += word(ru, fmt.Sprintf("; OF OURS NOT REMOVED: %d", len(ours)), fmt.Sprintf("; НАШИХ НЕ УБРАНО: %d", len(ours))) + list(ours)
		}
	}
	if len(gone) > 0 {
		s += word(ru, fmt.Sprintf("; gone since the start (usually a client or adapter went away): %d", len(gone)),
			fmt.Sprintf("; пропало с момента запуска (обычно исчез клиент или адаптер): %d", len(gone))) + list(gone)
	}
	if b.Cut {
		s += word(ru, " (the comparison ran out of time; the next start finishes it)", " (сверка не уложилась во время; следующий запуск доделает)")
	}
	return s
}

// Lines is the full list of differences, one per line, for `vpnsplit diff` and the menu.
func (b Baseline) Lines(ru bool) []string {
	var out []string
	if !b.Checked {
		out = append(out, word(ru, "no comparison: ", "сверки нет: ")+b.noteText(ru))
		return out
	}
	if b.ReportOnly {
		out = append(out, word(ru, "note: report only, nothing is removed: "+b.Why, "замечание: только отчёт, ничего не удаляется: "+whyRu(b.Why)))
	}
	if b.Approx {
		out = append(out, word(ru, "note: the snapshot was taken while vpnsplit already had routes applied; they are not in it",
			"замечание: снимок снят, когда у vpnsplit уже были применённые маршруты; в нём их нет"))
	}
	add := func(sign string, d BaseDiff) {
		s := sign + " " + d.Kind + " " + d.Text
		switch {
		case d.Ours && d.Why != "":
			s += word(ru, "  <- OURS, "+d.Why, "  <- НАШЕ, "+d.Why)
		case d.Ours:
			s += word(ru, "  <- ours", "  <- наше")
		case d.Who != "":
			s += word(ru, "  <- not set by vpnsplit: "+d.Who, "  <- поставлено не vpnsplit: "+d.Who)
		default:
			s += word(ru, "  <- not set by vpnsplit", "  <- поставлено не vpnsplit")
		}
		if !d.Ours && d.Why != "" {
			s += " [" + d.Why + "]"
		}
		out = append(out, s)
	}
	for _, d := range b.Extra {
		add("+", d)
	}
	for _, d := range b.Missing {
		d.Ours = false
		s := "- " + d.Kind + " " + d.Text + word(ru, "  <- was there before the start, gone now", "  <- было до запуска, сейчас нет")
		if d.Who != "" {
			s += " (" + d.Who + ")"
		}
		out = append(out, s)
	}
	if len(out) == 0 || (b.Approx && b.ReportOnly && len(out) == 2) || ((b.Approx || b.ReportOnly) && len(out) == 1) {
		out = append(out, word(ru, "no differences from the state before the start", "отличий от состояния до запуска нет"))
	}
	if b.Cut {
		out = append(out, word(ru, "the comparison is not complete (time ran out)", "сверка неполная (не хватило времени)"))
	}
	return out
}

// whyRu translates the reasons a comparison may only report.
func whyRu(w string) string {
	switch {
	case strings.HasPrefix(w, reasonUnproven):
		return "снимок нельзя привязать к этой загрузке компьютера"
	case strings.HasPrefix(w, reasonTooLarge):
		return "таблица маршрутов слишком велика для снимка"
	case strings.HasPrefix(w, "the snapshot may only be reported"):
		return "снимок можно только показать"
	}
	return w
}

// The reasons (English; whyRu has the Russian) a comparison may only report.
const (
	reasonUnproven = "the snapshot cannot be tied to this boot of the computer"
	reasonTooLarge = "the routing table is too large to keep"
)

func (b Baseline) noteText(ru bool) string {
	switch {
	case b.Note == "no snapshot":
		return word(ru, "there is no snapshot of the state before the start (it is taken when a session or apply starts)",
			"снимка состояния до запуска нет (он снимается при старте сессии или apply)")
	case strings.HasPrefix(b.Note, noTableNote):
		return word(ru, b.Note, "таблица маршрутов недоступна"+strings.TrimPrefix(b.Note, noTableNote))
	}
	return b.Note
}
