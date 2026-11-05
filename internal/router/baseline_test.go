package router

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// ---- pure comparison: the rules of each OS run on every host

func route(dest, iface string, idx, metric, proto, origin int) OSRoute {
	return OSRoute{Dest: netip.MustParsePrefix(dest), Iface: iface, IfIndex: idx, LUID: uint64(idx) << 24, Metric: metric, Proto: proto, Origin: origin}
}

func withGW(o OSRoute, gw string) OSRoute { o.Gateway = netip.MustParseAddr(gw); return o }

func inTable(t int, o OSRoute) OSRoute { o.Table = t; return o }

func snapOf(routes ...OSRoute) *config.Snapshot {
	s := &config.Snapshot{RoutesKnown: true, RulesKnown: true, ResolversKnown: true}
	for _, o := range routes {
		s.Routes = append(s.Routes, snapRouteOf(o))
	}
	return s
}

func cmp(goos string, snap *config.Snapshot, cur []OSRoute, journal []config.Route) compareOut {
	return cmpPlanned(goos, snap, cur, journal, OSRoute{}, false, false)
}

// cmpPlanned is cmp with the route `of` in a plan of ours (and, with kept, found in place and left alone).
func cmpPlanned(goos string, snap *config.Snapshot, cur []OSRoute, journal []config.Route, of OSRoute, planned, kept bool) compareOut {
	in := compareIn{goos: goos, snap: snap, journal: journal, hint: map[string]bool{}, kept: map[string]bool{},
		cur: osState{routes: cur, routesKnown: true, rulesKnown: true, resolversKnown: true}}
	if planned {
		in.hint[osKey(of)] = true
	}
	if kept {
		in.kept[osKey(of)] = true
	}
	return compare(in)
}

// The client's routes are in the snapshot; what comes on top is sorted by the
// marks. Windows: metric 3 + NETMGMT + Manual is ours, metric 1 with the same is
// what the route.exe of the old versions made.
func TestCompareWindowsOwnership(t *testing.T) {
	client := withGW(route("10.201.0.0/24", "wghome", 6, 261, 3, 0), "10.201.0.1")
	cases := []struct {
		name    string
		extra   OSRoute
		journal []config.Route
		planned bool // the same route (destination, adapter, next hop) is in a plan of ours
		kept    bool // ... and it was found in place at apply and left as somebody else's
		del     bool
		legacy  bool   // the removal is asked in the form of the old journal (metric 0)
		why     string // part of the reason it stays although the journal lists it
	}{
		{name: "our mark alone is only a candidate: anyone can make that route", extra: route("10.10.0.0/16", "wgcorp", 5, 3, 3, 0)},
		{name: "our mark and the very route of our plan", extra: route("10.10.0.0/16", "wgcorp", 5, 3, 3, 0), planned: true, del: true},
		{name: "our mark, in the plan, but found in place and left alone at apply: a client's", extra: route("10.10.0.0/16", "wgcorp", 5, 3, 3, 0), planned: true, kept: true},
		{name: "our mark and the journal lists it", extra: route("10.10.0.0/16", "wgcorp", 5, 3, 3, 0),
			journal: []config.Route{{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: "corp", Metric: 3}}, del: true},
		{name: "old version, destination in our plan: the plan is not enough", extra: route("10.10.0.0/16", "wgcorp", 5, 1, 3, 0), planned: true},
		{name: "old version, in our plan but found in place and left alone at apply: a client's", extra: route("10.10.0.0/16", "wgcorp", 5, 1, 3, 0), planned: true, kept: true},
		{name: "old version, not in any plan: may be the user's", extra: route("10.10.0.0/16", "wgcorp", 5, 1, 3, 0)},
		{name: "old version listed in the old journal", extra: route("10.10.0.0/16", "wgcorp", 5, 1, 3, 0),
			journal: []config.Route{{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: "corp"}}, del: true, legacy: true},
		{name: "journal lists it but the metric is 3 and the protocol is RIP-ish", extra: route("10.10.0.0/16", "wgcorp", 5, 3, 8, 0),
			journal: []config.Route{{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: "corp", Metric: 3}}, why: "not ours"},
		{name: "journal lists it but the origin is DHCP", extra: route("10.10.0.0/16", "wgcorp", 5, 3, 3, 2),
			journal: []config.Route{{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: "corp", Metric: 3}}, why: "not ours"},
		{name: "a VPN client's route", extra: withGW(route("172.16.0.0/12", "wgcorp", 5, 25, 3, 0), "10.200.0.1")},
		{name: "metric 3 but another origin", extra: route("10.10.0.0/16", "wgcorp", 5, 3, 3, 2)},
		{name: "never a default route", extra: withGW(route("0.0.0.0/0", "wgcorp", 5, 3, 3, 0), "10.200.0.1"), planned: true},
		{name: "unnamed adapter cannot be removed", extra: route("10.10.0.0/16", "", 77, 3, 3, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := cmpPlanned("windows", snapOf(client), []OSRoute{client, c.extra}, c.journal, c.extra, c.planned, c.kept)
			if c.del {
				if len(out.del) != 1 || len(out.extra) != 0 {
					t.Fatalf("want one removal: %+v", out)
				}
				r := out.del[0].route
				if r.Dest != c.extra.Dest.String() || r.Iface != c.extra.Iface || (c.legacy) != r.Legacy() {
					t.Errorf("removal %+v", r)
				}
				if c.legacy && r.EffMetric() != 1 {
					t.Errorf("an old route is matched on metric 1: %+v", r)
				}
				return
			}
			if len(out.del) != 0 || len(out.extra) != 1 {
				t.Fatalf("want one difference, nothing removed: %+v", out)
			}
			if c.why != "" && !strings.Contains(out.extra[0].Why, c.why) {
				t.Errorf("the reason must be reported, got %q", out.extra[0].Why)
			}
			if out.extra[0].Who == "" && c.extra.Iface != "" {
				t.Errorf("no adapter named: %+v", out.extra[0])
			}
		})
	}
}

func TestCompareLinuxOwnership(t *testing.T) {
	client := withGW(route("10.201.0.0/24", "wghome", 6, 0, 2, 0), "10.201.0.1")
	cases := []struct {
		name    string
		extra   OSRoute
		planned bool
		journal []config.Route
		del     bool
		legacy  bool
	}{
		{name: "tagged, our table", extra: inTable(247, route("10.10.0.0/16", "wgcorp", 5, 1, 247, 0)), del: true},
		{name: "tagged, another table of ours", extra: inTable(249, route("10.10.0.0/16", "wgcorp", 5, 1, 247, 0)), del: true},
		{name: "tagged, main table", extra: route("10.10.0.0/16", "wgcorp", 5, 1, 247, 0), del: true},
		{name: "tagged, but a table of somebody else", extra: inTable(2022, route("10.10.0.0/16", "wgcorp", 5, 1, 247, 0))},
		{name: "tagged, but not our metric", extra: route("10.10.0.0/16", "wgcorp", 5, 25, 247, 0)},
		{name: "tagged, half of a full tunnel, not in the journal", extra: route("0.0.0.0/1", "wghome", 6, 1, 247, 0)},
		{name: "tagged, half of a full tunnel, the journal lists it", extra: route("0.0.0.0/1", "wghome", 6, 1, 247, 0),
			journal: []config.Route{{Dest: "0.0.0.0/1", Iface: "wghome", Via: "home", Metric: 1}}, del: true},
		{name: "never a default route", extra: route("0.0.0.0/0", "wghome", 6, 1, 247, 0), journal: []config.Route{{Dest: "0.0.0.0/0", Iface: "wghome", Metric: 1}}},
		{name: "old version: metric 1, boot protocol, in the plan: the plan is not enough", extra: route("203.0.113.11/32", "wgcorp", 5, 1, 3, 0), planned: true},
		{name: "old version: metric 1, boot protocol, listed in the old journal", extra: route("203.0.113.11/32", "wgcorp", 5, 1, 3, 0),
			journal: []config.Route{{Dest: "203.0.113.11/32", Iface: "wgcorp", Via: "corp"}}, del: true, legacy: true},
		{name: "old version: metric 1, no protocol, listed in the old journal", extra: route("203.0.113.11/32", "wgcorp", 5, 1, 0, 0),
			journal: []config.Route{{Dest: "203.0.113.11/32", Iface: "wgcorp", Via: "corp"}}, del: true, legacy: true},
		{name: "same shape, not in any plan", extra: route("203.0.113.11/32", "wgcorp", 5, 1, 3, 0)},
		{name: "metric 1 but a DHCP protocol", extra: route("203.0.113.11/32", "wgcorp", 5, 1, 16, 0), planned: true},
		{name: "old shape in another table is a client's", extra: inTable(2022, route("203.0.113.11/32", "wgcorp", 5, 1, 3, 0)), planned: true},
		{name: "a client's route", extra: route("172.16.0.0/12", "wgcorp", 5, 0, 4, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := cmpPlanned("linux", snapOf(client), []OSRoute{client, c.extra}, c.journal, c.extra, c.planned, false)
			if c.del {
				if len(out.del) != 1 || len(out.extra) != 0 {
					t.Fatalf("want one removal: %+v", out)
				}
				if r := out.del[0].route; r.Table != c.extra.Table || c.legacy != r.Legacy() {
					t.Errorf("removal %+v", r)
				}
				return
			}
			if len(out.del) != 0 || len(out.extra) != 1 {
				t.Fatalf("want one difference, nothing removed: %+v", out)
			}
		})
	}
}

// A VPN that reconnects under the same name has another index and LUID: that is
// the same route, not a difference.
func TestCompareSameNameNewIndexIsNoDifference(t *testing.T) {
	before := withGW(route("10.201.0.0/24", "wghome", 6, 261, 3, 0), "10.201.0.1")
	after := withGW(route("10.201.0.0/24", "wghome", 19, 261, 3, 0), "10.201.0.1")
	after.LUID = 12345
	for _, goos := range []string{"windows", "linux"} {
		out := cmp(goos, snapOf(before), []OSRoute{after}, nil)
		if len(out.del)+len(out.extra)+len(out.missing) != 0 {
			t.Errorf("%s: %+v", goos, out)
		}
	}
}

// What was there and is gone is only reported, never restored or counted as ours.
func TestCompareMissingIsOnlyReported(t *testing.T) {
	a := withGW(route("10.201.0.0/24", "wghome", 6, 261, 3, 0), "10.201.0.1")
	b := route("10.200.0.0/24", "wgcorp", 5, 261, 3, 0)
	out := cmp("windows", snapOf(a, b), []OSRoute{a}, nil)
	if len(out.missing) != 1 || !strings.Contains(out.missing[0].Text, "10.200.0.0/24") || len(out.del) != 0 || len(out.extra) != 0 {
		t.Errorf("%+v", out)
	}
	// two equal routes in the snapshot (two tables, two metrics) are counted, not merged
	out = cmp("linux", snapOf(a, a), []OSRoute{a}, nil)
	if len(out.missing) != 1 {
		t.Errorf("%+v", out)
	}
}

func TestCompareRulesAndDNS(t *testing.T) {
	clientRule := OSRule{Pref: 9000, Table: 2022, Suppress: -1, ToTable: true, Fwmark: true, Inv: true}
	ourRule := OSRule{Pref: 5000, Table: config.OwnTable, Suppress: -1, ToTable: true, Ours: true}
	foreign := OSRule{Pref: 100, Table: 77, Suppress: -1, ToTable: true, Src: netip.MustParsePrefix("10.0.0.0/8")}
	snap := &config.Snapshot{RoutesKnown: true, RulesKnown: true, ResolversKnown: true,
		Rules:     []config.SnapRule{snapRuleOf(clientRule), snapRuleOf(OSRule{Pref: 32766, Table: 254, Suppress: -1, ToTable: true})},
		Resolvers: []config.SnapResolver{{ID: "keep.example", Detail: "servers 1.1.1.1 comment \"\""}, {ID: "gone.example", Detail: "x"}}}
	out := compare(compareIn{goos: "linux", snap: snap, jRes: []string{"journal.example"},
		cur: osState{routesKnown: true, rulesKnown: true, resolversKnown: true,
			rules: []OSRule{clientRule, ourRule, foreign},
			resolvers: []OSResolver{{ID: "keep.example", Detail: "servers 1.1.1.1 comment \"\""},
				{ID: "mine.example", Detail: "c", Ours: true}, {ID: "journal.example", Detail: "c"}, {ID: "other.example", Detail: "c"}}}})
	kinds := func(items []delItem) string {
		var s []string
		for _, i := range items {
			s = append(s, i.diff.Kind)
		}
		return strings.Join(s, ",")
	}
	if got := kinds(out.del); got != "rule,dns,dns" {
		t.Errorf("removals %q: %+v", got, out.del)
	}
	if len(out.extra) != 2 { // the foreign rule and other.example
		t.Errorf("extra %+v", out.extra)
	}
	if len(out.missing) != 2 { // the main rule and gone.example
		t.Errorf("missing %+v", out.missing)
	}
}

func TestRouteMarkTable(t *testing.T) {
	for _, c := range []struct {
		goos string
		o    OSRoute
		want markKind
	}{
		{"windows", route("10.0.0.0/8", "a", 1, 3, 3, 0), markOurs},
		{"windows", route("10.0.0.0/8", "a", 1, 1, 3, 0), markLegacy},
		{"windows", route("10.0.0.0/8", "a", 1, 1, 3, 2), markNone},
		{"windows", route("10.0.0.0/8", "a", 1, 3, 2, 0), markNone},
		{"windows", route("10.0.0.0/8", "a", 1, 2, 3, 0), markNone},
		{"linux", route("10.0.0.0/8", "a", 1, 1, 247, 0), markOurs},
		{"linux", inTable(250, route("10.0.0.0/8", "a", 1, 1, 247, 0)), markOurs},
		{"linux", inTable(251, route("10.0.0.0/8", "a", 1, 1, 247, 0)), markNone},
		{"linux", inTable(2022, route("10.0.0.0/8", "a", 1, 1, 247, 0)), markNone},
		{"linux", route("10.0.0.0/8", "a", 1, 5, 247, 0), markNone},
		{"linux", route("10.0.0.0/8", "a", 1, 1, 3, 0), markLegacy},
		{"linux", route("10.0.0.0/8", "a", 1, 1, 4, 0), markNone},
		{"darwin", route("10.0.0.0/8", "a", 1, 1, 3, 0), markNone},
	} {
		if got := routeMark(c.goos, c.o); got != c.want {
			t.Errorf("%s %+v: %v, want %v", c.goos, c.o, got, c.want)
		}
	}
}

func TestBaselineDescribe(t *testing.T) {
	ok := Baseline{Checked: true}
	if got := ok.Describe(true); got != "Восстановлено как до запуска" {
		t.Errorf("%q", got)
	}
	if got := ok.Describe(false); !strings.Contains(got, "Restored") {
		t.Errorf("%q", got)
	}
	b := Baseline{Checked: true, Extra: []BaseDiff{
		{Kind: "route", Text: "192.0.2.0/24 dev wgcorp metric 0", Who: "adapter wgcorp / client WireGuard"},
		{Kind: "route", Text: "10.1.0.0/16 dev wgcorp metric 3", Ours: true, Why: "not removed: boom"},
	}, Missing: []BaseDiff{{Kind: "route", Text: "10.9.0.0/16 dev gone"}}}
	got := b.Describe(true)
	for _, w := range []string{"Осталось отличий: 3", "поставлено не vpnsplit: 1", "НАШИХ НЕ УБРАНО: 1", "WireGuard", "пропало с момента запуска"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q misses %q", got, w)
		}
	}
	if b.Restored() {
		t.Error("restored with differences")
	}
	if (Baseline{Checked: true, Cut: true}).Restored() {
		t.Error("an incomplete comparison is not a success")
	}
	// nothing to say where the OS has no table or there is no snapshot
	if s := (Baseline{Note: "no snapshot"}).Describe(false); s != "" {
		t.Errorf("%q", s)
	}
	if s := (Baseline{Note: noTableNote + ": boom"}).Describe(false); !strings.Contains(s, "boom") {
		t.Errorf("a real failure must be said: %q", s)
	}
}

// ---- the session: snapshot at Acquire, comparison at the end

func clientSeed(b *memBackend) {
	b.routes = append(b.routes,
		withGW(route("0.0.0.0/0", "eth0", 2, 25, 3, 0), "192.168.1.1"),
		route("10.201.0.0/24", "wghome", 6, 261, 2, 0),
		route("10.200.0.0/24", "wgcorp", 5, 261, 2, 0))
}

func ours(goosRoute config.Route) OSRoute { return newMemBackend().toOS(goosRoute) }

func finish(t *testing.T, a *applyRig) Report {
	t.Helper()
	rep, err := a.s.CleanupUntil(time.Now().Add(5*time.Second), nil)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	return rep
}

func TestBaselineRestoredAfterSession(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	if a.store.snap == nil {
		t.Fatal("no snapshot was taken at Acquire")
	}
	a.apply(t, testCfg())
	if a.mb.count() <= 3 {
		t.Fatal("nothing was applied")
	}
	rep := finish(t, a)
	if rep.Base == nil || !rep.Base.Restored() {
		t.Fatalf("not restored: %+v", rep.Base)
	}
	if a.store.snap != nil {
		t.Error("the snapshot of a finished session must be deleted")
	}
	if a.mb.count() != 3 {
		t.Errorf("the table is not the seed: %d routes", a.mb.count())
	}
	if !strings.Contains(rep.Base.Describe(true), "Восстановлено как до запуска") {
		t.Errorf("%q", rep.Base.Describe(true))
	}
}

// A route a VPN client adds during the session stays, and the report says whose it is.
func TestBaselineClientRouteStaysAndIsReported(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	a.m.providerOf = func() map[string]string { return map[string]string{"wgcorp": "WireGuard"} }
	a.apply(t, testCfg())
	a.mb.routes = append(a.mb.routes, withGW(route("192.0.2.0/24", "wgcorp", 5, 0, 4, 0), "10.200.0.1"))
	rep := finish(t, a)
	if rep.Base == nil || rep.Base.Restored() || len(rep.Base.Extra) != 1 {
		t.Fatalf("%+v", rep.Base)
	}
	d := rep.Base.Extra[0]
	if d.Ours || d.Who != "adapter wgcorp / client WireGuard" {
		t.Errorf("%+v", d)
	}
	if !a.mb.has("192.0.2.0/24", "wgcorp") {
		t.Error("a client's route was removed")
	}
	if s := rep.Base.Describe(true); !strings.Contains(s, "Осталось отличий: 1") || !strings.Contains(s, "поставлено не vpnsplit") {
		t.Errorf("%q", s)
	}
}

// lostRoute puts a route of ours into the table that the journal does not list
// and notes it in the plan, as if the journal had been lost after the plan was made.
func (a *applyRig) lostRoute(dest string) {
	r := config.Route{Dest: dest, Iface: "wgcorp", Metric: ownMetric}
	a.m.notePlanned([]config.Route{r})
	if sn, _ := a.store.LoadSnapshot(); sn != nil { // the manager may have ended already: the next start reads the notes
		n, _ := a.store.LoadPlanNotes(sn.Taken)
		if n == nil {
			n = &config.PlanNotes{Taken: sn.Taken}
		}
		n.Planned = append(n.Planned, routeKey(r))
		_ = a.store.SavePlanNotes(n)
	}
	a.mb.routes = append(a.mb.routes, ours(r))
}

// Something of ours that the journal has lost is removed by the comparison: on
// Linux it carries the mark, on Windows it is also a route of the plan.
func TestBaselineRemovesOursTheJournalLost(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	a.apply(t, testCfg())
	a.lostRoute("198.51.100.0/24")
	rep := finish(t, a)
	if rep.Base == nil || !rep.Base.Restored() || len(rep.Base.Removed) != 1 {
		t.Fatalf("%+v", rep.Base)
	}
	if a.mb.has("198.51.100.0/24", "wgcorp") {
		t.Error("still there")
	}
}

// A route of the shape of an old version (metric 1, no mark) is not removed
// because a plan of ours covers it: a VPN client makes such routes by the thousand.
// Only the journal of an old version, picked up in this run, says they are ours.
func TestBaselineOldVersionShapeStaysWithoutItsJournal(t *testing.T) {
	if ownMetric == config.LegacyMetric {
		t.Skip("on this build our routes have the metric of the old ones: the kernel would not hold both, the journal says which is ours")
	}
	a := newApplyRigWith(t, clientSeed)
	a.m.goos = "windows"
	a.apply(t, testCfg())
	old := route("10.10.0.0/16", "wgcorp", 5, 1, mibNetMgmt, 0) // what route.exe made with metric 1
	a.mb.routes = append(a.mb.routes, old)
	a.m.notePlanned([]config.Route{{Dest: "10.10.0.0/16", Iface: "wgcorp", Metric: 1}})
	rep := finish(t, a)
	if rep.Base == nil || len(rep.Base.Removed) != 0 || rep.Base.Restored() || len(rep.Base.Extra) != 1 {
		t.Fatalf("%+v", rep.Base)
	}
	if !a.mb.has("10.10.0.0/16", "wgcorp") {
		t.Error("a route that may be a client's was removed")
	}
}

// Running out of time does not lose the comparison: the snapshot stays, and the
// next start (Acquire) makes it, removing what is ours on the way.
func TestBaselineOutOfTimeIsFinishedByTheNextStart(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	a.apply(t, testCfg())
	a.mb.routesBlock = make(chan struct{})
	rep, err := a.s.CleanupUntil(time.Now().Add(400*time.Millisecond), nil)
	if err != nil {
		t.Fatalf("the journal part was complete: %v", err)
	}
	if rep.Base == nil || !rep.Base.Cut || rep.Base.Restored() {
		t.Fatalf("%+v", rep.Base)
	}
	if !strings.Contains(rep.Base.Describe(false), "next start") {
		t.Errorf("%q", rep.Base.Describe(false))
	}
	if a.store.snap == nil {
		t.Fatal("the snapshot must stay for the next start")
	}
	close(a.mb.routesBlock)
	a.mb.routesBlock = nil
	a.lostRoute("198.51.100.0/24")

	m2 := newManager(a.mb, a.store, a.procs, a.lock.take)
	s2, info, err := m2.Acquire(context.Background(), config.ModeSession, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Baseline == nil || !info.Baseline.Restored() || len(info.Baseline.Removed) != 1 {
		t.Fatalf("%+v", info.Baseline)
	}
	if a.mb.has("198.51.100.0/24", "wgcorp") || a.mb.count() != 3 {
		t.Errorf("the table is not the seed: %d routes", a.mb.count())
	}
	if a.store.snap == nil {
		t.Error("the new session needs a snapshot of its own")
	}
	_, _ = s2.CleanupUntil(time.Now().Add(time.Second), nil)
}

func TestSnapshotFromBeforeARestartIsIgnored(t *testing.T) {
	r := newRig(nil)
	old := &config.Snapshot{Owner: &config.Owner{PID: 1, Boot: "boot-1"}, RoutesKnown: true,
		Routes: []config.SnapRoute{{Dest: "10.7.0.0/16", Iface: "x"}}}
	_ = r.store.SaveSnapshot(old)
	s, info := acquire(t, r, config.ModeSession)
	if info.Baseline != nil {
		t.Errorf("compared with the table of another boot: %+v", info.Baseline)
	}
	sn, _ := r.store.LoadSnapshot()
	if sn == nil || sn.Owner.Boot != "boot-2" || len(sn.Routes) != 0 {
		t.Errorf("a new snapshot was expected: %+v", sn)
	}
	_ = s
}

// While the journal lists entries (apply/watch left them), the snapshot of that
// run is the baseline and is not replaced.
func TestSnapshotKeptWhileJournalListsEntries(t *testing.T) {
	st := sessionJournal(4242, config.ModePersistent)
	r := newRig(st)
	mark := &config.Snapshot{Owner: &config.Owner{PID: 4242, Boot: "boot-2"}, Taken: "2020-01-01T00:00:00Z", RoutesKnown: true}
	_ = r.store.SaveSnapshot(mark)
	_, info := acquire(t, r, config.ModeSession)
	if info.Baseline != nil {
		t.Errorf("%+v", info.Baseline)
	}
	if sn, _ := r.store.LoadSnapshot(); sn == nil || sn.Taken != mark.Taken {
		t.Errorf("replaced: %+v", sn)
	}
}

// No snapshot, journal with entries: the snapshot leaves them out and says so.
func TestSnapshotLeavesOutWhatTheJournalLists(t *testing.T) {
	mb := newMemBackend()
	clientSeed(mb)
	listed := config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: ViaCorp, Metric: ownMetric}
	mb.routes = append(mb.routes, mb.toOS(listed))
	r := newRig(&config.State{Version: config.JournalVersion, Routes: []config.Route{listed}, Sig: "s",
		Owner: &config.Owner{PID: 4242, Start: 4000, Boot: "boot-2"}, Mode: config.ModePersistent})
	r.m = newManager(mb, r.store, r.procs, r.lock.take)
	acquire(t, r, config.ModePersistent)
	sn, _ := r.store.LoadSnapshot()
	if sn == nil || !sn.Approx || len(sn.Routes) != 3 {
		t.Fatalf("%+v", sn)
	}
	for _, x := range sn.Routes {
		if x.Dest == "10.10.0.0/16" {
			t.Error("a route of the journal is in the baseline")
		}
	}
}

func TestNoSnapshotForReset(t *testing.T) {
	r := newRig(nil)
	r.m.NoSnapshot()
	acquire(t, r, config.ModePersistent)
	if r.store.snap != nil || r.store.snapSaves != 0 {
		t.Error("reset must not take a snapshot")
	}
}

func TestApplyRecordsThePlanInTheSnapshot(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	a.apply(t, testCfg())
	sn, _ := a.store.LoadSnapshot()
	if sn == nil {
		t.Fatal("no snapshot")
	}
	n, _ := a.store.LoadPlanNotes(sn.Taken)
	if n == nil || len(n.Planned) == 0 {
		t.Fatalf("%+v", n)
	}
	found := false
	for _, d := range n.Planned {
		found = found || d == "10.10.0.0/16|wgcorp||0"
	}
	if !found {
		t.Errorf("%v", n.Planned)
	}
	snapSaves, planSaves := a.store.snapSaves, a.store.planSaves
	a.apply(t, testCfg()) // the same plan again: nothing to write
	if a.store.snapSaves != snapSaves || a.store.planSaves != planSaves {
		t.Errorf("rewritten for an unchanged plan: snapshot %d -> %d, notes %d -> %d", snapSaves, a.store.snapSaves, planSaves, a.store.planSaves)
	}
	// a bigger plan grows the small file of notes and never touches the snapshot
	cfg := testCfg()
	cfg.Networks = append(cfg.Networks, "198.51.100.0/24")
	a.apply(t, cfg)
	if a.store.snapSaves != snapSaves || a.store.planSaves != planSaves+1 {
		t.Errorf("snapshot %d -> %d, notes %d -> %d", snapSaves, a.store.snapSaves, planSaves, a.store.planSaves)
	}
}

// `reset` removes what the journal lists and then compares: Settle.
func TestSettleAfterReset(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	a.apply(t, testCfg())
	rep, errs := a.m.ResetReport()
	if len(errs) != 0 || rep.Total() == 0 {
		t.Fatalf("%v %+v", errs, rep)
	}
	a.lostRoute("198.51.100.0/24")
	b := a.s.Settle(time.Now().Add(5 * time.Second))
	if b == nil || !b.Restored() || len(b.Removed) != 1 {
		t.Fatalf("%+v", b)
	}
	if a.store.snap != nil {
		t.Error("the snapshot stays after a complete comparison")
	}
}

// vpnsplit diff: a read-only comparison.
func TestDiffChangesNothing(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	a.apply(t, testCfg())
	before := a.mb.count()
	b := a.m.diff(context.Background(), true)
	if !b.Checked {
		t.Fatalf("%+v", b)
	}
	// the applied routes are in the journal and carry our mark: they are ours, still there
	ourN := 0
	for _, d := range b.Extra {
		if d.Ours {
			ourN++
		}
	}
	if ourN == 0 || a.mb.count() != before {
		t.Errorf("ours %d, table %d -> %d", ourN, before, a.mb.count())
	}
}

// Check Point puts thousands of metric-1 routes of exactly the shape of the old
// versions' routes into the table. Only the route our own plan has (same
// destination, adapter AND next hop) can be taken for ours; a client's route to
// a destination of our plan through its own adapter must stay.
func TestCompareClientRouteWithShapeOfOldVersionStays(t *testing.T) {
	cp := withGW(route("10.1.15.0/24", "Ethernet 3", 45, 1, 3, 0), "10.0.73.156")
	planned := withGW(route("10.1.15.0/24", "Беспроводная сеть", 20, 1, 3, 0), "192.168.1.1") // our plan's (direct) route to it
	out := cmpPlanned("windows", snapOf(), []OSRoute{cp}, nil, planned, true, false)
	if len(out.del) != 0 || len(out.extra) != 1 {
		t.Errorf("%+v", out)
	}
	// not even the route of the plan itself: only a journal of an old version says it is ours
	out = cmpPlanned("windows", snapOf(), []OSRoute{planned}, nil, planned, true, false)
	if len(out.del) != 0 || len(out.extra) != 1 {
		t.Errorf("the route of the plan itself: %+v", out)
	}
}

// A look at a running session is not a failure report: what is ours is simply applied.
func TestLiveDescribeDoesNotCallAppliedRoutesLeftovers(t *testing.T) {
	b := Baseline{Checked: true, Live: true, Extra: []BaseDiff{{Kind: "route", Text: "10.10.0.0/16 dev wgcorp", Ours: true}}}
	s := b.Describe(false)
	if strings.Contains(s, "NOT REMOVED") || !strings.Contains(s, "applied by vpnsplit") || !strings.Contains(s, "Differences now: 1") {
		t.Errorf("%q", s)
	}
	if !strings.Contains(b.Lines(false)[0], "<- ours") {
		t.Errorf("%v", b.Lines(false))
	}
}
