package router

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// The one rule of the comparison with the snapshot: it never removes what may
// be a VPN client's or the user's. These tests are that rule, case by case.

func plainState(routes []OSRoute) osState {
	return osState{routes: routes, routesKnown: true, rulesKnown: true, resolversKnown: true}
}

// Check Point puts thousands of metric-1 routes of exactly the shape of the old
// versions' routes into the table, on its own adapter. Whatever a plan says and
// whatever the OS and the client lookup say, none of them goes without the journal.
func TestCheckPointRoutesAreNeverRemoved(t *testing.T) {
	var cur []OSRoute
	hint := map[string]bool{}
	for i := 0; i < 1000; i++ {
		o := withGW(route(fmt.Sprintf("10.%d.%d.0/24", i/250+1, i%250), "Ethernet 3", 45, 1, mibNetMgmt, 0), "10.0.73.156")
		cur = append(cur, o)
		hint[osKey(o)] = true
	}
	for _, goos := range []string{"windows", "linux"} {
		for _, provider := range []string{"", "Check Point"} {
			p := provider
			out := compare(compareIn{goos: goos, snap: snapOf(), cur: plainState(cur), hint: hint, kept: map[string]bool{},
				provider: func(string) string { return p }})
			if len(out.del) != 0 || len(out.extra) != 1000 {
				t.Errorf("%s/%q: %d removals, %d left", goos, provider, len(out.del), len(out.extra))
			}
		}
	}
	// the same routes with the mark of the Windows build (metric 3) and in the plan:
	// the adapter of a recognized client keeps them
	var marked []OSRoute
	for _, o := range cur {
		o.Metric = 3
		marked = append(marked, o)
	}
	hint3 := map[string]bool{}
	for _, o := range marked {
		hint3[osKey(o)] = true
	}
	out := compare(compareIn{goos: "windows", snap: snapOf(), cur: plainState(marked), hint: hint3, kept: map[string]bool{},
		provider: func(string) string { return "Check Point" }})
	if len(out.del) != 0 || len(out.extra) != 1000 {
		t.Errorf("a client's adapter: %d removals, %d left", len(out.del), len(out.extra))
	}
	if !strings.Contains(out.extra[0].Why, "Check Point") {
		t.Errorf("the reason must be given: %+v", out.extra[0])
	}
}

// A metric-3 route that was there before the start is in the baseline and is not
// removed, whether or not a plan of ours covers it.
func TestForeignMarkedRouteBeforeTheStartStays(t *testing.T) {
	client := withGW(route("10.10.0.0/16", "wgcorp", 5, 3, mibNetMgmt, 0), "10.200.0.1")
	a := newApplyRigOS(t, "windows", func(b *memBackend) {
		clientSeed(b)
		b.routes = append(b.routes, client)
	})
	sn, _ := a.store.LoadSnapshot()
	found := false
	for _, r := range sn.Routes {
		found = found || r.Dest == "10.10.0.0/16"
	}
	if !found {
		t.Fatal("a route with the shape of ours that the journal does not list belongs in the baseline")
	}
	a.apply(t, testCfg()) // its destination is in the plan; it is found in place and left alone
	rep := finish(t, a)
	if rep.Base == nil || !rep.Base.Restored() || len(rep.Base.Removed) != 0 {
		t.Fatalf("%+v", rep.Base)
	}
	if !a.mb.has("10.10.0.0/16", "wgcorp") {
		t.Error("the route of the baseline was removed")
	}
}

// A metric-3 route that appears during the session, and is not in the journal, is
// reported and stays unless it is exactly a route of the plan.
func TestMarkedRouteOfAClientDuringTheSessionStays(t *testing.T) {
	a := newApplyRigOS(t, "windows", clientSeed)
	a.apply(t, testCfg())
	a.mb.routes = append(a.mb.routes, withGW(route("172.20.0.0/16", "wgcorp", 5, 3, mibNetMgmt, 0), "10.200.0.1"))
	rep := finish(t, a)
	if rep.Base == nil || rep.Base.Restored() || len(rep.Base.Removed) != 0 || len(rep.Base.Extra) != 1 || rep.Base.Extra[0].Ours {
		t.Fatalf("%+v", rep.Base)
	}
	if !a.mb.has("172.20.0.0/16", "wgcorp") {
		t.Error("removed")
	}
}

// The client puts a route with the key of one of ours (the destination of a plan,
// the old version's shape: boot protocol, metric 1) in the main table while ours is
// in table 247: only ours goes.
func TestLinuxBootRouteInMainStaysWhenOursIsIn247(t *testing.T) {
	clients := withGW(route("203.0.113.11/32", "wgcorp", 5, 1, 3, 0), "10.200.0.1")
	mine := inTable(247, withGW(route("203.0.113.11/32", "wgcorp", 5, 1, 247, 0), "10.200.0.1"))
	mine.Ours = true
	hint := map[string]bool{osKey(mine): true, osKey(clients): true}
	out := compare(compareIn{goos: "linux", snap: snapOf(), cur: plainState([]OSRoute{clients, mine}), hint: hint, kept: map[string]bool{}})
	if len(out.del) != 1 || out.del[0].route.Table != 247 || len(out.extra) != 1 || out.extra[0].Ours {
		t.Fatalf("%+v", out)
	}
	// the key of a route includes its table: the plan's route in 247 says nothing about main
	if osKey(clients) == osKey(mine) {
		t.Error("the table is part of the key")
	}
}

func TestDNSOfSomebodyElseStays(t *testing.T) {
	snap := &config.Snapshot{RoutesKnown: true, RulesKnown: true, ResolversKnown: true}
	theirs := OSResolver{ID: "corp.example", Detail: "servers 10.1.1.1 comment \"corp\""}
	mine := OSResolver{ID: "mine.example", Detail: "servers 10.2.2.2 comment \"vpnsplit\"", Ours: true}
	cur := osState{routesKnown: true, rulesKnown: true, resolversKnown: true, resolvers: []OSResolver{theirs, mine}}
	// the journal names the zone of the foreign rule too (same namespace)
	for _, goos := range []string{"windows", "linux"} {
		out := compare(compareIn{goos: goos, snap: snap, cur: cur, jRes: []string{"corp.example"}})
		dels := map[string]bool{}
		for _, d := range out.del {
			dels[d.id] = true
		}
		switch goos {
		case "windows":
			// only a rule with our comment goes; the journal's word is not enough
			if dels["corp.example"] || !dels["mine.example"] || len(out.extra) != 1 {
				t.Errorf("windows: %+v", out)
			}
		default:
			// where the OS has no mark on the entry, the journal is the proof
			if !dels["corp.example"] || !dels["mine.example"] {
				t.Errorf("%s: %+v", goos, out)
			}
		}
	}
}

func TestSafeguards(t *testing.T) {
	provider := func(iface string) string {
		if iface == "ckp0" {
			return "Check Point"
		}
		return ""
	}
	owned := func(o OSRoute) OSRoute { o.Ours = true; return o }
	cases := []struct {
		name    string
		goos    string
		extra   OSRoute
		journal []config.Route
		hint    bool
		del     bool
		why     string
	}{
		{name: "linux tagged, on the adapter of a client, not in the journal", goos: "linux", extra: owned(route("10.9.0.0/16", "ckp0", 7, 1, 247, 0)), why: "Check Point"},
		{name: "linux tagged, on the adapter of a client, the journal lists it", goos: "linux", extra: owned(route("10.9.0.0/16", "ckp0", 7, 1, 247, 0)),
			journal: []config.Route{{Dest: "10.9.0.0/16", Iface: "ckp0", Via: "corp", Metric: 1}}, del: true},
		{name: "linux tagged, on our adapter", goos: "linux", extra: owned(route("10.9.0.0/16", "wgcorp", 5, 1, 247, 0)), del: true},
		{name: "windows planned, on the adapter of a client", goos: "windows", extra: route("10.9.0.0/16", "ckp0", 7, 3, mibNetMgmt, 0), hint: true, why: "Check Point"},
		{name: "windows planned, on our adapter", goos: "windows", extra: route("10.9.0.0/16", "wgcorp", 5, 3, mibNetMgmt, 0), hint: true, del: true},
		{name: "windows planned /1, not in the journal", goos: "windows", extra: route("0.0.0.0/1", "wghome", 6, 3, mibNetMgmt, 0), hint: true, why: "full tunnel"},
		{name: "windows planned /1, the journal lists it", goos: "windows", extra: route("128.0.0.0/1", "wghome", 6, 3, mibNetMgmt, 0), hint: true,
			journal: []config.Route{{Dest: "128.0.0.0/1", Iface: "wghome", Via: "home", Metric: 3}}, del: true},
		{name: "windows planned /2 is not a half", goos: "windows", extra: route("64.0.0.0/2", "wghome", 6, 3, mibNetMgmt, 0), hint: true, del: true},
		{name: "windows default route, listed", goos: "windows", extra: route("0.0.0.0/0", "wghome", 6, 3, mibNetMgmt, 0), hint: true,
			journal: []config.Route{{Dest: "0.0.0.0/0", Iface: "wghome", Via: "home", Metric: 3}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hint := map[string]bool{}
			if c.hint {
				hint[osKey(c.extra)] = true
			}
			out := compare(compareIn{goos: c.goos, snap: snapOf(), cur: plainState([]OSRoute{c.extra}), journal: c.journal,
				hint: hint, kept: map[string]bool{}, provider: provider})
			if c.del {
				if len(out.del) != 1 || len(out.extra) != 0 {
					t.Fatalf("want one removal: %+v", out)
				}
				return
			}
			if len(out.del) != 0 || len(out.extra) != 1 {
				t.Fatalf("want nothing removed: %+v", out)
			}
			if c.why != "" && !strings.Contains(out.extra[0].Why, c.why) {
				t.Errorf("reason %q, want %q in it", out.extra[0].Why, c.why)
			}
		})
	}
	// not knowing who owns the adapter is no reason to remove
	o := owned(route("10.9.0.0/16", "wgcorp", 5, 1, 247, 0))
	out := compare(compareIn{goos: "linux", snap: snapOf(), cur: plainState([]OSRoute{o}),
		provider: func(string) string { return "(unknown)" }})
	if len(out.del) != 0 || len(out.extra) != 1 {
		t.Errorf("%+v", out)
	}
}

// The lookup of the clients behind the adapters is made once, and a failed one
// keeps everything in place.
func TestProviderLookupFailureKeepsRoutes(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	calls := 0
	a.m.providerOf = func() map[string]string { calls++; return nil } // the adapters cannot be listed
	a.apply(t, testCfg())
	a.lostRoute("198.51.100.0/24")
	a.lostRoute("198.51.100.1/32")
	rep := finish(t, a)
	if rep.Base == nil || len(rep.Base.Removed) != 0 || len(rep.Base.Extra) < 2 {
		t.Fatalf("%+v", rep.Base)
	}
	if calls != 1 {
		t.Errorf("the lookup was made %d times", calls)
	}
}

// Time ran out after the removals: what was removed is not reported as left.
func TestReportAfterTimeoutDoesNotListWhatWasRemoved(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	a.apply(t, testCfg())
	if _, errs := a.m.ResetReport(); len(errs) != 0 {
		t.Fatal(errs)
	}
	a.lostRoute("198.51.100.0/24")
	release := make(chan struct{})
	base := a.mb.routeReads
	a.mb.onRoutes = func(n int) {
		if n == base+2 { // the second read, after the removal
			<-release
		}
	}
	b := a.s.Settle(time.Now().Add(600 * time.Millisecond))
	close(release)
	if b == nil || !b.Cut || len(b.Removed) != 1 {
		t.Fatalf("%+v", b)
	}
	if len(b.Extra) != 0 {
		t.Errorf("a removed route is listed as not removed: %+v", b.Extra)
	}
	if a.mb.has("198.51.100.0/24", "wgcorp") {
		t.Error("still there")
	}
}

// An exit that the OS forces: no DNS is read, and with too little time left
// nothing is compared (the snapshot stays for the next start).
func TestAbruptCleanupBudget(t *testing.T) {
	t.Run("no time left", func(t *testing.T) {
		a := newApplyRigWith(t, clientSeed)
		a.apply(t, testCfg())
		a.lostRoute("198.51.100.0/24")
		reads := a.mb.routeReads
		rep, err := a.s.CleanupUntil(time.Now().Add(time.Second), nil)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Base == nil || !rep.Base.Cut || rep.Base.Checked {
			t.Fatalf("%+v", rep.Base)
		}
		if a.store.snap == nil {
			t.Error("the snapshot must stay for the next start")
		}
		if a.mb.routeReads != reads {
			t.Error("the table was read with no time to compare")
		}
		if !strings.Contains(rep.Base.Describe(true), "следующий запуск доделает") {
			t.Errorf("%q", rep.Base.Describe(true))
		}
	})
	t.Run("DNS is not read", func(t *testing.T) {
		a := newApplyRigWith(t, clientSeed)
		a.apply(t, testCfg())
		lists := a.mb.resolverLists
		rep, err := a.s.CleanupUntil(time.Now().Add(4500*time.Millisecond), nil)
		if err != nil || rep.Base == nil || !rep.Base.Checked {
			t.Fatalf("%v %+v", err, rep.Base)
		}
		if a.mb.resolverLists != lists {
			t.Error("the DNS entries were read in a hurry")
		}
	})
	t.Run("DNS is read when there is time", func(t *testing.T) {
		a := newApplyRigWith(t, clientSeed)
		a.apply(t, testCfg())
		lists := a.mb.resolverLists
		if _, err := a.s.CleanupUntil(time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		if a.mb.resolverLists == lists {
			t.Error("the DNS entries were not compared")
		}
	})
}

// A snapshot that cannot be tied to this boot is compared for the report only.
func TestUnprovenSnapshotIsOnlyReported(t *testing.T) {
	mb := newMemBackend()
	clientSeed(mb)
	r := newRig(nil)
	r.m = newManager(mb, r.store, r.procs, r.lock.take)
	r.m.providerOf = func() map[string]string { return map[string]string{} }
	old := &config.Snapshot{Owner: &config.Owner{PID: 1}, Taken: time.Now().UTC().Format(time.RFC3339), RoutesKnown: true, RulesKnown: true, ResolversKnown: true}
	for _, o := range mb.routes {
		old.Routes = append(old.Routes, snapRouteOf(o))
	}
	_ = r.store.SaveSnapshot(old)
	lost := config.Route{Dest: "198.51.100.0/24", Iface: "wgcorp", Metric: ownMetric}
	mb.routes = append(mb.routes, ours(lost))
	r.m.planned[routeKey(lost)] = true
	_, info := acquire(t, r, config.ModeSession)
	if info.Baseline == nil || !info.Baseline.ReportOnly || len(info.Baseline.Removed) != 0 {
		t.Fatalf("%+v", info.Baseline)
	}
	if !mb.has("198.51.100.0/24", "wgcorp") {
		t.Error("removed by a snapshot that cannot be trusted")
	}
	if s := info.Baseline.Describe(false); !strings.Contains(s, "report only") || !strings.Contains(s, "boot") {
		t.Errorf("%q", s)
	}
	if s := info.Baseline.Describe(true); !strings.Contains(s, "только отчёт") {
		t.Errorf("%q", s)
	}
	if lines := info.Baseline.Lines(false); !strings.Contains(strings.Join(lines, "\n"), "report only") {
		t.Errorf("%v", lines)
	}

	// the same for vpnsplit diff
	r2 := newRig(nil)
	r2.m = newManager(mb, r2.store, r2.procs, r2.lock.take)
	_ = r2.store.SaveSnapshot(old)
	if b := r2.m.diff(context.Background(), false); !b.Checked || !b.ReportOnly {
		t.Errorf("%+v", b)
	}
}

// A table too large to keep: the snapshot says so and the end only reports.
func TestTableTooLargeForTheSnapshot(t *testing.T) {
	defer func(n int) { maxSnapRoutes = n }(maxSnapRoutes)
	maxSnapRoutes = 2
	a := newApplyRigWith(t, clientSeed) // 3 routes
	sn, _ := a.store.LoadSnapshot()
	if sn == nil || !sn.ReportOnly || len(sn.Routes) != 0 || sn.RoutesKnown || !strings.Contains(sn.Why, "too large") {
		t.Fatalf("%+v", sn)
	}
	a.apply(t, testCfg())
	a.lostRoute("198.51.100.0/24")
	rep := finish(t, a)
	if rep.Base == nil || !rep.Base.ReportOnly || len(rep.Base.Removed) != 0 || rep.Base.Restored() {
		t.Fatalf("%+v", rep.Base)
	}
	if !a.mb.has("198.51.100.0/24", "wgcorp") {
		t.Error("removed")
	}
	if s := rep.Base.Describe(true); !strings.Contains(s, "слишком велика") {
		t.Errorf("%q", s)
	}
}

// Only the main table and ours are compared on Linux: a client's policy tables are not the baseline.
func TestOtherTablesAreNotCompared(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	a.apply(t, testCfg())
	a.mb.routes = append(a.mb.routes, inTable(2022, route("10.0.0.0/8", "wgcorp", 5, 0, 4, 0)))
	rep := finish(t, a)
	if rep.Base == nil || !rep.Base.Restored() {
		t.Errorf("%+v", rep.Base)
	}
}

// Text from the OS is put on the screen: control characters do not get through.
func TestNamesFromTheOSAreEscaped(t *testing.T) {
	evil := "Wi-Fi" + string(rune(27)) + "[2J" + string(rune(7))
	o := route("10.0.0.0/8", evil, 5, 0, 4, 0)
	txt := routeText(o)
	for _, r := range txt + (compareIn{}).who(evil) {
		if r < 32 {
			t.Fatalf("control character in %q", txt)
		}
	}
	snap := &config.Snapshot{RoutesKnown: true, RulesKnown: true, ResolversKnown: true}
	out := compare(compareIn{goos: "linux", snap: snap, cur: osState{routesKnown: true, rulesKnown: true, resolversKnown: true,
		routes: []OSRoute{o}, resolvers: []OSResolver{{ID: "x.example", Detail: "c" + string(rune(27)) + "[31m"}}}})
	if len(out.extra) != 2 {
		t.Fatalf("%+v", out)
	}
	for _, d := range out.extra {
		for _, r := range d.Text + d.Who {
			if r < 32 {
				t.Errorf("control character in %+v", d)
			}
		}
	}
}

// The notes of the plans are one small file, grown in one write per batch, and
// safe to touch from several goroutines.
func TestPlanNotesAreBatchedAndRaceFree(t *testing.T) {
	a := newApplyRigWith(t, clientSeed)
	saves := a.store.planSaves
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				a.m.noteKept(config.Route{Dest: fmt.Sprintf("10.%d.%d.0/24", i, j), Iface: "wgcorp"})
				a.m.hintSet()
			}
		}(i)
	}
	wg.Wait()
	if a.store.planSaves != saves {
		t.Error("noteKept must not write by itself")
	}
	a.m.flushNotes()
	if a.store.planSaves != saves+1 {
		t.Errorf("one write for the batch, got %d", a.store.planSaves-saves)
	}
	sn, _ := a.store.LoadSnapshot()
	if n, _ := a.store.LoadPlanNotes(sn.Taken); n == nil || len(n.Kept) != 400 {
		t.Errorf("%+v", n)
	}
	a.m.flushNotes()
	if a.store.planSaves != saves+1 {
		t.Error("nothing new, nothing written")
	}
}

// ---- DNS: only what is missing is made, and the old goes after the new

func dnsRig(t *testing.T, zones ...string) (*applyRig, *config.Config) {
	t.Helper()
	a := newApplyRig(t)
	a.m.dnsOf = corpOnly([]string{"10.200.0.1"}, zones)
	cfg := testCfg()
	cfg.SplitDNS = true
	return a, cfg
}

func TestDNSDriftMakesOnlyTheMissingEntry(t *testing.T) {
	a, cfg := dnsRig(t, "corp.example", "other.example")
	a.apply(t, cfg)
	ids := a.store.state().Resolvers
	if len(ids) < 2 {
		t.Skip("this OS has no per-domain DNS here (systemd-resolved)")
	}
	a.mb.dnsLog = nil
	a.mb.missingRes = ids[:1]
	a.apply(t, cfg)
	if len(a.mb.dnsLog) != 1 || a.mb.dnsLog[0] != "add "+ids[0] {
		t.Errorf("only the missing entry is made again, nothing removed: %v", a.mb.dnsLog)
	}
	if got := a.store.state().Resolvers; len(got) != len(ids) {
		t.Errorf("%v", got)
	}
}

func TestDNSPlanChangeAddsBeforeItRemoves(t *testing.T) {
	a, cfg := dnsRig(t, "corp.example", "old.example")
	a.apply(t, cfg)
	if len(a.store.state().Resolvers) < 2 {
		t.Skip("this OS has no per-domain DNS here (systemd-resolved)")
	}
	a.mb.dnsLog = nil
	a.m.dnsOf = corpOnly([]string{"10.200.0.1"}, []string{"corp.example", "new.example"})
	a.apply(t, cfg)
	var add, del []string
	firstDel, lastAdd := len(a.mb.dnsLog), -1
	for i, l := range a.mb.dnsLog {
		switch {
		case strings.HasPrefix(l, "add "):
			add = append(add, l)
			lastAdd = i
		case strings.HasPrefix(l, "del "):
			del = append(del, l)
			firstDel = min(firstDel, i)
		}
	}
	if len(add) != 1 || !strings.Contains(add[0], "new.example") || len(del) != 1 || !strings.Contains(del[0], "old.example") {
		t.Fatalf("only the difference: %v", a.mb.dnsLog)
	}
	if lastAdd > firstDel {
		t.Errorf("the new entry is made before the old one goes: %v", a.mb.dnsLog)
	}
	for _, id := range a.store.state().Resolvers {
		if strings.Contains(id, "old.example") {
			t.Errorf("the old entry is still in the journal: %v", a.store.state().Resolvers)
		}
	}
	// other servers: all entries point to the new ones
	a.mb.dnsLog = nil
	a.m.dnsOf = corpOnly([]string{"10.200.0.9"}, []string{"corp.example", "new.example"})
	a.apply(t, cfg)
	adds := 0
	for _, l := range a.mb.dnsLog {
		if strings.HasPrefix(l, "add ") {
			adds++
		}
		if strings.HasPrefix(l, "del ") {
			t.Errorf("nothing to remove: %v", a.mb.dnsLog)
		}
	}
	if adds != 2 {
		t.Errorf("new servers: %v", a.mb.dnsLog)
	}
}

// ---- journals of older versions

// A journal with no owner is a leftover of an older version: ours, so a session
// (the menu too) removes it when it ends, and the menu does not ask.
func TestOwnerlessJournalIsTakenIntoTheSession(t *testing.T) {
	st := &config.State{Routes: []config.Route{
		{Dest: "217.12.96.0/21", Iface: "Беспроводная сеть", Gateway: "192.168.1.1", Via: ViaDirect},
		{Dest: "217.12.104.0/23", Iface: "Беспроводная сеть", Gateway: "192.168.1.1", Via: ViaDirect},
	}, Sig: "old"}
	for _, mode := range []string{ModeSessionAsk, config.ModeSession} {
		t.Run(mode, func(t *testing.T) {
			r := newRig(st)
			s, info, err := r.m.Acquire(context.Background(), mode, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			if !info.TookOver || info.Foreign || s.Mode() != config.ModeSession || s.Foreign() {
				t.Fatalf("%+v mode %s", info, s.Mode())
			}
			if got := r.store.state(); got.Mode != config.ModeSession || got.Owner == nil || len(got.Routes) != 2 {
				t.Errorf("the journal is the session's now: %+v", got)
			}
			rep, err := s.CleanupUntil(time.Now().Add(5*time.Second), nil)
			if err != nil || rep.Routes != 2 {
				t.Fatalf("%v %+v", err, rep)
			}
			calls := strings.Join(r.b.calls(), ",")
			if !strings.Contains(calls, "route 217.12.96.0/21") || !strings.Contains(calls, "route 217.12.104.0/23") {
				t.Errorf("not removed at the end: %s", calls)
			}
		})
	}
	// apply/watch (persistent) leave it, `reset` removes it at once
	r := newRig(st)
	s, _, err := r.m.Acquire(context.Background(), config.ModePersistent, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	rep, errs := r.m.ResetReport()
	if len(errs) != 0 || rep.Routes != 2 {
		t.Fatalf("%v %+v", errs, rep)
	}
	_, _ = s.CleanupUntil(time.Now().Add(time.Second), nil)
}

// What apply/watch left (persistent, with an owner) is still not taken without the user's word.
func TestPersistentJournalIsStillAskedAbout(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModePersistent))
	s, info, err := r.m.Acquire(context.Background(), ModeSessionAsk, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !info.Foreign || info.TookOver || s.Mode() != config.ModePersistent {
		t.Errorf("%+v %s", info, s.Mode())
	}
}
