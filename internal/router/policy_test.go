package router

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// sing-box: pref 9000 not fwmark 2022 lookup 2022, default dev wghome in table 2022
func singBoxRules() []OSRule {
	return []OSRule{
		{Pref: 0, Table: 255, Suppress: -1, ToTable: true},
		{Pref: 9000, Table: 2022, Suppress: -1, ToTable: true, Fwmark: true, Inv: true},
		{Pref: 32766, Table: RuleTableMain, Suppress: -1, ToTable: true},
	}
}

func (a *applyRig) withSingBox() {
	a.mb.rules = singBoxRules()
	a.mb.routes = append(a.mb.routes, OSRoute{Dest: netip.MustParsePrefix("0.0.0.0/0"), Iface: "wghome", Table: 2022})
}

// Linux policy routing: corp and direct routes go into our table, one rule
// "lookup <our table>" is added before the first client rule, everything is
// idempotent and removed with the session.
func TestApplyPolicyRules(t *testing.T) {
	a := newApplyRig(t)
	a.withSingBox()
	cfg := testCfg()
	out := a.apply(t, cfg)
	if a.mb.has("0.0.0.0/1", "wghome") {
		t.Error("the home client routes everything itself: 0/1 must not be added")
	}
	if !strings.Contains(out, "already sends everything into the tunnel") {
		t.Errorf("no remark about the home VPN:\n%s", out)
	}
	st := a.store.state()
	if len(st.Rules) != 1 || st.Rules[0] != (config.Rule{Table: config.OwnTable, Pref: rulePrefBase}) {
		t.Fatalf("rules: %+v", st.Rules)
	}
	for _, c := range []struct{ dest, iface string }{{"10.10.0.0/16", "wgcorp"}, {"203.0.113.11/32", "wgcorp"}, {"203.0.113.12/32", "eth0"}} {
		if !a.mb.hasIn(config.OwnTable, c.dest, c.iface) || a.mb.has(c.dest, c.iface) {
			t.Errorf("%s via %s must be in table %d and not in main", c.dest, c.iface, config.OwnTable)
		}
	}
	for _, r := range st.Routes {
		if r.Table != config.OwnTable {
			t.Errorf("journal route %+v is not in our table", r)
		}
	}
	a.mb.reset()
	a.apply(t, cfg)
	if a.mb.ruleAdds+a.mb.ruleDels+a.mb.adds+a.mb.dels != 0 {
		t.Error("the second apply is not idempotent")
	}
	// a route goes with its prefix, the rule stays while there are routes
	cfg.DirectNetworks = nil
	a.apply(t, cfg)
	if a.mb.dels != 1 || a.mb.ruleDels != 0 || len(a.store.state().Rules) != 1 || len(a.store.state().Routes) != 2 {
		t.Errorf("dels %d, rule dels %d, journal %+v", a.mb.dels, a.mb.ruleDels, a.store.state())
	}
	// a rule that is gone is added again, the routes are not
	a.mb.rules = a.mb.rules[:3]
	if !drifted(a.mb, a.store.state()) {
		t.Error("a missing rule must count as drift")
	}
	a.mb.reset()
	a.apply(t, cfg)
	if a.mb.ruleAdds != 1 || a.mb.adds != 0 {
		t.Errorf("rule adds %d, route adds %d", a.mb.ruleAdds, a.mb.adds)
	}
	a.mb.reset()
	rep, err := a.s.Cleanup(time.Second)
	if err != nil || rep.Rules != 1 || rep.Routes != 2 || len(a.mb.rules) != 3 || a.mb.count() != 1 {
		t.Errorf("cleanup: %+v %v, %d rules left, %d routes left", rep, err, len(a.mb.rules), a.mb.count())
	}
	if !before(a.mb.log, "delrule", "del ") {
		t.Errorf("the rule goes before the routes: %v", a.mb.log)
	}
}

// The rule has no destination and does not look into the main table: when the
// corp tunnel is gone and its routes with it, nothing in our table matches and
// the packet goes on to the client's rules instead of the default route of the
// main table.
func TestPolicyRuleIsAPlainLookupOfOurTable(t *testing.T) {
	a := newApplyRig(t)
	a.withSingBox()
	a.apply(t, testCfg())
	n := 0
	for _, r := range a.mb.rules {
		if !r.Ours {
			continue
		}
		n++
		if r.Table != config.OwnTable || r.Dest.IsValid() || r.Src.IsValid() || r.hasSel() || r.Pref >= 9000 {
			t.Errorf("our rule must be a plain lookup of our table before the client's: %+v", r)
		}
	}
	if n != 1 {
		t.Errorf("%d rules of ours", n)
	}
	// nothing of the corp network is in the main table, where the default route would catch it
	for _, r := range a.mb.routes {
		if r.Table == 0 && r.Dest.Bits() > 0 {
			t.Errorf("a route in the main table: %+v", r)
		}
	}
}

// Policy routing appears while routes are applied (the client starts later):
// the routes move from main into our table, additions first; and back.
func TestApplyMovesRoutesIntoOurTableAndBack(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	a.apply(t, cfg)
	if !a.mb.has("10.10.0.0/16", "wgcorp") || len(a.store.state().Rules) != 0 {
		t.Fatal("no policy routing: main table, no rules")
	}
	a.withSingBox()
	a.mb.reset()
	a.apply(t, cfg)
	if a.mb.has("10.10.0.0/16", "wgcorp") || !a.mb.hasIn(config.OwnTable, "10.10.0.0/16", "wgcorp") {
		t.Error("the route did not move into our table")
	}
	if !before(a.mb.log, "add 10.10.0.0/16", "del 10.10.0.0/16") || !before(a.mb.log, "addrule", "del 10.10.0.0/16") {
		t.Errorf("additions before removals: %v", a.mb.log)
	}
	if len(a.store.state().Rules) != 1 {
		t.Errorf("rules: %+v", a.store.state().Rules)
	}
	// the client goes away: back to main, the rule is removed before the old routes
	a.mb.rules = a.mb.rules[:0:0]
	a.mb.rules = append(a.mb.rules, OSRule{Pref: rulePrefBase, Table: config.OwnTable, Suppress: -1, ToTable: true, Ours: true})
	a.mb.reset()
	a.apply(t, cfg)
	if !a.mb.has("10.10.0.0/16", "wgcorp") || a.mb.hasIn(config.OwnTable, "10.10.0.0/16", "wgcorp") || len(a.mb.rules) != 0 {
		t.Errorf("not back in main: %v %v", a.mb.routes, a.mb.rules)
	}
	if !before(a.mb.log, "delrule", "del ") {
		t.Errorf("the rule goes before the routes: %v", a.mb.log)
	}
}

// Somebody else uses our table: the next free one of 247-250 is taken (the number
// is in the journal with every route and the rule).
func TestApplyTakesTheNextFreeTable(t *testing.T) {
	a := newApplyRig(t)
	a.withSingBox()
	a.mb.routes = append(a.mb.routes, OSRoute{Dest: netip.MustParsePrefix("172.31.0.0/16"), Iface: "eth0", Table: config.OwnTable})
	a.apply(t, testCfg())
	st := a.store.state()
	if len(st.Rules) != 1 || st.Rules[0].Table != 248 {
		t.Fatalf("rules %+v", st.Rules)
	}
	if a.mb.has("10.10.0.0/16", "wgcorp") || !a.mb.hasIn(248, "10.10.0.0/16", "wgcorp") {
		t.Error("the route did not go into table 248")
	}
	for _, r := range st.Routes {
		if (r.Via == ViaCorp || r.Via == ViaDirect) && r.Table != 248 {
			t.Errorf("%+v", r)
		}
	}
	// a rule of somebody else that looks into 248 takes it away as well
	a2 := newApplyRig(t)
	a2.withSingBox()
	a2.mb.routes = append(a2.mb.routes, OSRoute{Dest: netip.MustParsePrefix("172.31.0.0/16"), Iface: "eth0", Table: 247})
	a2.mb.rules = append(a2.mb.rules, OSRule{Pref: 100, Table: 248, Suppress: -1, ToTable: true, Src: netip.MustParsePrefix("10.0.0.0/8")})
	a2.apply(t, testCfg())
	if st := a2.store.state(); len(st.Rules) != 1 || st.Rules[0].Table != 249 {
		t.Errorf("rules %+v", st.Rules)
	}
}

// Every table of 247-250 is in use: the routes stay in main.
func TestApplyKeepsMainWhenAllOwnTablesAreTaken(t *testing.T) {
	a := newApplyRig(t)
	a.withSingBox()
	for tb := config.OwnTable; tb <= config.OwnTableLast; tb++ {
		a.mb.routes = append(a.mb.routes, OSRoute{Dest: netip.MustParsePrefix("172.31.0.0/16"), Iface: "eth0", Table: tb})
	}
	out := a.apply(t, testCfg())
	if !a.mb.has("10.10.0.0/16", "wgcorp") || len(a.store.state().Rules) != 0 || !strings.Contains(out, "used by something else") {
		t.Errorf("rules %+v\n%s", a.store.state().Rules, out)
	}
}

// wg-quick: the main table is consulted first for anything but the default
// route (suppress_prefixlength 0): our routes need no rules, and the home
// client keeps the default.
func TestApplyWgQuickNeedsNoRules(t *testing.T) {
	a := newApplyRig(t)
	a.mb.rules = []OSRule{
		{Pref: 0, Table: 255, Suppress: -1, ToTable: true},
		{Pref: 32764, Table: RuleTableMain, Suppress: 0, ToTable: true},
		{Pref: 32765, Table: 51820, Suppress: -1, ToTable: true, Fwmark: true, Inv: true},
		{Pref: 32766, Table: RuleTableMain, Suppress: -1, ToTable: true},
	}
	a.mb.routes = append(a.mb.routes, OSRoute{Dest: netip.MustParsePrefix("0.0.0.0/0"), Iface: "wghome", Table: 51820})
	a.apply(t, testCfg())
	if a.mb.ruleAdds != 0 || len(a.store.state().Rules) != 0 {
		t.Error("rules are not needed with suppress_prefixlength 0")
	}
	if a.mb.has("0.0.0.0/1", "wghome") {
		t.Error("the client's own default route is used: 0/1 must not be added")
	}
	if !a.mb.has("10.10.0.0/16", "wgcorp") {
		t.Error("corp route missing")
	}
}

// A route that takes the place of one of ours (the corp adapter changed its
// gateway) replaces it in one step where the OS can (Linux), and by add, then
// remove, elsewhere. The old route is never removed before the new one exists.
func TestApplyReplacesInsteadOfRemovingFirst(t *testing.T) {
	for _, plain := range []bool{false, true} {
		a := newApplyRig(t)
		if plain {
			a.m.b = plainBackend{a.mb}
		}
		cfg := testCfg()
		cfg.Networks = []string{"10.10.0.0/16"}
		cfg.CorpGateway = ""
		a.apply(t, cfg)
		a.mb.reset()
		cfg.CorpGateway = "10.200.0.254" // the same prefix and metric, another next hop
		a.apply(t, cfg)
		n := 0
		for _, r := range a.mb.routes {
			if r.Dest == netip.MustParsePrefix("10.10.0.0/16") {
				n++
				if r.Gateway != netip.MustParseAddr("10.200.0.254") {
					t.Errorf("plain=%v: old route is still there: %+v", plain, r)
				}
			}
		}
		if n != 1 {
			t.Errorf("plain=%v: %d routes to 10.10.0.0/16", plain, n)
		}
		if !plain && a.mb.replaces != 1 {
			t.Errorf("Linux path: %d replaces\n%v", a.mb.replaces, a.mb.log)
		}
		for _, r := range a.store.state().Routes {
			if r.Dest == "10.10.0.0/16" && r.Gateway != "10.200.0.254" {
				t.Errorf("plain=%v: journal still has the old route: %+v", plain, r)
			}
		}
	}
}

// If the new route cannot be created, the old one stays, in the OS and in the journal.
func TestApplyKeepsStaleRouteWhenTheAdditionFails(t *testing.T) {
	for _, plain := range []bool{false, true} {
		a := newApplyRig(t)
		if plain {
			a.m.b = plainBackend{a.mb}
		}
		cfg := testCfg()
		cfg.Networks = []string{"10.10.0.0/16"}
		a.apply(t, cfg)
		a.mb.reset()
		cfg.CorpGateway = "10.200.0.254"
		a.mb.failAdd["10.10.0.0/16"] = errors.New("boom")
		out := a.apply(t, cfg)
		var old bool
		for _, r := range a.mb.routes {
			old = old || (r.Dest == netip.MustParsePrefix("10.10.0.0/16") && !r.Gateway.IsValid())
		}
		if !old {
			t.Errorf("plain=%v: the old route was removed although the new one failed\n%s", plain, out)
		}
		found := false
		for _, r := range a.store.state().Routes {
			found = found || (r.Dest == "10.10.0.0/16" && r.Gateway == "")
		}
		if !found {
			t.Errorf("plain=%v: the old route is not in the journal any more", plain)
		}
	}
}

// A route that is in the way and is not ours stays, and so does ours.
func TestApplyReplaceWontTouchForeignRoute(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	cfg.Networks = []string{"10.10.0.0/16"}
	a.apply(t, cfg)
	// the route in the table is a client's now (same prefix and metric, not ours)
	a.mb.mu.Lock()
	for i := range a.mb.routes {
		if a.mb.routes[i].Dest == netip.MustParsePrefix("10.10.0.0/16") {
			a.mb.routes[i].Ours, a.mb.routes[i].NotOurs = false, true
		}
	}
	a.mb.mu.Unlock()
	cfg.CorpGateway = "10.200.0.254"
	a.apply(t, cfg)
	for _, r := range a.mb.routes {
		if r.Dest == netip.MustParsePrefix("10.10.0.0/16") && (r.Gateway.IsValid() || r.Ours || !r.NotOurs) {
			t.Errorf("the client's route was changed: %+v", r)
		}
	}
}

// An apply that was cut short leaves a pending journal. If the table cannot be
// read the next apply cannot know what exists: it creates the entries again,
// and a route that is there already (ours) stays in the journal.
func TestPendingJournalWithUnknownTableCreatesAgain(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	a.apply(t, cfg)
	// the apply "died" after the first half
	st := a.store.state()
	st.Sig = pendingSig
	a.store = newMemStore(st)
	a.m.store = a.store
	// two of the routes were never created
	a.mb.mu.Lock()
	var left []OSRoute
	for _, r := range a.mb.routes {
		if r.Dest != netip.MustParsePrefix("10.10.0.0/16") && r.Dest != netip.MustParsePrefix("128.0.0.0/1") {
			left = append(left, r)
		}
	}
	a.mb.routes = left
	a.mb.mu.Unlock()
	a.mb.routesErr = errors.New("cannot read the table")
	a.mb.reset()
	out := a.apply(t, cfg)
	if !a.mb.has("10.10.0.0/16", "wgcorp") || !a.mb.has("128.0.0.0/1", "wghome") {
		t.Errorf("routes that were never created are not created:\n%s", out)
	}
	if got := len(a.store.state().Routes); got != 5 {
		t.Errorf("journal has %d routes, want 5 (the ones that existed stay in it)\n%s", got, out)
	}
	if a.store.state().Sig == pendingSig {
		t.Error("the apply is over")
	}
	a.mb.routesErr = nil
	rep, err := a.s.Cleanup(time.Second)
	if err != nil || rep.Routes != 5 || a.mb.count() != 0 {
		t.Errorf("cleanup: %+v %v, %d left", rep, err, a.mb.count())
	}
}

// EEXIST on a journal entry means a route of ours is there already only if it
// has our key and tag: then it stays in the journal. A client's is not journaled.
func TestExistingJournalRouteIsKeptOnlyIfOurs(t *testing.T) {
	for _, ours := range []bool{true, false} {
		a := newApplyRig(t)
		cfg := testCfg()
		cfg.Networks = []string{"10.10.0.0/16"}
		a.apply(t, cfg)
		st := a.store.state()
		st.Sig = pendingSig
		if !ours { // the route in the table is a client's, with the same key
			a.mb.mu.Lock()
			for i := range a.mb.routes {
				if a.mb.routes[i].Dest == netip.MustParsePrefix("10.10.0.0/16") {
					a.mb.routes[i].Ours, a.mb.routes[i].NotOurs = false, true
				}
			}
			a.mb.mu.Unlock()
		}
		a.store = newMemStore(st)
		a.m.store = a.store
		// the diff is made from a read that does not show the route; the add then fails with EEXIST
		tbl, rs := a.m.readTables()
		delete(tbl.byKey, keyOf(config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", Metric: ownMetric}))
		p := a.m.buildPlan(cfg, *a.env, st, tbl, rs, &discard{})
		var out strings.Builder
		if err := a.m.reconcile(st, p, tbl, rs, "sig", false, &out); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range a.store.state().Routes {
			found = found || r.Dest == "10.10.0.0/16"
		}
		if found != ours {
			t.Errorf("ours=%v: in the journal=%v\n%s", ours, found, out.String())
		}
	}
}

type discard struct{}

func (discard) Write(b []byte) (int, error) { return len(b), nil }

// Failures of AddResolver are failures; "already there" is not.
func TestResolverFailuresAreCounted(t *testing.T) {
	a := newApplyRig(t)
	a.m.dnsOf = corpOnly([]string{"10.200.0.1"}, []string{"corp.example"})
	rb := &resolverBackend{memBackend: a.mb}
	a.m.b = rb
	cfg := testCfg()
	cfg.SplitDNS = true
	tbl, rs := a.m.readTables()
	if a.m.buildPlan(cfg, *a.env, &config.State{}, tbl, rs, &discard{}).dns == nil {
		t.Skip("this OS has no per-domain DNS here (systemd-resolved)")
	}
	rb.err = errors.New("resolvectl exploded")
	out := a.apply(t, cfg)
	if !strings.Contains(out, "1 failed") || !strings.Contains(out, "resolvectl exploded") {
		t.Errorf("a failed DNS entry must count as failed:\n%s", out)
	}
	if len(a.store.state().Resolvers) != 0 {
		t.Error("a failed entry is journaled")
	}
	rb.err = errResolverExists
	a.mb.reset()
	cfg.Networks = append(cfg.Networks, "192.0.2.0/24") // forces an apply
	out = a.apply(t, cfg)
	if !strings.Contains(out, " 0 failed") {
		t.Errorf("an entry that exists is no failure:\n%s", out)
	}
}

type resolverBackend struct {
	*memBackend
	err error
}

func (r *resolverBackend) AddResolver(string, []string) error { return r.err }

// Orphans of ours with a metric that is not ours are left alone; with ours they go.
func TestOrphansNeedOurMetric(t *testing.T) {
	tbl := newTable([]OSRoute{
		{Dest: netip.MustParsePrefix("10.1.0.0/16"), Iface: "wgcorp", Ours: true, Metric: 0},
		{Dest: netip.MustParsePrefix("10.2.0.0/16"), Iface: "wgcorp", Ours: true, Metric: ownMetric},
		{Dest: netip.MustParsePrefix("10.3.0.0/16"), Iface: "wgcorp", Ours: true, Metric: ownMetric, Table: config.OwnTable},
		{Dest: netip.MustParsePrefix("10.4.0.0/16"), Iface: "wgcorp", Ours: false, Metric: ownMetric},
		{Dest: netip.MustParsePrefix("10.5.0.0/16"), Iface: "wgcorp", Ours: true, Metric: ownMetric, Table: 2022},
	})
	got := tbl.taggedOurs()
	if len(got) != 2 || got[0].Dest != netip.MustParsePrefix("10.2.0.0/16") || got[1].Table != config.OwnTable {
		t.Fatalf("%+v", got)
	}
	// and what is made of them for removal is exact: metric as is, tagged, in the right table
	r := got[1].toRoute()
	if r.Legacy() || r.Table != config.OwnTable || r.EffMetric() != ownMetric {
		t.Errorf("%+v", r)
	}
}

// A metric 0 route with our tag is never "legacy": makeDiff does not list it for removal.
func TestMakeDiffSkipsOrphanWithMetricZero(t *testing.T) {
	if !routesTagged {
		t.Skip("this OS does not tag routes")
	}
	tbl := newTable([]OSRoute{{Dest: netip.MustParsePrefix("10.1.0.0/16"), Iface: "wgcorp", Ours: true, Metric: 0}})
	d := makeDiff(&config.State{}, &plan{}, tbl, &ruleSet{}, false)
	if len(d.del) != 0 {
		t.Errorf("%+v", d.del)
	}
}

// Drifted looks at the DNS entries too, but not on every call.
func TestDriftedChecksDNSRarely(t *testing.T) {
	mb := newMemBackend()
	st := &config.State{Resolvers: []string{testResolver("corp.example")}}
	mb.missingRes = st.Resolvers
	dnsCheck.mu.Lock()
	dnsCheck.last = time.Time{}
	dnsCheck.mu.Unlock()
	if !drifted(mb, st) {
		t.Fatal("a missing DNS entry is drift")
	}
	if drifted(mb, st) {
		t.Error("the DNS entries are looked at once in dnsCheckEvery")
	}
	dnsCheck.mu.Lock()
	dnsCheck.last = time.Now().Add(-2 * dnsCheckEvery)
	dnsCheck.mu.Unlock()
	if !drifted(mb, st) {
		t.Error("and again after that")
	}
	mb.missingRes = nil
	dnsCheck.mu.Lock()
	dnsCheck.last = time.Time{}
	dnsCheck.mu.Unlock()
	if drifted(mb, st) {
		t.Error("nothing is missing")
	}
	if drifted(plainBackend{mb}, st) {
		t.Error("a backend that cannot tell reports no drift")
	}
}

// A DNS entry removed behind our back is made again by the next apply.
func TestApplyRestoresMissingDNS(t *testing.T) {
	a := newApplyRig(t)
	a.m.dnsOf = corpOnly([]string{"10.200.0.1"}, []string{"corp.example"})
	cfg := testCfg()
	cfg.SplitDNS = true
	a.apply(t, cfg)
	if len(a.store.state().Resolvers) == 0 {
		t.Skip("this OS has no per-domain DNS here (systemd-resolved)")
	}
	a.mb.missingRes = a.store.state().Resolvers[:1]
	out := a.apply(t, cfg)
	if !strings.Contains(out, "DNS entries missing") || !strings.Contains(out, "corp DNS") {
		t.Errorf("not restored:\n%s", out)
	}
}

func TestSigIgnoresTheOrderOfAddresses(t *testing.T) {
	cfg := testCfg()
	e := *testEnv()
	e.Home.Addrs = []string{"10.201.0.2", "10.201.0.3"}
	e2 := e
	e2.Home.Addrs = []string{"10.201.0.3", "10.201.0.2"}
	if Sig(cfg, e) != Sig(cfg, e2) {
		t.Error("the same addresses in another order must give the same Sig")
	}
}

func TestIfaceByName(t *testing.T) {
	if _, found, err := ifaceByName("no-such-adapter-7f3a"); err != nil || found {
		t.Errorf("found=%v err=%v", found, err)
	}
}
