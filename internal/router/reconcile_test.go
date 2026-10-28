package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

func testEnv() *Env {
	return &Env{
		Corp: netif.Info{Name: "wgcorp", Index: 5, Addrs: []string{"10.200.0.2"}}, CorpOK: true,
		Home: netif.Info{Name: "wghome", Index: 6, Addrs: []string{"10.201.0.2"}}, HomeOK: true,
		GW: Gateway{Iface: "eth0", Router: "192.168.1.1"}, GWOK: true,
	}
}

func testCfg() *config.Config {
	cfg := config.New()
	cfg.SplitDNS = false
	cfg.Networks = []string{"10.10.0.0/16", "203.0.113.11/32"}
	cfg.DirectNetworks = []string{"203.0.113.12/32"}
	return cfg
}

// applyRig is a Manager over memBackend with a fixed Env.
type applyRig struct {
	*rig
	mb  *memBackend
	env *Env
	s   *Session
}

func newApplyRig(t *testing.T) *applyRig { return newApplyRigWith(t, nil) }

// newApplyRigWith is newApplyRig with the table seeded before the session starts
// (the state the snapshot records).
func newApplyRigWith(t *testing.T, seed func(*memBackend)) *applyRig {
	t.Helper()
	return newApplyRigOS(t, "", seed)
}

// newApplyRigOS is newApplyRigWith for the rules of the OS goos ("": this one):
// they decide what is taken for ours when the snapshot is made and compared.
func newApplyRigOS(t *testing.T, goos string, seed func(*memBackend)) *applyRig {
	t.Helper()
	mb := newMemBackend()
	if seed != nil {
		seed(mb)
	}
	r := &rig{
		b:     &fakeBackend{failRoute: map[string]error{}},
		store: newMemStore(nil),
		procs: &fakeProcs{self: config.Owner{PID: 100, Start: 5000, Boot: "boot-2"}, alive: map[int]int64{100: 5000}},
		lock:  &fakeLock{},
	}
	r.m = newManager(mb, r.store, r.procs, r.lock.take)
	r.m.providerOf = func() map[string]string { return map[string]string{} } // no VPN client anywhere
	if goos != "" {
		r.m.goos = goos
	}
	ar := &applyRig{rig: r, mb: mb, env: testEnv()}
	r.m.detect = func(*config.Config) Env { return *ar.env }
	r.m.dnsOf = func(string) ([]string, []string) { return nil, nil }
	ar.s, _ = acquire(t, r, config.ModeSession)
	return ar
}

func (a *applyRig) apply(t *testing.T, cfg *config.Config) string {
	t.Helper()
	var w bytes.Buffer
	if err := a.m.Apply(cfg, &w); err != nil {
		t.Fatalf("Apply: %v\n%s", err, w.String())
	}
	return w.String()
}

func TestApplyBuildsTheRoutes(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	a.apply(t, cfg)
	for _, c := range []struct{ dest, iface string }{
		{"10.10.0.0/16", "wgcorp"}, {"203.0.113.11/32", "wgcorp"}, {"203.0.113.12/32", "eth0"},
		{"0.0.0.0/1", "wghome"}, {"128.0.0.0/1", "wghome"},
	} {
		if !a.mb.has(c.dest, c.iface) {
			t.Errorf("%s via %s is not in the table", c.dest, c.iface)
		}
	}
	st := a.store.state()
	if len(st.Routes) != 5 || st.Sig != Sig(cfg, *a.env) || st.Mode != config.ModeSession || st.Owner == nil {
		t.Errorf("journal: %+v", st)
	}
	for _, r := range st.Routes {
		if r.Metric != ownMetric {
			t.Errorf("route %s has metric %d in the journal, want %d", r.Dest, r.Metric, ownMetric)
		}
	}
	if st.Routes[len(st.Routes)-1].Via != ViaHome {
		t.Errorf("the home halves must come last, after the pins and the rules: %+v", st.Routes)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	a.apply(t, cfg)
	a.mb.reset()
	saves := a.store.saves
	out := a.apply(t, cfg)
	if a.mb.adds != 0 || a.mb.dels != 0 || a.mb.ruleAdds+a.mb.ruleDels != 0 {
		t.Errorf("the second apply touched the table: %d adds, %d dels\n%s", a.mb.adds, a.mb.dels, out)
	}
	if a.store.saves != saves {
		t.Errorf("the second apply wrote the journal %d times", a.store.saves-saves)
	}
	if !strings.Contains(out, "0 added") || !strings.Contains(out, "5 unchanged") {
		t.Errorf("summary: %s", out)
	}
}

// Changing the rules changes only the routes that differ, and additions come
// before removals so that traffic is not interrupted.
func TestApplyOnlyTheDifference(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	a.apply(t, cfg)
	a.mb.reset()
	cfg.Networks = []string{"10.10.0.0/16", "192.0.2.0/24"} // 203.0.113.11 out, 192.0.2.0/24 in
	out := a.apply(t, cfg)
	if got := strings.Join(a.mb.log, ","); got != "add 192.0.2.0/24,del 203.0.113.11/32" {
		t.Errorf("table calls: %s\n%s", got, out)
	}
	if !a.mb.has("10.10.0.0/16", "wgcorp") || !a.mb.has("0.0.0.0/1", "wghome") {
		t.Error("routes that did not change must stay")
	}
	st := a.store.state()
	if len(st.Routes) != 5 || st.Sig != Sig(cfg, *a.env) {
		t.Errorf("journal: %+v", st)
	}
}

// A route that went missing (its adapter was recreated) is added again, the
// rest is left alone; Drifted says so before.
func TestApplyRestoresMissingRoutes(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	a.apply(t, cfg)
	if drifted(a.mb, a.store.state()) {
		t.Fatal("nothing is missing yet")
	}
	// the home VPN reconnects: its routes are gone with the old adapter
	a.mb.mu.Lock()
	var left []OSRoute
	for _, r := range a.mb.routes {
		if r.Iface != "wghome" {
			left = append(left, r)
		}
	}
	a.mb.routes = left
	a.mb.mu.Unlock()
	a.env.Home.Index = 9
	a.mb.idx["wghome"] = 9
	if !drifted(a.mb, a.store.state()) {
		t.Fatal("missing routes must be noticed")
	}
	if apply, _ := Sync(cfg, *a.env, a.store.state()); !apply {
		t.Error("a new index must change the Sig")
	}
	a.mb.reset()
	a.apply(t, cfg)
	if got := strings.Join(a.mb.log, ","); got != "add 0.0.0.0/1,add 128.0.0.0/1" {
		t.Errorf("table calls: %s", got)
	}
	if drifted(a.mb, a.store.state()) {
		t.Error("still missing after the restoration")
	}
}

// 2000 prefixes: the journal is written twice, not 2000 times, and it is
// written before the first route is created.
func TestApplyManyPrefixesWritesTheJournalTwice(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	cfg.Networks = nil
	for i := 0; i < 2000; i++ {
		cfg.Networks = append(cfg.Networks, fmt.Sprintf("10.%d.%d.0/24", 100+i/250, i%250))
	}
	var plannedAtFirstAdd, sigAtFirstAdd = -1, ""
	a.mb.onAdd = func(n int, _ config.Route) error {
		if n == 1 {
			st := a.store.state()
			plannedAtFirstAdd, sigAtFirstAdd = len(st.Routes), st.Sig
		}
		return nil
	}
	saves := a.store.saves
	start := time.Now()
	a.apply(t, cfg)
	el := time.Since(start)
	if n := a.store.saves - saves; n != 2 {
		t.Errorf("the journal was written %d times, want 2 (planned, done)", n)
	}
	if plannedAtFirstAdd != 2000+1+2 || sigAtFirstAdd != pendingSig {
		t.Errorf("write-ahead: the journal at the first add had %d routes, sig %q", plannedAtFirstAdd, sigAtFirstAdd)
	}
	if got := len(a.store.state().Routes); got != 2000+1+2 {
		t.Errorf("journal has %d routes", got)
	}
	if el > 5*time.Second {
		t.Errorf("2000 prefixes took %v", el)
	}
	// and the removal of all of them
	start = time.Now()
	rep, err := a.s.Cleanup(10 * time.Second)
	if err != nil || rep.Routes != 2003 {
		t.Errorf("cleanup: %+v %v", rep, err)
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Errorf("cleanup of 2000 prefixes took %v", el)
	}
	if a.mb.count() != 0 {
		t.Errorf("%d routes left", a.mb.count())
	}
}

// A crash in the middle (here: the 3rd route cannot be created and the process
// is "killed" by cancelling): the journal lists everything that may exist.
func TestApplyStoppedInTheMiddleKeepsWriteAhead(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	var snap *config.State
	a.mb.onAdd = func(n int, _ config.Route) error {
		if n == 3 {
			snap = a.store.state() // what a crash here would leave behind
			a.m.cancel()           // the program is told to exit
		}
		return nil
	}
	var w bytes.Buffer
	if err := a.m.Apply(cfg, &w); err != nil {
		t.Fatal(err)
	}
	if snap == nil || len(snap.Routes) != 5 || snap.Sig != pendingSig {
		t.Fatalf("journal at the crash: %+v", snap)
	}
	for _, r := range a.mb.routes { // everything in the table is in the journal
		found := false
		for _, j := range snap.Routes {
			found = found || keyOf(j) == r.key()
		}
		if !found {
			t.Errorf("%v is in the table, not in the journal", r)
		}
	}
	st := a.store.state()
	if st.Sig != pendingSig || len(st.Routes) != a.mb.count() {
		t.Errorf("final journal: sig %q, %d routes for %d in the table", st.Sig, len(st.Routes), a.mb.count())
	}
	rep, err := a.s.Cleanup(time.Second)
	if err != nil || rep.Routes != 3 || a.mb.count() != 0 {
		t.Errorf("cleanup: %+v %v, %d left", rep, err, a.mb.count())
	}
}

// A route a client or the OS already has is not ours: not journaled, not removed.
func TestApplyLeavesForeignRoutes(t *testing.T) {
	a := newApplyRig(t)
	foreign := config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", Metric: ownMetric}
	fr := a.mb.toOS(foreign)
	fr.Ours, fr.Proto, fr.NotOurs = false, 2, true // a client's: no tag, not our protocol
	a.mb.routes = append(a.mb.routes, fr)
	out := a.apply(t, testCfg())
	if !strings.Contains(out, "already routed") {
		t.Errorf("no note about the foreign route:\n%s", out)
	}
	for _, r := range a.store.state().Routes {
		if r.Dest == "10.10.0.0/16" {
			t.Error("a foreign route was journaled")
		}
	}
	if _, err := a.s.Cleanup(time.Second); err != nil {
		t.Fatal(err)
	}
	if !a.mb.has("10.10.0.0/16", "wgcorp") {
		t.Error("the foreign route was removed")
	}
}

// A failed route is neither journaled nor counted as in place.
func TestApplyFailedRouteIsNotJournaled(t *testing.T) {
	a := newApplyRig(t)
	a.mb.failAdd["203.0.113.12/32"] = fmt.Errorf("boom")
	out := a.apply(t, testCfg())
	if !strings.Contains(out, "boom") || !strings.Contains(out, "1 failed") {
		t.Errorf("failure not reported:\n%s", out)
	}
	for _, r := range a.store.state().Routes {
		if r.Dest == "203.0.113.12/32" {
			t.Error("journaled although it was not created")
		}
	}
}

// Routes of a journal written before the metric was recorded have metric 1
// and are removed as such.
func TestLegacyJournalRoutes(t *testing.T) {
	var st config.State
	old := `{"version":2,"routes":[{"dest":"10.10.0.0/16","iface":"wgcorp","via":"corp"},{"dest":"9.9.9.0/24","iface":"wgcorp","via":"corp","metric":3}]}`
	if err := json.Unmarshal([]byte(old), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Routes[0].Legacy() || st.Routes[0].EffMetric() != 1 || st.Routes[1].Legacy() || st.Routes[1].EffMetric() != 3 {
		t.Fatalf("%+v", st.Routes)
	}
	a := newApplyRig(t)
	legacy := st.Routes[0]
	lr := a.mb.toOS(legacy)
	lr.Ours = false // created by an older version: no tag
	a.mb.routes = append(a.mb.routes, lr)
	// a journal of that version, owned by a dead session
	a.store = newMemStore(&config.State{Version: 2, Owner: &config.Owner{PID: 4242, Start: 4000, Boot: "boot-2"}, Mode: config.ModeSession, Routes: st.Routes[:1], Sig: "x"})
	a.m.store = a.store
	a.s.release()
	_, info, err := a.m.Acquire(context.Background(), config.ModeSession, &bytes.Buffer{})
	if err != nil || info.Recovered.Routes != 1 {
		t.Fatalf("%+v %v", info, err)
	}
	if a.mb.has("10.10.0.0/16", "wgcorp") {
		t.Error("the route of the older version was not removed")
	}
	// the sanitizer keeps it too
	if w := (&config.State{Routes: st.Routes}).Sanitize(); len(w) != 0 {
		t.Errorf("%v", w)
	}
}

// An apply over a journal with a legacy entry replaces it (Windows: another
// metric) or adopts it (same key) and ends with the wanted routes only.
func TestApplyOverLegacyJournal(t *testing.T) {
	a := newApplyRig(t)
	legacy := config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: ViaCorp}
	lr := a.mb.toOS(legacy)
	lr.Ours = false
	a.mb.routes = append(a.mb.routes, lr)
	self := a.procs.Self()
	a.store = newMemStore(&config.State{Version: 2, Owner: &self, Mode: config.ModeSession, Routes: []config.Route{legacy}, Sig: "old"})
	a.m.store = a.store
	a.apply(t, testCfg())
	if !a.mb.has("10.10.0.0/16", "wgcorp") {
		t.Error("the corp network is not routed")
	}
	n := 0
	for _, r := range a.mb.routes {
		if r.Dest == netip.MustParsePrefix("10.10.0.0/16") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d routes to 10.10.0.0/16", n)
	}
	for _, r := range a.store.state().Routes {
		if r.Dest == "10.10.0.0/16" && ownMetric != 1 && r.Legacy() {
			t.Error("the legacy entry must be replaced")
		}
	}
}

// Routes of ours that the journal lost are removed (where the OS tags them).
func TestApplyRemovesOrphans(t *testing.T) {
	if !routesTagged {
		t.Skip("this OS does not tag routes")
	}
	a := newApplyRig(t)
	orphan := config.Route{Dest: "172.16.0.0/12", Iface: "wgcorp", Via: ViaCorp, Metric: ownMetric}
	a.mb.routes = append(a.mb.routes, a.mb.toOS(orphan))
	a.apply(t, testCfg())
	if a.mb.has("172.16.0.0/12", "wgcorp") {
		t.Error("the orphan stays")
	}
}

// Everything the plan needs from the OS: unknown tables are taken as the journal says.
func TestApplyWithUnreadableTable(t *testing.T) {
	a := newApplyRig(t)
	ub := &unreadable{memBackend: a.mb}
	a.m.b = ub
	cfg := testCfg()
	a.apply(t, cfg)
	a.mb.reset()
	a.apply(t, cfg)
	if a.mb.adds != 0 || a.mb.dels != 0 {
		t.Errorf("an unreadable table must not make every route 'missing': %d adds", a.mb.adds)
	}
	if drifted(ub, a.store.state()) {
		t.Error("no drift without a table")
	}
}

type unreadable struct{ *memBackend }

func (u *unreadable) Routes() ([]OSRoute, error) { return nil, ErrNoTable }

func TestSigHasIndexAndAddresses(t *testing.T) {
	cfg := testCfg()
	e := *testEnv()
	base := Sig(cfg, e)
	e2 := e
	e2.Home.Index = 7
	if Sig(cfg, e2) == base {
		t.Error("a new index must change the Sig")
	}
	e3 := e
	e3.Corp.Addrs = []string{"10.200.0.9"}
	if Sig(cfg, e3) == base {
		t.Error("a new address must change the Sig")
	}
	e4 := e
	e4.GW.Router = "192.168.1.254"
	if Sig(cfg, e4) == base {
		t.Error("a new gateway must change the Sig")
	}
	if Sig(cfg, e) != base {
		t.Error("the Sig is not stable")
	}
}

func TestSessionCleanupCountsRules(t *testing.T) {
	r := newRig(&config.State{
		Version: config.JournalVersion, Owner: &config.Owner{PID: 4242, Start: 4000, Boot: "boot-2"}, Mode: config.ModeSession,
		Routes: []config.Route{corpRoute()}, Rules: []config.Rule{{Table: config.OwnTable, Pref: 5000}}, Sig: "s",
	})
	_, info := acquire(t, r, config.ModeSession)
	if info.Recovered.Routes != 1 || info.Recovered.Rules != 1 || info.Recovered.Total() != 2 {
		t.Errorf("%+v", info.Recovered)
	}
	if !strings.Contains(info.Recovered.Describe(false), "1 policy rules") {
		t.Error(info.Recovered.Describe(false))
	}
	if !before(r.b.calls(), "rule ", "route ") {
		t.Errorf("rules go before routes: %v", r.b.calls())
	}
	if st := r.store.state(); len(st.Rules) != 0 || len(st.Routes) != 0 {
		t.Errorf("%+v", st)
	}
}
