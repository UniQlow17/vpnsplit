package router

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func main(dest, iface string) OSRoute {
	return OSRoute{Dest: netip.MustParsePrefix(dest), Iface: iface}
}

func TestPlanPins(t *testing.T) {
	gw := Gateway{Iface: "eth0", Router: "192.168.1.1"}
	server := netip.MustParseAddr("198.51.100.7")

	// a client pinned its server itself: nothing to add; the corp rule over it is not applied
	tbl := newTable([]OSRoute{main("198.51.100.7/32", "eth0")})
	pins, drop, warns := planPins(gw, true, tbl, []netip.Addr{server}, pfx("198.51.100.0/24", "10.0.0.0/8"), true)
	if len(pins) != 0 || !drop[netip.MustParsePrefix("198.51.100.0/24")] || drop[netip.MustParsePrefix("10.0.0.0/8")] || len(warns) != 1 {
		t.Errorf("pinned: %v %v %v", pins, drop, warns)
	}

	// not pinned, the halves are in use: a /32 through the physical gateway; the covering corp rule is dropped as well
	pins, drop, _ = planPins(gw, true, newTable(nil), []netip.Addr{server}, pfx("198.51.100.0/24"), true)
	if len(pins) != 1 || pins[0].Dest != "198.51.100.7/32" || pins[0].Gateway != "192.168.1.1" || pins[0].Iface != "eth0" || pins[0].Via != ViaPin || !drop[netip.MustParsePrefix("198.51.100.0/24")] {
		t.Errorf("not pinned: %+v %v", pins, drop)
	}

	// without the halves nothing is pinned, but a corp rule over the server is still not applied
	pins, drop, warns = planPins(gw, true, newTable(nil), []netip.Addr{server}, pfx("198.51.100.0/24"), false)
	if len(pins) != 0 || !drop[netip.MustParsePrefix("198.51.100.0/24")] || len(warns) != 1 {
		t.Errorf("no halves: %+v %v %v", pins, drop, warns)
	}

	// a pin through a VPN adapter is not a pin
	pins, _, _ = planPins(gw, true, newTable([]OSRoute{main("198.51.100.7/32", "wgcorp")}), []netip.Addr{server}, nil, true)
	if len(pins) != 1 {
		t.Errorf("a host route through a tunnel must not count as pinned: %+v", pins)
	}

	// cannot pin (no gateway): nothing to add, the rules over the server go
	pins, drop, warns = planPins(gw, false, newTable(nil), []netip.Addr{server}, pfx("198.51.100.0/24", "10.0.0.0/8"), true)
	if len(pins) != 0 || !drop[netip.MustParsePrefix("198.51.100.0/24")] || drop[netip.MustParsePrefix("10.0.0.0/8")] || len(warns) != 1 {
		t.Errorf("cannot pin: %v %v %v", pins, drop, warns)
	}

	// a corp rule for the server's own host route is not applied
	_, drop, warns = planPins(gw, true, newTable(nil), []netip.Addr{server}, pfx("198.51.100.7/32"), true)
	if !drop[netip.MustParsePrefix("198.51.100.7/32")] || len(warns) == 0 {
		t.Errorf("host rule: %v %v", drop, warns)
	}
}

func viaGW(dest, iface, gw string) OSRoute {
	r := main(dest, iface)
	r.Gateway = netip.MustParseAddr(gw)
	return r
}

func TestEndpointCandidates(t *testing.T) {
	e := *testEnv()
	st := &config.State{Routes: []config.Route{{Dest: "198.18.9.9/32", Iface: "eth0", Gateway: "192.168.1.1", Via: ViaPin}}}
	tbl := newTable([]OSRoute{
		viaGW("198.18.2.2/32", "eth0", "192.168.1.1"), // the client pinned its server
		viaGW("198.18.1.2/32", "eth0", "192.168.1.1"),
		viaGW("198.18.2.2/32", "eth0", "192.168.1.1"),   // twice: once
		viaGW("192.168.1.1/32", "eth0", "192.168.1.1"),  // the gateway itself
		viaGW("198.18.9.9/32", "eth0", "192.168.1.1"),   // our own pin
		viaGW("203.0.113.1/32", "wgcorp", "10.200.0.1"), // through a tunnel
		viaGW("10.0.0.0/8", "eth0", "192.168.1.1"),      // not a host route
		main("198.18.7.7/32", "eth0"),                   // on-link: DHCP's own host routes
	})
	got := endpointCandidates(e, tbl, st)
	if len(got) != 2 || got[0] != netip.MustParseAddr("198.18.1.2") || got[1] != netip.MustParseAddr("198.18.2.2") {
		t.Errorf("%v", got)
	}
	if endpointCandidates(e, &table{}, st) != nil {
		t.Error("an unreadable table has no candidates")
	}
}

// A corp network over a pinned server is not applied, whether or not the halves are used.
func TestPlanDropsCorpRuleOverEndpoint(t *testing.T) {
	for _, home := range []bool{false, true} {
		a := newApplyRig(t)
		a.env.HomeOK = home
		a.mb.routes = append(a.mb.routes, viaGW("198.18.2.2/32", "eth0", "192.168.1.1"), viaGW("198.18.1.2/32", "eth0", "192.168.1.1"))
		cfg := testCfg()
		cfg.Networks = []string{"10.10.0.0/16", "198.18.0.0/16"}
		out := a.apply(t, cfg)
		if a.mb.has("198.18.0.0/16", "wgcorp") || !a.mb.has("10.10.0.0/16", "wgcorp") {
			t.Errorf("home=%v: the corp network over the endpoints must not be applied, the other must\n%s", home, out)
		}
		if !strings.Contains(out, "covers 198.18.1.2") || !strings.Contains(out, "covers 198.18.2.2") {
			t.Errorf("home=%v: no warning:\n%s", home, out)
		}
	}
}

func TestPinnedHosts(t *testing.T) {
	tbl := newTable([]OSRoute{main("198.51.100.7/32", "eth0"), main("203.0.113.1/32", "wgcorp"), main("10.0.0.0/8", "eth0")})
	if n := pinnedHosts(tbl); n != 1 {
		t.Errorf("pinned %d", n)
	}
	if n := pinnedHosts(&table{}); n != 0 {
		t.Errorf("unknown table: %d", n)
	}
}

func TestPlanRules(t *testing.T) {
	prefixes := pfx("10.10.0.0/16", "203.0.113.11/32")
	sing := OSRule{Pref: 9000, Table: 2022, Suppress: -1, ToTable: true, Fwmark: true, Inv: true}
	mainRule := OSRule{Pref: 32766, Table: RuleTableMain, Suppress: -1, ToTable: true}
	local := OSRule{Pref: 0, Table: 255, Suppress: -1, ToTable: true}
	want := func(pref int) []config.Rule { return []config.Rule{{Table: config.OwnTable, Pref: pref}} }

	if r, _ := planRules([]OSRule{local, mainRule}, prefixes); len(r) != 0 {
		t.Errorf("no client rules: %v", r)
	}
	r, note := planRules([]OSRule{local, sing, mainRule}, prefixes)
	if len(r) != 1 || r[0] != want(5000)[0] || note == "" {
		t.Errorf("sing-box: %v %q", r, note)
	}
	// Tailscale-like: the client's rules start before the default base
	ts := OSRule{Pref: 5270, Table: 52, Suppress: -1, ToTable: true}
	if r, _ := planRules([]OSRule{ts}, prefixes); len(r) != 1 || r[0].Pref != 5000 {
		t.Errorf("tailscale: %v", r)
	}
	early := OSRule{Pref: 100, Table: 77, Suppress: -1, ToTable: true}
	if r, _ := planRules([]OSRule{early, sing}, prefixes); len(r) != 1 || r[0].Pref != 99 {
		t.Errorf("early client rule: %v", r)
	}
	if r, note := planRules([]OSRule{{Pref: 1, Table: 77, Suppress: -1, ToTable: true}}, prefixes); len(r) != 0 || !strings.Contains(note, "cannot be overtaken") {
		t.Errorf("pref 1: %v %q", r, note)
	}
	// wg-quick: lookup main suppress_prefixlength 0 before the client's rule
	wgMain := OSRule{Pref: 32764, Table: RuleTableMain, Suppress: 0, ToTable: true}
	wgTbl := OSRule{Pref: 32765, Table: 51820, Suppress: -1, ToTable: true, Fwmark: true, Inv: true}
	if r, note := planRules([]OSRule{wgMain, wgTbl, mainRule}, prefixes); len(r) != 0 || note == "" {
		t.Errorf("wg-quick: %v %q", r, note)
	}
	// suppress_prefixlength 24 would hide a /16
	hide := OSRule{Pref: 32764, Table: RuleTableMain, Suppress: 24, ToTable: true}
	if r, _ := planRules([]OSRule{hide, wgTbl}, prefixes); len(r) != 1 {
		t.Errorf("suppress 24: %v", r)
	}
	// a main lookup with a selector does not make main visible for everything
	mainMark := OSRule{Pref: 32764, Table: RuleTableMain, Suppress: 0, ToTable: true, Fwmark: true}
	if r, _ := planRules([]OSRule{mainMark, wgTbl}, prefixes); len(r) != 1 {
		t.Errorf("main with a mark: %v", r)
	}
	// our own rules, rules for one source or destination and rules with a selector do not divert
	ours := OSRule{Pref: 5000, Table: config.OwnTable, Suppress: -1, ToTable: true, Ours: true}
	fromSrc := OSRule{Pref: 100, Table: 77, Suppress: -1, ToTable: true, Src: netip.MustParsePrefix("10.9.0.0/16")}
	positiveMark := OSRule{Pref: 100, Table: 77, Suppress: -1, ToTable: true, Fwmark: true}
	uid := OSRule{Pref: 100, Table: 77, Suppress: -1, ToTable: true, OtherSel: true}
	for name, rl := range map[string]OSRule{"ours": ours, "from src": fromSrc, "positive fwmark": positiveMark, "uidrange": uid} {
		if r, _ := planRules([]OSRule{rl, mainRule}, prefixes); len(r) != 0 {
			t.Errorf("%s does not divert, but: %v", name, r)
		}
	}
}

func TestCaptured(t *testing.T) {
	sing := OSRule{Pref: 9000, Table: 2022, Suppress: -1, ToTable: true, Fwmark: true, Inv: true}
	tbl := newTable([]OSRoute{{Dest: netip.MustParsePrefix("0.0.0.0/0"), Iface: "wghome", Table: 2022}})
	if n, ok := captured([]OSRule{sing}, tbl, "wghome"); !ok || n != 2022 {
		t.Errorf("%d %v", n, ok)
	}
	if _, ok := captured([]OSRule{sing}, tbl, "wgcorp"); ok {
		t.Error("the table's default goes through another adapter")
	}
	// a rule that sends only some traffic (a positive mark, a uid range) does not capture everything
	narrow := sing
	narrow.Inv = false
	if _, ok := captured([]OSRule{narrow}, tbl, "wghome"); ok {
		t.Error("fwmark X lookup T sends only the marked packets")
	}
	narrow = sing
	narrow.Fwmark, narrow.Inv, narrow.OtherSel = false, false, true
	if _, ok := captured([]OSRule{narrow}, tbl, "wghome"); ok {
		t.Error("a uid range sends only some users' packets")
	}
	if _, ok := captured(nil, tbl, "wghome"); ok {
		t.Error("no rules: not captured")
	}
	if _, ok := captured([]OSRule{sing}, &table{}, "wghome"); ok {
		t.Error("unknown table: not captured")
	}
}

func TestGatewayFrom(t *testing.T) {
	g := func(iface, gw string, metric, ifm int) OSRoute {
		return OSRoute{Dest: netip.MustParsePrefix("0.0.0.0/0"), Iface: iface, Gateway: netip.MustParseAddr(gw), Metric: metric, IfMetric: ifm}
	}
	rs := []OSRoute{g("wghome", "10.201.0.1", 0, 1), g("Wi-Fi", "192.168.1.1", 0, 40), g("Ethernet", "192.168.0.1", 0, 25),
		{Dest: netip.MustParsePrefix("0.0.0.0/0"), Iface: "Ethernet 2"}} // on-link default: no gateway
	if gw, ok := gatewayFrom(rs); !ok || gw != (Gateway{Iface: "Ethernet", Router: "192.168.0.1"}) {
		t.Errorf("%+v %v", gw, ok)
	}
	if _, ok := gatewayFrom(rs[:1]); ok {
		t.Error("a VPN-only default is not a physical gateway")
	}
}

// The plan, not the OS: pins appear in a plan with 0/1 and a warning tells
// that the endpoint is not pinned.
func TestPlanWarnsWhenNothingIsPinned(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	out := a.apply(t, cfg)
	if !strings.Contains(out, "endpoint not pinned") {
		t.Errorf("no warning:\n%s", out)
	}
	// the client pinned its server: no warning
	a2 := newApplyRig(t)
	a2.mb.routes = append(a2.mb.routes, main("198.18.2.2/32", "eth0"))
	if out := a2.apply(t, cfg); strings.Contains(out, "endpoint not pinned") {
		t.Errorf("warned although the server is pinned:\n%s", out)
	}
}

func TestPlanDedupAndCanonical(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	cfg.Networks = []string{"10.10.0.5/16", "10.10.0.0/16"} // the same prefix twice
	cfg.DirectNetworks = []string{"10.10.0.0/16"}           // and in the other list
	var w bytes.Buffer
	p := a.m.buildPlan(cfg, *a.env, &config.State{}, &table{}, &ruleSet{}, &w)
	n := 0
	for _, r := range p.routes {
		if r.Dest == "10.10.0.0/16" {
			n++
			if r.Via != ViaCorp {
				t.Errorf("corp must win: %+v", r)
			}
		}
	}
	if n != 1 || !strings.Contains(w.String(), "both corp and direct") {
		t.Errorf("%d routes, output %q", n, w.String())
	}
	_ = config.Route{}
}

func TestBootstrapPlan(t *testing.T) {
	e := *testEnv()
	cfg := testCfg()
	if bootstrapPlan(cfg, e, &table{}, &ruleSet{}) != nil {
		t.Error("no corp domains: nothing to resolve, nothing to bootstrap")
	}
	cfg.CorpDNS, cfg.Domains = "10.200.0.1", []string{"corp.example"}
	p := bootstrapPlan(cfg, e, &table{}, &ruleSet{known: true})
	if p == nil || len(p.routes) != 1 || p.routes[0].Dest != "10.200.0.1/32" || p.routes[0].Iface != "wgcorp" || p.routes[0].Via != ViaCorp {
		t.Fatalf("%+v", p)
	}
	rs := newRuleSet([]OSRule{{Pref: 9000, Table: 2022, Suppress: -1, ToTable: true, Fwmark: true, Inv: true}})
	if p = bootstrapPlan(cfg, e, &table{}, rs); len(p.rules) != 1 || p.rules[0].Table != config.OwnTable || p.rules[0].Pref != rulePrefBase || p.routes[0].Table != config.OwnTable {
		t.Errorf("the DNS must be reachable past the client's rule: %+v", p.rules)
	}
	e.CorpOK = false
	if bootstrapPlan(cfg, e, &table{}, rs) != nil {
		t.Error("corp is not connected")
	}
}

// The bootstrap adds only what it needs and removes nothing the journal has
// from an earlier apply; the full plan then finds the DNS route in place.
func TestPartialReconcileKeepsTheRest(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	a.apply(t, cfg)
	a.mb.reset()
	st := a.store.state()
	tbl, rs := a.m.readTables()
	bp := &plan{routes: []config.Route{{Dest: "10.200.0.1/32", Iface: "wgcorp", Via: ViaCorp, Metric: ownMetric}}}
	if err := a.m.reconcile(st, bp, tbl, rs, pendingSig, true, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if a.mb.dels != 0 || a.mb.adds != 1 {
		t.Errorf("adds %d dels %d", a.mb.adds, a.mb.dels)
	}
	after := a.store.state()
	if len(after.Routes) != len(st.Routes)+1 || after.Sig != pendingSig {
		t.Errorf("journal: %d routes, sig %q", len(after.Routes), after.Sig)
	}
	// the full apply that follows has nothing left to do for it
	a.mb.reset()
	cfg.Networks = append(cfg.Networks, "10.200.0.1/32")
	a.apply(t, cfg)
	if a.mb.adds != 0 {
		t.Errorf("the route of the bootstrap was added again: %d", a.mb.adds)
	}
}
