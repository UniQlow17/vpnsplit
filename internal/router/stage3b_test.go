package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// What is no address of a host a route or a DNS entry can be made for.
func TestBadAddr(t *testing.T) {
	for a, bad := range map[string]bool{
		"127.0.0.53": true, "127.0.0.1": true, "0.0.0.0": true, "224.0.0.251": true, "169.254.10.1": true,
		"255.255.255.255": true, "198.18.0.1": true, "198.19.255.254": true, "::1": true, "fe80::1": true,
		"8.8.8.8": false, "192.168.1.1": false, "10.200.0.1": false, "1.1.1.1": false, "198.20.0.1": false,
	} {
		if got := badAddr(netip.MustParseAddr(a)) != ""; got != bad {
			t.Errorf("%s: %v, want %v", a, got, bad)
		}
	}
}

// The servers the OS reports for DNS pass the same filter: the stub of a local
// resolver, link-local, multicast and the fake-ip range are no provider's.
func TestValidServersUseTheAddressFilter(t *testing.T) {
	got := validServers([]string{"127.0.0.53", "0.0.0.0", "169.254.1.1", "224.0.0.1", "198.18.0.2", "255.255.255.255", "9.9.9.9", "192.168.1.1"})
	if strings.Join(got, ",") != "9.9.9.9,192.168.1.1" {
		t.Errorf("%v", got)
	}
}

// directRig is an applyRig whose provider DNS and lookups are set; the answers
// are what the names resolve to.
func directRig(t *testing.T, provider []string, answers map[string][]netip.Addr) (*applyRig, *lookupLog) {
	t.Helper()
	a := newApplyRig(t)
	ll := &lookupLog{answers: answers}
	a.m.lookup = ll.lookup
	a.m.physDNS = func(string) []string { return provider }
	a.m.dnsOf = func(iface string) ([]string, []string) {
		switch iface {
		case "wgcorp":
			return []string{"10.200.0.1"}, nil
		case "wghome":
			return []string{"10.201.0.1"}, nil
		}
		return nil, nil
	}
	return a, ll
}

// A provider's DNS that is the DNS of the corp VPN or of the home VPN gets no
// /32 around the tunnel, a note says so, and the names that go direct are asked
// of the system resolver instead.
func TestProviderDNSThatIsAVPNsDNSIsNotRouted(t *testing.T) {
	for _, c := range []struct{ name, server, who string }{
		{"corp", "10.200.0.1", "the corp DNS server"},
		{"home", "10.201.0.1", "the DNS server of the home VPN"},
	} {
		a, ll := directRig(t, []string{c.server, "192.168.77.53"}, map[string][]netip.Addr{"bank.example": addrs("93.184.216.34")})
		cfg := testCfg()
		cfg.DirectDomains = []string{"bank.example"}
		out := a.apply(t, cfg)
		if r, ok := journalRoute(a, c.server+"/32"); ok && r.Via == ViaDirect {
			t.Errorf("%s: a direct /32 to %s: %+v", c.name, c.server, r)
		}
		if !strings.Contains(out, "the DNS server "+c.server+" of the provider is "+c.who) {
			t.Errorf("%s: no note:\n%s", c.name, out)
		}
		if r, ok := journalRoute(a, "192.168.77.53/32"); !ok || r.Via != ViaDirect {
			t.Errorf("%s: the other server of the provider is left out: %+v %v", c.name, r, ok)
		}
		if len(ll.asked) != 1 || ll.asked[0] != "192.168.77.53 bank.example" {
			t.Errorf("%s: questions %q", c.name, ll.asked)
		}
	}
	// no server left: the system resolver
	a, ll := directRig(t, []string{"10.200.0.1"}, map[string][]netip.Addr{"bank.example": addrs("93.184.216.34")})
	cfg := testCfg()
	cfg.DirectDomains = []string{"bank.example"}
	out := a.apply(t, cfg)
	if len(ll.asked) != 1 || ll.asked[0] != " bank.example" || !strings.Contains(out, "no DNS server of the provider is usable") {
		t.Errorf("questions %q\n%s", ll.asked, out)
	}
}

// A provider's DNS inside a corp network, or the address of a VPN server, is
// not routed around the tunnel either.
func TestProviderDNSInsideCorpOrAtAnEndpoint(t *testing.T) {
	a, _ := directRig(t, []string{"10.10.7.53", "198.51.100.5", "192.168.77.53"}, map[string][]netip.Addr{"bank.example": addrs("93.184.216.34")})
	a.mb.routes = append(a.mb.routes, OSRoute{Dest: netip.MustParsePrefix("198.51.100.5/32"), Iface: "eth0", IfIndex: 2, Gateway: netip.MustParseAddr("192.168.1.9")})
	cfg := testCfg()
	cfg.DirectDomains = []string{"bank.example"}
	out := a.apply(t, cfg)
	for _, s := range []string{"10.10.7.53", "198.51.100.5"} {
		if r, ok := journalRoute(a, s+"/32"); ok && r.Via == ViaDirect {
			t.Errorf("a direct /32 to %s", s)
		}
	}
	if !strings.Contains(out, "10.10.7.53 of the provider is covered by a corp rule") || !strings.Contains(out, "198.51.100.5 of the provider is the address of a VPN server") {
		t.Errorf("no notes:\n%s", out)
	}
	if _, ok := journalRoute(a, "192.168.77.53/32"); !ok {
		t.Error("the usable server has no route")
	}
}

// An answer for a name that goes direct is not given a /32 when a rule of the
// corp or the home VPN covers it, or when it is an address the filter refuses;
// each is a warning.
func TestDirectAnswersAreFiltered(t *testing.T) {
	a, _ := directRig(t, []string{"192.168.77.53"}, map[string][]netip.Addr{
		"covered.example":   addrs("10.10.5.5"),
		"dns.example":       addrs("10.200.0.1"),
		"homedns.example":   addrs("10.201.0.1"),
		"loop.example":      addrs("127.0.0.1"),
		"linklocal.example": addrs("169.254.3.3"),
		"multi.example":     addrs("224.0.0.9"),
		"fine.example":      addrs("93.184.216.40"),
		"endpoint.example":  addrs("198.51.100.5"),
	})
	a.mb.routes = append(a.mb.routes, OSRoute{Dest: netip.MustParsePrefix("198.51.100.5/32"), Iface: "eth0", IfIndex: 2, Gateway: netip.MustParseAddr("192.168.1.9")})
	cfg := testCfg()
	cfg.DirectDomains = []string{"covered.example", "dns.example", "homedns.example", "loop.example", "linklocal.example", "multi.example", "fine.example", "endpoint.example"}
	out := a.apply(t, cfg)
	for _, s := range []string{"10.10.5.5", "127.0.0.1", "169.254.3.3", "224.0.0.9", "198.51.100.5"} {
		if r, ok := journalRoute(a, s+"/32"); ok && r.Via == ViaDirect {
			t.Errorf("a direct /32 to %s", s)
		}
	}
	if r, ok := journalRoute(a, "10.200.0.1/32"); !ok || r.Via != ViaCorp {
		t.Errorf("the corp DNS keeps its corp route: %+v %v", r, ok)
	}
	if r, ok := journalRoute(a, "10.201.0.1/32"); ok {
		t.Errorf("a route to the DNS of the home VPN: %+v", r)
	}
	if _, ok := journalRoute(a, "93.184.216.40/32"); !ok {
		t.Error("a good answer has no route")
	}
	for _, want := range []string{
		"covered.example resolves to 10.10.5.5 (covered by a corp rule)",
		"dns.example resolves to 10.200.0.1 (the corp DNS server)",
		"homedns.example resolves to 10.201.0.1 (the DNS server of the home VPN)",
		"loop.example resolves to 127.0.0.1 (loopback)",
		"linklocal.example resolves to 169.254.3.3 (link-local)",
		"multi.example resolves to 224.0.0.9 (multicast)",
		"endpoint.example resolves to 198.51.100.5 (the address of a VPN server)",
	} {
		if !strings.Contains(out, "! "+want) {
			t.Errorf("no warning %q in\n%s", want, out)
		}
	}
}

// With the rest going direct a rule "through the home VPN" covers its addresses:
// a name that goes direct and lands in one has no /32 around it.
func TestDirectAnswerInsideAHomeRule(t *testing.T) {
	a, _ := directRig(t, []string{"192.168.77.53"}, map[string][]netip.Addr{"tv.example": addrs("198.51.100.9")})
	cfg := testCfg()
	cfg.Rest = config.RestDirect
	cfg.HomeNetworks = []string{"198.51.100.0/24"}
	cfg.DirectDomains = []string{"tv.example"}
	// a direct rule is not applied with "rest: direct" (no meaning), so the answer is not looked at;
	// with the rest going home the home rule is not applied either: both ways nothing is wrong
	a.apply(t, cfg)
	if r, ok := journalRoute(a, "198.51.100.9/32"); ok {
		t.Errorf("a /32 for the answer: %+v", r)
	}
	if r, ok := journalRoute(a, "198.51.100.0/24"); !ok || r.Via != ViaHome {
		t.Errorf("the home rule: %+v %v", r, ok)
	}
}

// The bootstrap plan leaves out the same servers as the full one.
func TestBootstrapLeavesOutCorpAndHomeDNS(t *testing.T) {
	m := newTestMgr()
	m.dnsOf = func(iface string) ([]string, []string) {
		switch iface {
		case "wgcorp":
			return []string{"10.200.0.1"}, nil
		case "wghome":
			return []string{"10.201.0.1"}, nil
		}
		return nil, nil
	}
	m.physDNS = func(string) []string { return []string{"10.200.0.1", "10.201.0.1", "127.0.0.53", "192.168.77.53"} }
	cfg := testCfg()
	cfg.DirectDomains = []string{"bank.example"}
	p := m.bootstrapPlan(cfg, *testEnv(), nil, &table{}, &ruleSet{})
	if p == nil {
		t.Fatal("no plan")
	}
	for _, r := range p.routes {
		if r.Via == ViaDirect && r.Dest != "192.168.77.53/32" {
			t.Errorf("a direct route in the bootstrap: %+v", r)
		}
	}
	var direct int
	for _, r := range p.routes {
		if r.Via == ViaDirect {
			direct++
		}
	}
	if direct != 1 {
		t.Errorf("routes: %+v", p.routes)
	}
}

// A DNS server of the provider in a network of the physical adapter is reached
// on the link, with no next hop; one outside it goes through the gateway.
func TestProviderDNSOnLink(t *testing.T) {
	a, _ := directRig(t, []string{"192.168.1.53", "1.1.1.1"}, map[string][]netip.Addr{"bank.example": addrs("93.184.216.34")})
	a.env.GWNets = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	cfg := testCfg()
	cfg.DirectDomains = []string{"bank.example"}
	a.apply(t, cfg)
	if r, ok := journalRoute(a, "192.168.1.53/32"); !ok || r.Gateway != "" || r.Iface != "eth0" {
		t.Errorf("on-link server: %+v %v", r, ok)
	}
	if r, ok := journalRoute(a, "1.1.1.1/32"); !ok || r.Gateway != "192.168.1.1" {
		t.Errorf("remote server: %+v %v", r, ok)
	}
}

// needDNS skips a test on a system where the zones cannot be sent to a server.
func needDNS(t *testing.T) {
	t.Helper()
	if len(resolverPlan("wgcorp", []string{"10.200.0.1"}, []string{"corp.example"})) == 0 {
		t.Skip("this OS cannot send zones to a server here (systemd-resolved)")
	}
}

func splitDNSRig(t *testing.T) (*applyRig, *config.Config) {
	t.Helper()
	a, _ := directRig(t, []string{"192.168.77.53"}, map[string][]netip.Addr{"bank.example": addrs("93.184.216.34")})
	a.m.dnsOf = func(iface string) ([]string, []string) {
		switch iface {
		case "wgcorp":
			return []string{"10.200.0.1"}, []string{"corp.example"}
		case "wghome":
			return []string{"10.201.0.1"}, nil
		}
		return nil, nil
	}
	cfg := testCfg()
	cfg.SplitDNS = true
	return a, cfg
}

func hasID(ids []string, zone string) bool {
	for _, id := range ids {
		if id == zone || strings.HasSuffix(id, " "+zone) || strings.HasSuffix(id, "/"+zone) {
			return true
		}
	}
	return false
}

// With the rest going home the zones that go direct are sent to the DNS of the
// provider, so that the applications ask the server the route was made from.
func TestDirectZonesGoToTheProviderDNS(t *testing.T) {
	needDNS(t)
	a, cfg := splitDNSRig(t)
	cfg.DirectDomains = []string{"bank.example"}
	tbl, rs := a.m.readTables()
	p := a.m.buildPlan(cfg, *a.env, &config.State{}, tbl, rs, &discard{})
	if p.direct == nil || !hasID(p.direct.ids, "bank.example") || strings.Join(p.direct.servers, ",") != "192.168.77.53" || p.direct.iface != "eth0" {
		t.Fatalf("direct DNS plan: %+v", p.direct)
	}
	if p.dns == nil || hasID(p.dns.ids, "bank.example") {
		t.Errorf("corp zones: %+v", p.dns)
	}
	if !hasID(p.dnsIDs(), "bank.example") || !strings.Contains(p.dnsSig(), "192.168.77.53") {
		t.Errorf("ids %v sig %q", p.dnsIDs(), p.dnsSig())
	}
	// applied, journaled, and gone with the rest
	a.apply(t, cfg)
	if !hasID(a.store.state().Resolvers, "bank.example") {
		t.Errorf("journal: %v", a.store.state().Resolvers)
	}
	rep, err := a.s.Cleanup(5e9)
	if err != nil || a.store.state().Resolvers != nil && len(a.store.state().Resolvers) != 0 {
		t.Errorf("cleanup: %v %+v journal %v", err, rep, a.store.state().Resolvers)
	}
	// the rest elsewhere: no zone for the direct names
	for _, rest := range []string{config.RestKeep, config.RestDirect} {
		cfg.Rest = rest
		tbl, rs = a.m.readTables()
		if p := a.m.buildPlan(cfg, *a.env, &config.State{}, tbl, rs, &discard{}); p.direct != nil {
			t.Errorf("rest %s: %+v", rest, p.direct)
		}
	}
}

// The DNS rule for everything else is made only where it cannot take the corp
// names with it, where a watching process is there, and where the home VPN's DNS is known.
func TestRestDNSConditions(t *testing.T) {
	needDNS(t)
	a, cfg := splitDNSRig(t)
	build := func() *plan {
		tbl, rs := a.m.readTables()
		return a.m.buildPlan(cfg, *a.env, &config.State{}, tbl, rs, &discard{})
	}
	if p := build(); p.rest == nil || strings.Contains(strings.Join(p.warns, "|"), "DNS of the rest") {
		t.Fatalf("the plain case: %+v warns %v", p.rest, p.warns)
	}
	// split DNS off with a corp VPN: no "." and a warning
	cfg.SplitDNS = false
	p := build()
	if p.rest != nil || !strings.Contains(strings.Join(p.warns, "|"), "corp zones are not set up") {
		t.Errorf("split DNS off: %+v %v", p.rest, p.warns)
	}
	// without the corp VPN the rule is made as usual
	a.env.CorpOK = false
	if p := build(); p.rest == nil {
		t.Errorf("no corp VPN: %v", p.warns)
	}
	a.env.CorpOK = true
	cfg.SplitDNS = true
	// the corp zones are not known: the same
	a.m.dnsOf = func(iface string) ([]string, []string) {
		if iface == "wghome" {
			return []string{"10.201.0.1"}, nil
		}
		return []string{"10.200.0.1"}, nil
	}
	if p := build(); p.rest != nil {
		t.Errorf("no corp zones: %+v", p.rest)
	}
	// persistent apply with nobody watching
	a, cfg = splitDNSRig(t)
	a.m.SetOneShot()
	p = build()
	if p.rest != nil || !strings.Contains(strings.Join(p.warns, "|"), "\"apply\"") {
		t.Errorf("one-shot: %+v %v", p.rest, p.warns)
	}
	if p.dns == nil {
		t.Error("the corp zones are made by apply too")
	}
}

// foreignBackend is an OS where a DNS entry is made by somebody else already.
type foreignBackend struct {
	*memBackend
	foreignIDs map[string]bool
	adds       []string
	flushes    int
	onFlush    func() // called when the DNS cache is flushed: after all the entries are made, before the final journal
}

func (b *foreignBackend) AddResolver(id string, s []string) error {
	b.adds = append(b.adds, id)
	if b.foreignIDs[id] {
		return fmt.Errorf("%w: made by somebody else", errResolverExists)
	}
	return b.memBackend.AddResolver(id, s)
}
func (b *foreignBackend) FlushDNS() {
	b.flushes++
	if b.onFlush != nil {
		b.onFlush()
	}
}

// The entry that somebody else made is left as it is, and it does not make the
// next cycles redo the DNS entries and flush the cache: the plan counts as done.
func TestForeignRootDNSEntryDoesNotFlap(t *testing.T) {
	needDNS(t)
	a, cfg := splitDNSRig(t)
	fb := &foreignBackend{memBackend: a.mb, foreignIDs: map[string]bool{}}
	a.m.b = fb
	tbl, rs := a.m.readTables()
	pl := a.m.buildPlan(cfg, *a.env, &config.State{}, tbl, rs, &discard{})
	if pl.rest == nil {
		t.Fatal("no rule for the rest")
	}
	for _, id := range pl.rest.ids {
		fb.foreignIDs[id] = true
	}
	a.apply(t, cfg)
	st := a.store.state()
	if st.DNSSig == "" {
		t.Fatal("the DNS plan was not recorded as done")
	}
	for _, id := range pl.rest.ids {
		if hasID(st.Resolvers, id) && id != "dns wghome" {
			t.Errorf("the foreign entry %q is in our journal: %v", id, st.Resolvers)
		}
	}
	if !hasID(st.Resolvers, "corp.example") {
		t.Errorf("the corp zone is missing: %v", st.Resolvers)
	}
	fb.adds, fb.flushes = nil, 0
	for i := range 3 {
		out := a.apply(t, cfg)
		if len(fb.adds) != 0 || fb.flushes != 0 {
			t.Fatalf("cycle %d: adds %v flushes %d\n%s", i, fb.adds, fb.flushes, out)
		}
		if strings.Contains(out, "= ") && strings.Contains(out, "made by somebody else") {
			t.Errorf("cycle %d repeats the note:\n%s", i, out)
		}
	}
	// and when the plan changes the entries are made again
	cfg.Domains = append(cfg.Domains, "extra.example")
	fb.adds = nil
	a.apply(t, cfg)
	if len(fb.adds) == 0 {
		t.Error("a changed plan did not redo the entries")
	}

	// the foreign entry is never taken away
	if _, err := a.s.Cleanup(5e9); err != nil {
		t.Fatal(err)
	}
	for _, l := range a.mb.dnsLog {
		for _, id := range pl.rest.ids {
			if l == "del "+id && id != "dns wghome" {
				t.Errorf("removed an entry that is not ours: %s", l)
			}
		}
	}
}

// v6 captured by the client's rules.
type v6Backend struct {
	*memBackend
	rules6 []OSRule
	err    error
}

func (b *v6Backend) Rules6() ([]OSRule, error) { return b.rules6, b.err }

func v6Table(t *testing.T) (*memBackend, []OSRule) {
	t.Helper()
	mb := newMemBackend()
	rules := singBoxRules()
	mb.rules = rules
	mb.routes = append(mb.routes, OSRoute{Dest: netip.MustParsePrefix("0.0.0.0/0"), Iface: "wghome", Table: 2022})
	return mb, rules
}

func TestV6CapOf(t *testing.T) {
	mb, _ := v6Table(t)
	// the client takes IPv4 only
	b := &v6Backend{memBackend: mb, rules6: []OSRule{{Pref: 0, Table: 255, Suppress: -1, ToTable: true}, {Pref: 32766, Table: RuleTableMain, Suppress: -1, ToTable: true}}}
	if c := v6CapOf(b, "wghome"); c != V6CapV4Only {
		t.Errorf("v4 only: %v", c)
	}
	// and IPv6 too: a rule and a default route in its table
	mb.routes = append(mb.routes, OSRoute{Dest: netip.MustParsePrefix("::/0"), Iface: "wghome", Table: 2022})
	b.rules6 = append(b.rules6, OSRule{Pref: 9000, Table: 2022, Suppress: -1, ToTable: true, Fwmark: true, Inv: true})
	if c := v6CapOf(b, "wghome"); c != V6CapBoth {
		t.Errorf("both: %v", c)
	}
	// the IPv6 rules cannot be read
	b.err = errors.New("no")
	if c := v6CapOf(b, "wghome"); c != V6CapUnknown {
		t.Errorf("unreadable: %v", c)
	}
	// a backend that cannot read them at all
	if c := v6CapOf(mb, "wghome"); c != V6CapUnknown {
		t.Errorf("no reader: %v", c)
	}
	// not captured: nothing in the rules
	if c := v6CapOf(newMemBackend(), "wghome"); c != V6CapNone {
		t.Errorf("not captured: %v", c)
	}
}

func TestV6StatusByCapture(t *testing.T) {
	cfg := config.New()
	e := *testEnv()
	e.Home.Up, e.Home.Addrs6 = true, []string{"2001:db8:77::2"}
	e.GWv6 = true
	for _, c := range []struct {
		cap  V6Cap
		want V6Level
	}{
		{V6CapBoth, V6Info},
		{V6CapV4Only, V6Leaks},
		{V6CapUnknown, V6Info},
	} {
		e.V6Cap = c.cap
		lvl, text := V6Status(cfg, e)
		if lvl != c.want || text == "" {
			t.Errorf("cap %v: %v %q", c.cap, lvl, text)
		}
	}
	e.V6Cap = V6CapUnknown
	if _, text := V6Status(cfg, e); !strings.Contains(text, "left to the home VPN client") {
		t.Errorf("%q", text)
	}
	// v4-only capture and no IPv6 on the physical adapter: nothing to say
	e.V6Cap, e.GWv6 = V6CapV4Only, false
	if lvl, _ := V6Status(cfg, e); lvl != V6Quiet {
		t.Errorf("no v6 on the uplink: %v", lvl)
	}
}

// The routes of a pin that we made are not a client's.
func TestPinnedHostsLeavesOurOwn(t *testing.T) {
	host := netip.MustParsePrefix("198.51.100.5/32")
	tbl := newTable([]OSRoute{{Dest: host, Iface: "eth0", IfIndex: 2, Gateway: netip.MustParseAddr("192.168.1.9"), Ours: true}})
	st := &config.State{Routes: []config.Route{{Dest: "198.51.100.5/32", Iface: "eth0", Via: ViaPin}}}
	if routesTagged {
		if n := pinnedHosts(tbl, nil); n != 0 {
			t.Errorf("tagged as ours: %d", n)
		}
	} else if n := pinnedHosts(tbl, st); n != 0 {
		t.Errorf("listed in the journal: %d", n)
	}
	other := newTable([]OSRoute{{Dest: host, Iface: "eth0", IfIndex: 2, Gateway: netip.MustParseAddr("192.168.1.9")}})
	if n := pinnedHosts(other, &config.State{}); n != 1 {
		t.Errorf("a client's pin: %d", n)
	}
}

// A setting that was turned off and is on again (somebody turned it on) is
// turned off again; the original in the journal is not touched.
func TestTunnels6TurnedOffAgain(t *testing.T) {
	orig := config.Tunnels6{Teredo: "Client", SixToFour: "Automatic"}
	a, tb := newTunRig(t, orig)
	a.apply(t, testCfg())
	if len(tb.sets) != 1 {
		t.Fatalf("sets %+v", tb.sets)
	}
	tb.cur.Teredo = "Enterpriseclient" // somebody turned it back on (the cmdlet's spelling differs in case)
	cfg := testCfg()
	cfg.Networks = append(cfg.Networks, "192.0.2.0/24")
	a.apply(t, cfg)
	if len(tb.sets) != 2 || tb.sets[1] != (config.Tunnels6{Teredo: "Disabled"}) {
		t.Errorf("sets %+v", tb.sets)
	}
	if got := a.store.state().Tun6; got == nil || *got != orig {
		t.Errorf("the original was overwritten: %+v", got)
	}
	// a setting that was not recorded (it was Disabled before) is not ours to touch
	tb.cur.ISATAP = "Enabled"
	cfg.Networks = append(cfg.Networks, "192.0.3.0/24")
	a.apply(t, cfg)
	for _, s := range tb.sets[2:] {
		if s.ISATAP != "" {
			t.Errorf("ISATAP was touched: %+v", s)
		}
	}
}

// A value of a setting that vpnsplit does not know is named in the report.
func TestTunnels6UnknownValueIsReported(t *testing.T) {
	a, tb := newTunRig(t, config.Tunnels6{Teredo: "Default"})
	tb.unknown = []string{`Teredo "Strange"`}
	out := a.apply(t, testCfg())
	if !strings.Contains(out, `unknown to vpnsplit`) || !strings.Contains(out, `Teredo "Strange"`) {
		t.Errorf("no warning:\n%s", out)
	}
}

// Every value the cmdlets take is known.
func TestTeredoTypes(t *testing.T) {
	for _, v := range []string{"Default", "Disabled", "Client", "EnterpriseClient", "Server", "NATAwareClient", "natawareclient", "enterpriseclient"} {
		if _, ok := config.CanonTeredo(v); !ok {
			t.Errorf("%s", v)
		}
	}
	if _, ok := config.CanonTeredo("Strange; calc"); ok {
		t.Error("garbage accepted")
	}
	if got, _ := config.CanonTeredo("natawareclient"); got != "NATAwareClient" {
		t.Errorf("%q", got)
	}
}

var _ = context.Background
