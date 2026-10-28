package router

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// lookupLog is a lookup that answers from a table by name and keeps the
// questions: which server was asked for which name.
type lookupLog struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr // name -> addresses
	asked   []string                // "dns name"
}

func (l *lookupLog) lookup(_ context.Context, dns, name string) ([]netip.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked = append(l.asked, dns+" "+name)
	if a, ok := l.answers[name]; ok {
		return a, nil
	}
	return nil, errors.New("no such name")
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, x := range s {
		out = append(out, netip.MustParseAddr(x))
	}
	return out
}

func journalRoute(a *applyRig, dest string) (config.Route, bool) {
	for _, r := range a.store.state().Routes {
		if r.Dest == dest {
			return r, true
		}
	}
	return config.Route{}, false
}

// The names that go direct are asked of the DNS of the provider, and a /32 route
// leads to that server through the physical adapter and its gateway.
func TestDirectDomainsUseTheProviderDNS(t *testing.T) {
	a := newApplyRig(t)
	ll := &lookupLog{answers: map[string][]netip.Addr{"bank.example": addrs("93.184.216.34")}}
	a.m.lookup = ll.lookup
	a.m.physDNS = func(iface string) []string {
		if iface != "eth0" {
			t.Errorf("DNS of %s asked, not of the physical adapter", iface)
		}
		return []string{"192.168.77.53", "192.168.1.1"} // the second one is the gateway itself
	}
	cfg := testCfg()
	cfg.DirectDomains = []string{"bank.example"}
	a.apply(t, cfg)
	if len(ll.asked) != 1 || ll.asked[0] != "192.168.77.53 bank.example" {
		t.Errorf("questions: %q", ll.asked)
	}
	r, ok := journalRoute(a, "192.168.77.53/32")
	if !ok || r.Iface != "eth0" || r.Gateway != "192.168.1.1" || r.Via != ViaDirect {
		t.Errorf("the route to the provider's DNS: %+v %v", r, ok)
	}
	if _, ok := journalRoute(a, "192.168.1.1/32"); ok {
		t.Error("the gateway is on the link: no /32 to it")
	}
	if r, ok := journalRoute(a, "93.184.216.34/32"); !ok || r.Iface != "eth0" {
		t.Errorf("the address of the domain: %+v %v", r, ok)
	}
}

// With no DNS of the provider known the system resolver is used, and the report
// says so.
func TestDirectDomainsWithoutProviderDNS(t *testing.T) {
	a := newApplyRig(t)
	ll := &lookupLog{answers: map[string][]netip.Addr{"bank.example": addrs("93.184.216.34")}}
	a.m.lookup = ll.lookup
	cfg := testCfg()
	cfg.DirectDomains = []string{"bank.example"}
	out := a.apply(t, cfg)
	if len(ll.asked) != 1 || ll.asked[0] != " bank.example" {
		t.Errorf("questions: %q", ll.asked)
	}
	if !strings.Contains(out, "DNS servers of the provider are unknown") {
		t.Errorf("the report does not say it:\n%s", out)
	}
}

// An answer from the fake-ip range is dropped and the report says so.
func TestFakeIPAnswersAreDropped(t *testing.T) {
	a := newApplyRig(t)
	ll := &lookupLog{answers: map[string][]netip.Addr{
		"fake.example":  addrs("198.18.0.7", "198.19.255.1"),
		"mixed.example": addrs("198.18.4.4", "93.184.216.35"),
	}}
	a.m.lookup = ll.lookup
	a.m.physDNS = func(string) []string { return []string{"192.168.77.53"} }
	cfg := testCfg()
	cfg.DirectDomains = []string{"fake.example", "mixed.example"}
	out := a.apply(t, cfg)
	for _, d := range []string{"198.18.0.7/32", "198.19.255.1/32", "198.18.4.4/32"} {
		if _, ok := journalRoute(a, d); ok {
			t.Errorf("a fake-ip address was routed: %s", d)
		}
	}
	if _, ok := journalRoute(a, "93.184.216.35/32"); !ok {
		t.Error("the real address was dropped with the fake one")
	}
	if !strings.Contains(out, "fake-ip") || !strings.Contains(out, "fake.example=198.18.0.7") {
		t.Errorf("the report does not name them:\n%s", out)
	}
}

// The fake-ip range is exactly 198.18.0.0/15.
func TestFakeIPRange(t *testing.T) {
	for a, want := range map[string]bool{
		"198.18.0.0": true, "198.19.255.255": true, "198.17.255.255": false, "198.20.0.0": false, "93.184.216.34": false,
	} {
		if got := fakeIPNet.Contains(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v", a, got)
		}
	}
}

// The corp DNS (detected, not set by hand) is reached through the corp adapter.
func TestCorpDNSGetsAHostRoute(t *testing.T) {
	a := newApplyRig(t)
	a.m.dnsOf = corpOnly([]string{"10.200.0.1"}, nil)
	a.apply(t, testCfg())
	if r, ok := journalRoute(a, "10.200.0.1/32"); !ok || r.Iface != "wgcorp" || r.Via != ViaCorp {
		t.Errorf("%+v %v", r, ok)
	}
}

// With a global IPv6 address on the home VPN the halves of IPv6 go into it too.
func TestIPv6HalvesIntoTheHomeVPN(t *testing.T) {
	a := newApplyRig(t)
	a.env.Home.Up, a.env.Home.Addrs6 = true, []string{"2001:db8:77::2"}
	a.env.GWv6 = true
	cfg := testCfg()
	a.apply(t, cfg)
	for _, d := range []string{"::/1", "8000::/1"} {
		if !a.mb.has(d, "wghome") {
			t.Errorf("%s is not in the table", d)
		}
	}
	for _, r := range a.store.state().Routes {
		if err := config.ValidateRoute(r); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	if lvl, _ := V6Status(cfg, *a.env); lvl != V6Info {
		t.Errorf("level %v", lvl)
	}
	// cleanup takes them away again, like the IPv4 halves
	rep, err := a.s.Cleanup(time.Second)
	if err != nil || a.mb.has("::/1", "wghome") || a.mb.has("8000::/1", "wghome") || a.mb.has("0.0.0.0/1", "wghome") {
		t.Errorf("cleanup: %v %+v", err, rep)
	}
}

// Without IPv6 on the home VPN nothing is added for IPv6, and when the physical
// adapter has it the leak is announced.
func TestIPv6LeakIsAnnounced(t *testing.T) {
	a := newApplyRig(t)
	a.env.GWv6 = true
	cfg := testCfg()
	a.apply(t, cfg)
	if a.mb.has("::/1", "wghome") || a.mb.has("8000::/1", "wghome") {
		t.Error("IPv6 routes through a VPN that has no IPv6")
	}
	lvl, text := V6Status(cfg, *a.env)
	if lvl != V6Leaks || text == "" {
		t.Errorf("level %v %q", lvl, text)
	}
	a.env.GWv6 = false
	if lvl, _ := V6Status(cfg, *a.env); lvl != V6Quiet {
		t.Errorf("no IPv6 anywhere: level %v", lvl)
	}
	cfg.Rest = config.RestKeep
	a.env.GWv6 = true
	if lvl, _ := V6Status(cfg, *a.env); lvl != V6Quiet {
		t.Errorf("the rest is left to the client: level %v", lvl)
	}
}

// The identity of an adapter changes with the fact that it has IPv6, not with
// the (changing) privacy addresses.
func TestIdentIPv6(t *testing.T) {
	e := *testEnv()
	s0 := Sig(config.New(), e)
	e.Home.Up, e.Home.Addrs6 = true, []string{"2001:db8::1"}
	s1 := Sig(config.New(), e)
	e.Home.Addrs6 = []string{"2001:db8::2"}
	if s0 == s1 || s1 != Sig(config.New(), e) {
		t.Errorf("%s | %s", s0, s1)
	}
}

// Rest = direct: 0/1 + 128/1 go through the physical gateway, the rules "through the
// home VPN" matter and the direct ones do not.
func TestRestDirect(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	cfg.Rest = config.RestDirect
	cfg.HomeNetworks = []string{"198.51.100.0/24"}
	out := a.apply(t, cfg)
	if r, ok := journalRoute(a, "0.0.0.0/1"); !ok || r.Iface != "eth0" || r.Gateway != "192.168.1.1" || r.Via != ViaDirect {
		t.Errorf("0/1: %+v %v\n%s", r, ok, out)
	}
	if _, ok := journalRoute(a, "128.0.0.0/1"); !ok {
		t.Error("128/1")
	}
	if a.mb.has("0.0.0.0/1", "wghome") {
		t.Error("the home VPN must not get the default halves")
	}
	if r, ok := journalRoute(a, "198.51.100.0/24"); !ok || r.Iface != "wghome" || r.Via != ViaHome {
		t.Errorf("home rule: %+v %v", r, ok)
	}
	if _, ok := journalRoute(a, "203.0.113.12/32"); ok {
		t.Error("a direct rule is applied although everything else goes direct anyway")
	}
	if !strings.Contains(out, "has no meaning") {
		t.Errorf("the hidden rules are not mentioned:\n%s", out)
	}
	if got := cfg.Kinds(); strings.Join(got, ",") != "corp,home" {
		t.Errorf("kinds: %v", got)
	}
	if a.mb.dnsLogHas("add .") {
		t.Error("DNS for the rest with the rest going direct")
	}
}

// Rest = keep: no default halves, no DNS for the rest; the rules of all kinds apply.
func TestRestKeep(t *testing.T) {
	a := newApplyRig(t)
	a.m.dnsOf = func(string) ([]string, []string) { return []string{"10.200.0.1"}, nil }
	cfg := testCfg()
	cfg.Rest = config.RestKeep
	cfg.HomeNetworks = []string{"198.51.100.0/24"}
	a.env.Home.Up, a.env.Home.Addrs6 = true, []string{"2001:db8:77::2"}
	a.apply(t, cfg)
	for _, d := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		if _, ok := journalRoute(a, d); ok {
			t.Errorf("%s with the rest left to the client", d)
		}
	}
	for _, d := range []string{"10.10.0.0/16", "203.0.113.12/32", "198.51.100.0/24"} {
		if _, ok := journalRoute(a, d); !ok {
			t.Errorf("%s is missing", d)
		}
	}
	for _, id := range a.store.state().Resolvers {
		if strings.HasSuffix(id, ".") {
			t.Errorf("DNS entry %q for the rest with the rest left to the client", id)
		}
	}
}

// Rest = home: a rule "through the home VPN" is not applied (it is the default anyway).
func TestRestHomeIgnoresHomeRules(t *testing.T) {
	a := newApplyRig(t)
	cfg := testCfg()
	cfg.HomeNetworks = []string{"198.51.100.0/24"}
	a.apply(t, cfg)
	if _, ok := journalRoute(a, "198.51.100.0/24"); ok {
		t.Error("home rule applied with the rest going home")
	}
}

// The DNS for everything else points to the DNS of the home VPN and is journaled.
func TestRestDNSOfTheHomeVPN(t *testing.T) {
	a := newApplyRig(t)
	a.m.dnsOf = func(iface string) ([]string, []string) {
		if iface == "wghome" {
			return []string{"10.201.0.1"}, nil
		}
		return []string{"10.200.0.1"}, []string{"corp.example"} // the corp zones are set up: the rule for the rest may be
	}
	cfg := testCfg()
	cfg.SplitDNS = true
	tbl, rs := a.m.readTables()
	if a.m.buildPlan(cfg, *a.env, &config.State{}, tbl, rs, &discard{}).rest == nil {
		t.Skip("this OS cannot send the rest of the DNS to a link here (systemd-resolved)")
	}
	a.apply(t, cfg)
	var have bool
	for _, id := range a.store.state().Resolvers {
		have = have || id == "." || id == "domain wghome ."
	}
	if !have {
		t.Errorf("journal: %v", a.store.state().Resolvers)
	}
	// and the rest going elsewhere takes the entry away
	cfg.Rest = config.RestKeep
	a.apply(t, cfg)
	for _, id := range a.store.state().Resolvers {
		if id == "." || id == "domain wghome ." {
			t.Errorf("the entry for the rest stays: %v", a.store.state().Resolvers)
		}
	}
}

// tunBackend is a memBackend of Windows: it has the IPv6 tunnels.
type tunBackend struct {
	*memBackend
	cur     config.Tunnels6
	sets    []config.Tunnels6
	journal func() *config.State // what the journal says at the moment of a change
	atSet   []*config.State
	fail    error
	unknown []string
}

func (b *tunBackend) Tunnels6() (config.Tunnels6, []string, error) { return b.cur, b.unknown, nil }
func (b *tunBackend) SetTunnels6(t config.Tunnels6) error {
	if b.fail != nil {
		return b.fail
	}
	if b.journal != nil {
		b.atSet = append(b.atSet, b.journal())
	}
	b.sets = append(b.sets, t)
	if t.Teredo != "" {
		b.cur.Teredo = t.Teredo
	}
	if t.SixToFour != "" {
		b.cur.SixToFour = t.SixToFour
	}
	if t.ISATAP != "" {
		b.cur.ISATAP = t.ISATAP
	}
	return nil
}

func newTunRig(t *testing.T, cur config.Tunnels6) (*applyRig, *tunBackend) {
	t.Helper()
	a := newApplyRig(t)
	tb := &tunBackend{memBackend: a.mb, cur: cur}
	tb.journal = a.store.state
	a.m.b = tb
	return a, tb
}

// The settings are in the journal before they are changed, the original ones
// are what the journal keeps, and the cleanup puts them back.
func TestTunnels6JournalFirstAndRestored(t *testing.T) {
	orig := config.Tunnels6{Teredo: "Default", SixToFour: "Automatic", ISATAP: "Default"}
	a, tb := newTunRig(t, orig)
	a.apply(t, testCfg())
	if len(tb.sets) != 1 || tb.sets[0] != (config.Tunnels6{Teredo: "Disabled", SixToFour: "Disabled", ISATAP: "Disabled"}) {
		t.Fatalf("sets: %+v", tb.sets)
	}
	if got := tb.atSet[0].Tun6; got == nil || *got != orig {
		t.Errorf("at the moment of the change the journal says %+v", got)
	}
	// a second apply (the OS now says Disabled) keeps the first record
	cfg := testCfg()
	cfg.Networks = append(cfg.Networks, "192.0.2.0/24")
	a.apply(t, cfg)
	if got := a.store.state().Tun6; got == nil || *got != orig || len(tb.sets) != 1 {
		t.Errorf("journal %+v, sets %d", got, len(tb.sets))
	}
	rep, err := a.s.Cleanup(5 * time.Second)
	if err != nil || !rep.Tun6 {
		t.Fatalf("cleanup: %v %+v", err, rep)
	}
	if last := tb.sets[len(tb.sets)-1]; last != orig {
		t.Errorf("put back: %+v", last)
	}
	if !a.store.state().Empty() {
		t.Errorf("journal after cleanup: %+v", a.store.state())
	}
}

// What was Disabled before is not touched and not recorded; a value the cmdlets
// do not know is left alone.
func TestTunnels6AlreadyOff(t *testing.T) {
	a, tb := newTunRig(t, config.Tunnels6{Teredo: "Disabled", SixToFour: "Disabled", ISATAP: "Disabled"})
	a.apply(t, testCfg())
	if len(tb.sets) != 0 || a.store.state().Tun6 != nil {
		t.Errorf("sets %+v, journal %+v", tb.sets, a.store.state().Tun6)
	}
	a, tb = newTunRig(t, config.Tunnels6{Teredo: "weird; calc", SixToFour: "Enabled"})
	a.apply(t, testCfg())
	if len(tb.sets) != 1 || tb.sets[0].Teredo != "" || tb.sets[0].SixToFour != "Disabled" {
		t.Errorf("sets %+v", tb.sets)
	}
}

// When the rest does not go into the home VPN any more the tunnels are put back
// by the next apply.
func TestTunnels6PutBackWhenTheRestMoves(t *testing.T) {
	orig := config.Tunnels6{Teredo: "Client"}
	a, tb := newTunRig(t, orig)
	cfg := testCfg()
	a.apply(t, cfg)
	cfg.Rest = config.RestKeep
	a.apply(t, cfg)
	if last := tb.sets[len(tb.sets)-1]; last != orig || a.store.state().Tun6 != nil {
		t.Errorf("sets %+v, journal %+v", tb.sets, a.store.state().Tun6)
	}
}

// A session that was killed leaves the settings in the journal; the next start
// puts them back (Recover), also after a reboot (the settings outlive it).
func TestTunnels6RecoverPutsThemBack(t *testing.T) {
	for _, reboot := range []bool{false, true} {
		st := sessionJournal(4242, config.ModeSession)
		st.Tun6 = &config.Tunnels6{Teredo: "Default", ISATAP: "Enabled"}
		if reboot {
			st.Owner.Boot = "boot-1"
		}
		r := newRig(st)
		tb := &tunBackend{memBackend: newMemBackend()}
		r.m.b = tb
		acquire(t, r, config.ModeSession)
		if len(tb.sets) != 1 || tb.sets[0] != *st.Tun6 {
			t.Errorf("reboot=%v: sets %+v", reboot, tb.sets)
		}
		if r.store.state().Tun6 != nil {
			t.Errorf("reboot=%v: journal %+v", reboot, r.store.state().Tun6)
		}
	}
}

// A failure to put them back leaves them in the journal for the next start.
func TestTunnels6FailureStaysInTheJournal(t *testing.T) {
	st := sessionJournal(4242, config.ModeSession)
	st.Tun6 = &config.Tunnels6{Teredo: "Default"}
	r := newRig(st)
	tb := &tunBackend{memBackend: newMemBackend(), fail: errors.New("denied")}
	r.m.b = tb
	_, _, _ = r.m.Acquire(context.Background(), config.ModeSession, &strings.Builder{})
	if got := r.store.state().Tun6; got == nil || got.Teredo != "Default" {
		t.Errorf("journal %+v", got)
	}
}

// The scutil output is read per adapter.
func TestParseScutilDNS(t *testing.T) {
	out := `DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 192.168.1.2
  if_index : 6 (en0)
  flags    : Request A records

resolver #2
  nameserver[0] : 10.200.0.1
  if_index : 21 (utun4)
  flags    : Request A records

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
`
	got := parseScutilDNS(out, "en0")
	if strings.Join(got, ",") != "192.168.1.1,192.168.1.2" {
		t.Errorf("en0: %v", got)
	}
	if got := parseScutilDNS(out, "utun4"); strings.Join(got, ",") != "10.200.0.1" {
		t.Errorf("utun4: %v", got)
	}
	if got := parseScutilDNS(out, "en5"); len(got) != 0 {
		t.Errorf("en5: %v", got)
	}
}
