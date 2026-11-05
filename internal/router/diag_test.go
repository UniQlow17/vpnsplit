package router

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/clientcfg"
	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

func pf(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ad(s string) netip.Addr   { return netip.MustParseAddr(s) }

func adapter(name, provider string, nets ...string) netif.Info {
	i := netif.Info{Name: name, Up: true, Provider: provider, Kind: netif.KindVPN}
	for _, n := range nets {
		p := pf(n)
		i.Addrs = append(i.Addrs, p.Addr().String())
		i.Nets = append(i.Nets, p.Masked())
	}
	if provider == "" {
		i.Kind = netif.Classify(name)
	}
	return i
}

// diagEnv is a setup with a corp VPN, a home VPN and Ethernet.
func diagEnv() Env {
	corp := adapter("wgcorp", "WireGuard", "10.10.0.2/16")
	home := adapter("wghome", "WireGuard", "10.20.0.2/24")
	eth := adapter("eth0", "", "192.168.1.5/24")
	return Env{
		Corp: corp, Home: home, CorpOK: true, HomeOK: true,
		GW: Gateway{Iface: "eth0", Router: "192.168.1.1"}, GWOK: true, GWNets: eth.Nets,
		Ifs: []netif.Info{corp, home, eth},
	}
}

func baseIn() diagIn {
	cfg := config.New()
	return diagIn{goos: "linux", cfg: cfg, env: diagEnv()}
}

func codes(l []Diag) []string {
	var out []string
	for _, d := range l {
		out = append(out, d.Code)
	}
	return out
}

func find(l []Diag, code string) *Diag {
	for i := range l {
		if l[i].Code == code {
			return &l[i]
		}
	}
	return nil
}

func wantCode(t *testing.T, l []Diag, code string, lvl DiagLevel) *Diag {
	t.Helper()
	d := find(l, code)
	if d == nil {
		t.Fatalf("no %s among %v", code, codes(l))
	}
	if d.Level != lvl {
		t.Errorf("%s has level %s, want %s", code, d.Level, lvl)
	}
	if d.TextEN == "" || d.TextRU == "" {
		t.Errorf("%s: a text is missing", code)
	}
	return d
}

func noCode(t *testing.T, l []Diag, code string) {
	t.Helper()
	if d := find(l, code); d != nil {
		t.Errorf("unexpected %s: %s", code, d.TextEN)
	}
}

func orow(dest, iface, gw string, metric int, tbl int) OSRoute {
	r := OSRoute{Dest: pf(dest), Iface: iface, Metric: metric, Table: tbl}
	if gw != "" {
		r.Gateway = ad(gw)
	}
	return r
}

func TestDiagQuietSetup(t *testing.T) {
	in := baseIn()
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "eth0", "192.168.1.1", 100, 0), orow("10.10.0.0/16", "wgcorp", "10.10.0.1", 0, 0)})
	if got := diagnose(in); len(got) != 0 {
		t.Errorf("quiet setup gives %v", codes(got))
	}
	if got := diagnose(diagIn{}); got != nil {
		t.Errorf("no config: %v", got)
	}
}

func TestDiagProxy(t *testing.T) {
	in := baseIn()
	in.cl.Proxy = clientcfg.Proxy{Known: true, Enabled: true, Server: "127.0.0.1:7890", Source: "WinINET"}
	d := wantCode(t, diagnose(in), "PROXY_ON", DiagWarn)
	if !strings.Contains(d.TextEN, "127.0.0.1:7890") || !strings.Contains(d.TextRU, "127.0.0.1:7890") || d.AdviceEN == "" {
		t.Errorf("%+v", d)
	}
	in.cl.Proxy = clientcfg.Proxy{Known: true, PAC: "http://x/p.pac", Source: "gsettings"}
	wantCode(t, diagnose(in), "PROXY_ON", DiagWarn)
	in.cl.Proxy = clientcfg.Proxy{Known: true, Source: "WinINET"}
	noCode(t, diagnose(in), "PROXY_ON")
	in.cl.Proxy = clientcfg.Proxy{Known: true, Enabled: true, Server: "a:1"}
	in.env.CorpOK, in.env.HomeOK = false, false
	noCode(t, diagnose(in), "PROXY_ON")
}

func TestDiagTunConfigs(t *testing.T) {
	in := baseIn()
	in.cl.Tun = []clientcfg.TunCfg{
		{Client: "sing-box", Tun: true, StrictRoute: true},
		{Client: "Mihomo", FakeIP: true, FakeRanges: []netip.Prefix{pf("28.0.0.0/8")}},
	}
	l := diagnose(in)
	d := wantCode(t, l, "STRICT_ROUTE", DiagWarn)
	if !strings.Contains(d.TextEN, "sing-box") {
		t.Errorf("client not named: %s", d.TextEN)
	}
	f := wantCode(t, l, "FAKE_IP", DiagInfo)
	if !strings.Contains(f.TextEN, "28.0.0.0/8") {
		t.Errorf("range not named: %s", f.TextEN)
	}
	in.cfg.Domains = []string{"corp.example"}
	wantCode(t, diagnose(in), "FAKE_IP", DiagWarn)
	// a strict_route of a TUN that is off is no finding; no VPN, no finding
	in.cl.Tun = []clientcfg.TunCfg{{Client: "sing-box", StrictRoute: true}}
	noCode(t, diagnose(in), "STRICT_ROUTE")
	in.cl.Tun = []clientcfg.TunCfg{{Client: "sing-box", Tun: true, StrictRoute: true}}
	in.env.CorpOK, in.env.HomeOK = false, false
	noCode(t, diagnose(in), "STRICT_ROUTE")
}

func TestDiagFullTunnels(t *testing.T) {
	// the corp VPN has a default route and the best metric
	in := baseIn()
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "eth0", "192.168.1.1", 100, 0), orow("0.0.0.0/0", "wgcorp", "", 50, 0)})
	l := diagnose(in)
	d := wantCode(t, l, "CORP_FULL_TUNNEL", DiagWarn)
	if !strings.Contains(d.TextEN, "0.0.0.0/0") {
		t.Errorf("%s", d.TextEN)
	}

	// a default route that loses to the physical one does not take the traffic
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "eth0", "192.168.1.1", 100, 0), orow("0.0.0.0/0", "wgcorp", "", 500, 0)})
	noCode(t, diagnose(in), "CORP_FULL_TUNNEL")

	// the halves
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/1", "wgcorp", "", 0, 0), orow("128.0.0.0/1", "wgcorp", "", 0, 0)})
	d = wantCode(t, diagnose(in), "CORP_FULL_TUNNEL", DiagWarn)
	if !strings.Contains(d.TextEN, "0.0.0.0/1 + 128.0.0.0/1") {
		t.Errorf("%s", d.TextEN)
	}
	// only one half is not a full tunnel
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/1", "wgcorp", "", 0, 0)})
	noCode(t, diagnose(in), "CORP_FULL_TUNNEL")

	// our own halves (tagged, or in the journal) are not the client's
	own := orow("0.0.0.0/1", "wgcorp", "", 0, 0)
	own.Ours = true
	own2 := orow("128.0.0.0/1", "wgcorp", "", 0, 0)
	own2.Ours = true
	in.tbl = newTable([]OSRoute{own, own2})
	noCode(t, diagnose(in), "CORP_FULL_TUNNEL")
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/1", "wgcorp", "", 0, 0), orow("128.0.0.0/1", "wgcorp", "", 0, 0)})
	in.st = &config.State{Routes: []config.Route{{Dest: "0.0.0.0/1", Iface: "wgcorp"}, {Dest: "128.0.0.0/1", Iface: "wgcorp"}}}
	noCode(t, diagnose(in), "CORP_FULL_TUNNEL")
}

func TestDiagWireGuardPolicyTable(t *testing.T) {
	// wg-quick: "not from all fwmark X lookup X" and a default route in table X
	in := baseIn()
	wgRule := OSRule{Pref: 32765, Table: 51820, ToTable: true, Fwmark: true, Inv: true, Suppress: -1}
	suppress := OSRule{Pref: 32764, Table: RuleTableMain, ToTable: true, Suppress: 0}
	in.rs = newRuleSet([]OSRule{suppress, wgRule})
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "wghome", "", 0, 51820), orow("0.0.0.0/0", "eth0", "192.168.1.1", 100, 0)})
	d := wantCode(t, diagnose(in), "WG_FULL_TUNNEL", DiagInfo)
	if !strings.Contains(d.TextEN, "policy table 51820") {
		t.Errorf("%s", d.TextEN)
	}
	// the same table, but no rule sends traffic to it: nothing is taken
	in.rs = newRuleSet(nil)
	noCode(t, diagnose(in), "WG_FULL_TUNNEL")

	// a WireGuard that is neither the corp nor the home VPN
	in = baseIn()
	third := adapter("wg9", "WireGuard", "10.99.0.2/24")
	in.env.Ifs = append(in.env.Ifs, third)
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "wg9", "", 10, 0), orow("0.0.0.0/0", "eth0", "192.168.1.1", 100, 0)})
	wantCode(t, diagnose(in), "WG_FULL_TUNNEL", DiagWarn)

	// a corp WireGuard gets the corp finding, not this one
	in = baseIn()
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "wgcorp", "", 10, 0)})
	l := diagnose(in)
	wantCode(t, l, "CORP_FULL_TUNNEL", DiagWarn)
	noCode(t, l, "WG_FULL_TUNNEL")
}

func TestDiagCorpLockdown(t *testing.T) {
	in := baseIn()
	in.env.Corp.Provider = "Cisco Secure Client"
	in.cl.CiscoFailClosed = true
	wantCode(t, diagnose(in), "CORP_LOCKDOWN", DiagWarn)
	in.cl.CiscoFailClosed, in.cl.CiscoAlwaysOn = false, true
	wantCode(t, diagnose(in), "CORP_LOCKDOWN", DiagInfo)
	in.env.Corp.Provider = "GlobalProtect"
	noCode(t, diagnose(in), "CORP_LOCKDOWN")
}

func TestDiagBlockOutsideDNS(t *testing.T) {
	in := baseIn()
	in.cl.OvpnBlockDNS = "work.ovpn"
	noCode(t, diagnose(in), "BLOCK_OUTSIDE_DNS") // no OpenVPN adapter is connected
	in.env.Ifs = append(in.env.Ifs, adapter("OpenVPN TAP", "OpenVPN", "10.8.0.2/24"))
	d := wantCode(t, diagnose(in), "BLOCK_OUTSIDE_DNS", DiagInfo)
	if !strings.Contains(d.TextEN, "work.ovpn") {
		t.Errorf("%s", d.TextEN)
	}
}

func TestDiagGPO(t *testing.T) {
	in := baseIn()
	in.goos = "windows"
	in.cl.GPOKnown, in.cl.GPONRPT = true, 2
	d := wantCode(t, diagnose(in), "GPO_NRPT", DiagDanger)
	if !strings.Contains(d.TextEN, "2 NRPT") {
		t.Errorf("%s", d.TextEN)
	}
	in.cl.GPONRPT = 0
	noCode(t, diagnose(in), "GPO_NRPT")
	in.cl.GPONRPT = 2
	in.goos = "linux"
	noCode(t, diagnose(in), "GPO_NRPT")
	in.goos, in.cl.GPOKnown = "windows", false
	noCode(t, diagnose(in), "GPO_NRPT")
}

func TestDiagOverlaps(t *testing.T) {
	in := baseIn()
	in.cfg.Networks = []string{"192.168.0.0/16"} // covers the LAN of eth0
	l := diagnose(in)
	d := wantCode(t, l, "OVERLAP_LAN", DiagWarn)
	if !strings.Contains(d.TextEN, "192.168.1.0/24") || !strings.Contains(d.TextEN, "eth0") {
		t.Errorf("%s", d.TextEN)
	}

	// docker next to a corp rule that covers it
	in = baseIn()
	docker := adapter("docker0", "", "172.17.0.1/16")
	in.env.Ifs = append(in.env.Ifs, docker)
	in.cfg.Networks = []string{"172.16.0.0/12"}
	l = diagnose(in)
	wantCode(t, l, "OVERLAP_ADAPTER", DiagWarn)
	noCode(t, l, "OVERLAP_WELLKNOWN") // said already

	// the same rule, nobody in the docker range: a note
	in = baseIn()
	in.cfg.Networks = []string{"172.16.0.0/12"}
	wantCode(t, diagnose(in), "OVERLAP_WELLKNOWN", DiagInfo)
	in.cfg.Networks = []string{"100.64.0.0/10"}
	wantCode(t, diagnose(in), "OVERLAP_WELLKNOWN", DiagInfo)

	// the target adapter's own network is not an overlap
	in = baseIn()
	in.cfg.Networks = []string{"10.10.0.0/16"}
	noCode(t, diagnose(in), "OVERLAP_ADAPTER")
	noCode(t, diagnose(in), "OVERLAP_LAN")

	// the home VPN network over the LAN of the router
	in = baseIn()
	in.env.Home = adapter("wghome", "WireGuard", "192.168.1.9/24")
	in.env.Ifs[1] = in.env.Home
	wantCode(t, diagnose(in), "OVERLAP_VPN_LAN", DiagWarn)

	// the direct rules of a kind that does not matter are not looked at
	in = baseIn()
	in.cfg.Rest = config.RestDirect
	in.cfg.DirectNetworks = []string{"10.10.0.0/24"}
	noCode(t, diagnose(in), "OVERLAP_ADAPTER")

	// the corp networks of the journal count (AS, resolved names); /32 do not
	in = baseIn()
	in.st = &config.State{Routes: []config.Route{{Dest: "192.168.0.0/20", Iface: "wgcorp", Via: ViaCorp}, {Dest: "192.168.1.9/32", Iface: "wgcorp", Via: ViaCorp}}}
	l = diagnose(in)
	wantCode(t, l, "OVERLAP_LAN", DiagWarn)

	// many overlaps are cut
	in = baseIn()
	for i := 0; i < 10; i++ {
		in.cfg.Networks = append(in.cfg.Networks, netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 1, byte(i * 16)}), 28).String())
	}
	d = wantCode(t, diagnose(in), "OVERLAP_LAN", DiagWarn)
	if !strings.Contains(d.TextEN, "more") {
		t.Errorf("not cut: %s", d.TextEN)
	}
}

func TestDiagEndpointCovered(t *testing.T) {
	in := baseIn()
	// the client pinned the server of the home VPN through the gateway
	in.tbl = newTable([]OSRoute{orow("198.51.100.7/32", "eth0", "192.168.1.1", 0, 0)})
	in.cfg.Networks = []string{"198.51.100.0/24"}
	d := wantCode(t, diagnose(in), "ENDPOINT_COVERED", DiagWarn)
	if !strings.Contains(d.TextEN, "198.51.100.0/24") || !strings.Contains(d.TextEN, "198.51.100.7") {
		t.Errorf("%s", d.TextEN)
	}
	in.cfg.Networks = []string{"203.0.113.0/24"}
	noCode(t, diagnose(in), "ENDPOINT_COVERED")
	// a pin of ours is not a server
	in.cfg.Networks = []string{"198.51.100.0/24"}
	in.st = &config.State{Routes: []config.Route{{Dest: "198.51.100.7/32", Iface: "eth0", Via: ViaPin}}}
	noCode(t, diagnose(in), "ENDPOINT_COVERED")
}

func TestDiagBigDirect(t *testing.T) {
	in := baseIn()
	in.cfg.DirectNetworks = []string{"AS13335", "203.0.113.0/24"}
	d := wantCode(t, diagnose(in), "DIRECT_CDN_AS", DiagWarn)
	if !strings.Contains(d.TextEN, "Cloudflare") {
		t.Errorf("%s", d.TextEN)
	}
	noCode(t, diagnose(in), "DIRECT_BIG")

	// an AS that is not a CDN
	in.cfg.DirectNetworks = []string{"AS49675"}
	noCode(t, diagnose(in), "DIRECT_CDN_AS")

	// the size: a /9 and a /10 are over the line, a /10 alone is not
	in.cfg.DirectNetworks = []string{"11.0.0.0/10"}
	noCode(t, diagnose(in), "DIRECT_BIG")
	in.cfg.DirectNetworks = []string{"11.0.0.0/10", "12.0.0.0/9"}
	wantCode(t, diagnose(in), "DIRECT_BIG", DiagWarn)
	// the same network twice, or inside another, is counted once
	in.cfg.DirectNetworks = []string{"11.0.0.0/10", "11.0.0.0/10", "11.1.0.0/16"}
	noCode(t, diagnose(in), "DIRECT_BIG")
	// the networks of an AS from the cache count
	in.cfg.DirectNetworks = []string{"AS64500"}
	in.asNets = func(as string) ([]string, bool) { return []string{"20.0.0.0/8"}, true }
	wantCode(t, diagnose(in), "DIRECT_BIG", DiagWarn)
	in.asNets = func(as string) ([]string, bool) { return nil, false }
	noCode(t, diagnose(in), "DIRECT_BIG")

	// the setting makes direct rules meaningless: nothing to say
	in.cfg.Rest = config.RestDirect
	in.cfg.DirectNetworks = []string{"AS13335"}
	noCode(t, diagnose(in), "DIRECT_CDN_AS")
}

func TestDiagHyperV(t *testing.T) {
	in := baseIn()
	in.goos = "windows"
	in.env.GWOK = false
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "vEthernet (External)", "192.168.1.1", 25, 0)})
	d := wantCode(t, diagnose(in), "HYPERV_UPLINK", DiagWarn)
	if !strings.Contains(d.TextEN, "vEthernet (External)") {
		t.Errorf("%s", d.TextEN)
	}
	// a physical gateway was found, but the vSwitch route is better
	in.env.GWOK = true
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "vEthernet (External)", "192.168.1.1", 25, 0), orow("0.0.0.0/0", "eth0", "192.168.1.1", 50, 0)})
	wantCode(t, diagnose(in), "HYPERV_UPLINK", DiagWarn)
	// ... and when the physical one is better, nothing
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "vEthernet (WSL)", "172.20.0.1", 5000, 0), orow("0.0.0.0/0", "eth0", "192.168.1.1", 50, 0)})
	noCode(t, diagnose(in), "HYPERV_UPLINK")
	// Windows only
	in.goos = "linux"
	in.env.GWOK = false
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "vEthernet (External)", "192.168.1.1", 25, 0)})
	noCode(t, diagnose(in), "HYPERV_UPLINK")
}

func TestDiagCorpOnLink(t *testing.T) {
	in := baseIn()
	in.cfg.Networks = []string{"192.0.2.0/24"} // a corp rule: routes into the corp VPN are made
	in.tbl = newTable([]OSRoute{orow("10.30.0.0/16", "wgcorp", "", 0, 0)})
	wantCode(t, diagnose(in), "CORP_ONLINK", DiagInfo)
	// the network of the adapter itself is on-link by nature
	in.tbl = newTable([]OSRoute{orow("10.10.0.0/16", "wgcorp", "", 0, 0)})
	noCode(t, diagnose(in), "CORP_ONLINK")
	in.tbl = newTable([]OSRoute{orow("10.10.0.0/16", "wgcorp", "10.10.0.1", 0, 0)})
	noCode(t, diagnose(in), "CORP_ONLINK")
	in.tbl = newTable([]OSRoute{orow("10.30.0.0/16", "wgcorp", "", 0, 0)})
	in.cfg.CorpGateway = "10.10.0.1"
	noCode(t, diagnose(in), "CORP_ONLINK")
	// no corp rule: the lack of a next hop changes nothing
	in.cfg.CorpGateway = ""
	in.cfg.Networks = nil
	noCode(t, diagnose(in), "CORP_ONLINK")
}

// A corp route without a next hop is planned and validated as it is: the
// gateway of the route stays empty (on-link / point-to-point).
func TestPlanCorpRouteWithoutNextHop(t *testing.T) {
	r := config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: ViaCorp, Metric: ownMetric}
	if err := config.ValidateRoute(r); err != nil {
		t.Fatalf("a corp route without a gateway is refused: %v", err)
	}
	hr := hostRoutes([]string{"10.10.0.1"}, "wgcorp", "", ViaCorp, nil)
	if len(hr) != 1 || hr[0].Gateway != "" || hr[0].Dest != "10.10.0.1/32" {
		t.Errorf("%+v", hr)
	}
}

func TestDiagOrderAndText(t *testing.T) {
	list := []Diag{
		{Code: "B", Level: DiagInfo, TextEN: "b", TextRU: "б"},
		{Code: "A", Level: DiagWarn, TextEN: "a", TextRU: "а", AdviceEN: "do", AdviceRU: "сделайте"},
		{Code: "C", Level: DiagDanger, TextEN: "c", TextRU: "ц"},
		{Code: "A0", Level: DiagWarn, TextEN: "a0", TextRU: "а0"},
	}
	diagSort(list)
	if got := strings.Join(codes(list), ","); got != "C,A,A0,B" {
		t.Errorf("order %s", got)
	}
	if WorstDiag(list) != DiagDanger || WorstDiag(nil) != 0 {
		t.Error("worst")
	}
	if got := DiagSummary(list, false); got != "1 danger, 2 warnings, 1 notes" {
		t.Errorf("summary %q", got)
	}
	if DiagSummary(nil, true) != "" {
		t.Error("summary of nothing")
	}
	if got := list[1].Line(false); got != "[warn] A: a -> do" {
		t.Errorf("line %q", got)
	}
	if got := list[1].Line(true); !strings.Contains(got, "сделайте") {
		t.Errorf("line ru %q", got)
	}
	if DiagWarn.String() != "warn" || DiagLevel(0).String() != "?" {
		t.Error("level names")
	}
}

// The text of adapters comes from the OS: control characters must not get to the terminal.
func TestDiagTextsAreSafe(t *testing.T) {
	in := baseIn()
	in.env.Corp.Name = "wg\x1b[31mcorp"
	in.env.Ifs[0] = in.env.Corp
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", in.env.Corp.Name, "", 10, 0)})
	for _, d := range diagnose(in) {
		if strings.ContainsAny(d.TextEN+d.TextRU+d.AdviceEN+d.AdviceRU, "\x1b\x00\x07") {
			t.Errorf("%s: control character in %q", d.Code, d.TextEN)
		}
	}
}

// Every code has both texts, a level and an advice that is not empty for the
// findings that ask for an action; the codes are not repeated by mistake.
func TestDiagAllDetectorsFire(t *testing.T) {
	in := baseIn()
	in.goos = "windows"
	in.cfg.Domains = []string{"corp.example"}
	in.cfg.Networks = []string{"192.168.0.0/16", "172.16.0.0/12"}
	in.cfg.DirectNetworks = []string{"AS13335", "11.0.0.0/8"}
	in.env.Ifs = append(in.env.Ifs, adapter("docker0", "", "172.17.0.1/16"), adapter("OpenVPN TAP", "OpenVPN", "10.8.0.2/24"))
	in.env.Corp.Provider = "Cisco Secure Client"
	in.cl = clientcfg.Result{
		Proxy:    clientcfg.Proxy{Known: true, Enabled: true, Server: "127.0.0.1:1", Source: "WinINET"},
		Tun:      []clientcfg.TunCfg{{Client: "sing-box", Tun: true, StrictRoute: true, FakeIP: true}},
		GPOKnown: true, GPONRPT: 1, OvpnBlockDNS: "a.ovpn", CiscoFailClosed: true,
	}
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "wgcorp", "", 1, 0), orow("0.0.0.0/0", "vEthernet (External)", "192.168.1.1", 25, 0), orow("198.51.100.7/32", "eth0", "192.168.1.1", 0, 0)})
	got := diagnose(in)
	for _, c := range []string{"PROXY_ON", "STRICT_ROUTE", "FAKE_IP", "CORP_FULL_TUNNEL", "CORP_LOCKDOWN", "BLOCK_OUTSIDE_DNS", "GPO_NRPT",
		"OVERLAP_LAN", "OVERLAP_ADAPTER", "DIRECT_CDN_AS", "HYPERV_UPLINK"} {
		if find(got, c) == nil {
			t.Errorf("no %s among %v", c, codes(got))
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Level < got[i].Level {
			t.Errorf("not sorted: %v", codes(got))
		}
	}
}
