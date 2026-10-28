package router

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/clientcfg"
	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// Diagnose with the system replaced by fakes: it gives a list, reuses it for
// the same setup, and looks again when the default routes change.
func TestDiagnoseReadsAndCaches(t *testing.T) {
	routes := []OSRoute{orow("0.0.0.0/0", "eth0", "192.168.1.1", 100, 0)}
	var reads, scans int
	d := &diagnoser{
		routesFn: func() ([]OSRoute, error) { reads++; return routes, nil },
		rulesFn:  func() ([]OSRule, error) { return nil, nil },
		scanFn:   func() clientcfg.Result { scans++; return clientcfg.Result{} },
	}
	if got := d.run(nil, Env{}, nil); got != nil || reads != 0 {
		t.Errorf("without a config: %v, %d reads", got, reads)
	}
	cfg := config.New()
	e := diagEnv()
	a := d.run(cfg, e, &config.State{})
	d.mu.Lock()
	d.list = append(d.list[:0:0], Diag{Code: "SENTINEL", Level: DiagInfo})
	d.mu.Unlock()
	b := d.run(cfg, e, &config.State{})
	if len(b) != 1 || b[0].Code != "SENTINEL" || scans != 1 {
		t.Errorf("not reused: %v (first %v), %d scans", codes(b), codes(a), scans)
	}
	// the default routes changed: the findings are made again
	routes = []OSRoute{orow("0.0.0.0/0", "eth0", "192.168.1.1", 100, 0), orow("0.0.0.0/0", "wgcorp", "", 50, 0)}
	c := d.run(cfg, e, &config.State{})
	if find(c, "SENTINEL") != nil || scans != 2 {
		t.Errorf("an old answer for other routes: %v", codes(c))
	}
	if find(c, "CORP_FULL_TUNNEL") == nil {
		t.Errorf("the new default route is not seen: %v", codes(c))
	}
	cfg.CorpDNS = "10.0.0.1" // another setup: read again
	if x := d.run(cfg, e, &config.State{}); find(x, "SENTINEL") != nil || scans != 3 {
		t.Error("an old answer for another setup")
	}
	// a broken reader does not stop the caller
	d.routesFn = func() ([]OSRoute, error) { panic("boom") }
	if got := d.run(cfg, e, nil); got != nil {
		t.Errorf("after a panic: %v", got)
	}
}

// The real reader of the scan waits a bounded time for a hung scan (see
// clientcfg); here the diagnoser is given a scan that returns late and it must
// still have been called once, not once per poll.
func TestDiagnoseCallsScanOncePerFreshness(t *testing.T) {
	var mu sync.Mutex
	scans := 0
	d := &diagnoser{
		routesFn: func() ([]OSRoute, error) { return nil, nil },
		rulesFn:  func() ([]OSRule, error) { return nil, nil },
		scanFn: func() clientcfg.Result {
			mu.Lock()
			scans++
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			return clientcfg.Result{}
		},
	}
	cfg, e := config.New(), diagEnv()
	for range 5 {
		d.run(cfg, e, nil)
	}
	if scans != 1 {
		t.Errorf("%d scans", scans)
	}
}

// The adapter metric of Windows counts in the comparison of default routes.
func TestDiagWindowsIfMetric(t *testing.T) {
	in := baseIn()
	in.goos = "windows"
	vpn := orow("0.0.0.0/0", "wgcorp", "", 1, 0)
	vpn.IfMetric = 100 // 101 in total
	phys := orow("0.0.0.0/0", "eth0", "192.168.1.1", 25, 0)
	phys.IfMetric = 25 // 50 in total
	in.tbl = newTable([]OSRoute{vpn, phys})
	noCode(t, diagnose(in), "CORP_FULL_TUNNEL") // a winner by the metric of the route alone
	vpn.IfMetric = 5                            // 6 in total
	in.tbl = newTable([]OSRoute{vpn, phys})
	wantCode(t, diagnose(in), "CORP_FULL_TUNNEL", DiagWarn)

	// Hyper-V: the vSwitch route wins over eth0 only with the metrics of the adapters counted
	v := orow("0.0.0.0/0", "vEthernet (External)", "192.168.1.1", 5, 0)
	v.IfMetric = 25 // 30
	eth := orow("0.0.0.0/0", "eth0", "192.168.1.1", 25, 0)
	eth.IfMetric = 40 // 65
	in = baseIn()
	in.goos = "windows"
	in.tbl = newTable([]OSRoute{v, eth})
	wantCode(t, diagnose(in), "HYPERV_UPLINK", DiagWarn)
	v.IfMetric = 100 // 105 against 65: the physical route is better
	in.tbl = newTable([]OSRoute{v, eth})
	noCode(t, diagnose(in), "HYPERV_UPLINK")
}

// With nothing that competes with a full tunnel of the corp VPN it is a note.
func TestDiagCorpFullTunnelNoise(t *testing.T) {
	in := baseIn()
	in.tbl = newTable([]OSRoute{orow("0.0.0.0/0", "wgcorp", "", 10, 0)})
	in.cfg.Rest = config.RestKeep
	wantCode(t, diagnose(in), "CORP_FULL_TUNNEL", DiagInfo)
	in.cfg.DirectNetworks = []string{"11.0.0.0/8"}
	wantCode(t, diagnose(in), "CORP_FULL_TUNNEL", DiagWarn)
	in.cfg.DirectNetworks = nil
	in.cfg.Rest = config.RestHome
	wantCode(t, diagnose(in), "CORP_FULL_TUNNEL", DiagWarn)
	in.env.HomeOK = false
	wantCode(t, diagnose(in), "CORP_FULL_TUNNEL", DiagInfo)
}

// The addresses of DNS servers that the OS reports are judged by badServer,
// which knows nothing of fake-ip: a range in a config cannot remove a server.
func TestFakeRangeDoesNotTouchDNSServers(t *testing.T) {
	withFakeRanges(t, "28.0.0.0/8")
	if got := validServers([]string{"28.0.0.2", "198.18.0.2", "127.0.0.1", "8.8.8.8"}); strings.Join(got, ",") != "28.0.0.2,198.18.0.2,8.8.8.8" {
		t.Errorf("servers: %v", got)
	}
	if badServer(netip.MustParseAddr("28.0.0.2")) != "" || badAddr(netip.MustParseAddr("28.0.0.2")) == "" {
		t.Error("badServer and badAddr do not differ for a fake address")
	}
}

// Only the ranges of clients that are running count, and the report names the
// range and the client, not the path of the file.
func TestFakeRangesOnlyOfRunningClients(t *testing.T) {
	res := clientcfg.Result{Tun: []clientcfg.TunCfg{
		{Client: "Mihomo", Path: "/home/x/secret/config.yaml", FakeIP: true, FakeRanges: []netip.Prefix{netip.MustParsePrefix("28.0.0.0/8")}},
		{Client: "sing-box", FakeIP: true, FakeRanges: []netip.Prefix{netip.MustParsePrefix("29.0.0.0/8")}},
	}}
	up := func(name, provider string) netif.Info {
		return netif.Info{Name: name, Up: true, Addrs: []string{"172.19.0.1"}, Provider: provider}
	}
	eth := up("eth0", "")
	if got := fakeRangesFor(res, []netif.Info{eth}); len(got) != 0 {
		t.Errorf("no client runs: %v", got)
	}
	if got := fakeRangesFor(res, []netif.Info{eth, up("tun0", "Clash")}); len(got) != 1 || got[0].p.String() != "28.0.0.0/8" {
		t.Errorf("mihomo runs: %v", got)
	}
	down := up("Meta", "")
	down.Up = false
	if got := fakeRangesFor(res, []netif.Info{eth, down}); len(got) != 0 {
		t.Errorf("a down adapter counts: %v", got)
	}
	if got := fakeRangesFor(res, []netif.Info{eth, up("Meta", "")}); len(got) != 1 {
		t.Errorf("the name of the adapter is not used: %v", got)
	}
	setFakeRanges(fakeRangesFor(res, []netif.Info{eth, up("sb", "sing-box")}))
	t.Cleanup(func() { SetFakeRanges(nil) })
	why := badAddr(netip.MustParseAddr("29.1.1.1"))
	if !strings.Contains(why, "29.0.0.0/8") || !strings.Contains(why, "sing-box") || strings.Contains(why, "secret") {
		t.Errorf("report: %q", why)
	}
	if badAddr(netip.MustParseAddr("28.1.1.1")) != "" {
		t.Error("the range of a client that does not run is in force")
	}
}
