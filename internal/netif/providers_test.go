package netif

import "testing"

func TestParseNCList(t *testing.T) {
	out := `Available network connection services in the current set (*=enabled):
* (Disconnected)   B32CA991-A807-4026-B43F-8E72A538F4E2 VPN (llc.itdev.incy) "incy"                           [VPN:llc.itdev.incy]
* (Connected)      C5EF43C2-D4E8-4140-AC11-CAB086EAAE74 VPN (com.blancvpn.app) "BlancVPN"                       [VPN:com.blancvpn.app]
`
	got := parseNCList(out)
	if len(got) != 2 {
		t.Fatalf("got %d services: %+v", len(got), got)
	}
	want := ncService{ID: "C5EF43C2-D4E8-4140-AC11-CAB086EAAE74", Name: "BlancVPN", Bundle: "com.blancvpn.app", Connected: true}
	if got[1] != want || got[0].Connected || got[0].Name != "incy" {
		t.Errorf("got %+v", got)
	}
}

func TestParseLsofUtun(t *testing.T) {
	out := "p448\nf4\nn[ctl com.apple.net.utun_control id 5 unit 1]\np25571\nf9\nn[ctl com.apple.net.utun_control id 5 unit 226]\np99\nn[ctl com.apple.netsrc id 7 unit 10]\n"
	got := parseLsofUtun(out)
	if got["utun0"] != 448 || got["utun225"] != 25571 || len(got) != 2 {
		t.Errorf("got %v", got)
	}
}

func TestParsePSAndAppName(t *testing.T) {
	procs := parsePS("  317 /Library/Application Support/Checkpoint/Endpoint Connect/TracSrvWrapper\n25571 /Applications/Happ.app/Contents/MacOS/core/xray\n")
	if procs[317] != "/Library/Application Support/Checkpoint/Endpoint Connect/TracSrvWrapper" {
		t.Errorf("path with spaces: %q", procs[317])
	}
	if got := appName(procs[25571]); got != "Happ" {
		t.Errorf("appName = %q", got)
	}
	if p, ok := findProvider(procs[317]); !ok || p.Name != "Check Point" || p.Role != KindCorp {
		t.Errorf("Check Point not recognised: %+v", p)
	}
}

func TestProxyAddr(t *testing.T) {
	for addr, want := range map[string]bool{"169.254.10.2": true, "198.18.0.1": true, "10.0.69.116": false, "172.19.0.1": true} {
		if proxyAddr(addr) != want {
			t.Errorf("proxyAddr(%s) != %v", addr, want)
		}
	}
}

func TestResolve(t *testing.T) {
	ifs := []Info{
		{Name: "utun0", Up: true, Kind: KindVPN}, // system tunnel, no address
		{Name: "utun3", Up: true, Addrs: []string{"10.9.9.9"}, Kind: KindVPN},
		{Name: "utun4", Up: true, Addrs: []string{"10.0.69.116"}, Kind: KindCorp, Provider: "Check Point"},
		{Name: "utun5", Up: true, Addrs: []string{"198.18.0.1"}, Kind: KindVPN, Provider: "BlancVPN"},
	}
	check := func(sel string, kind Kind, skip, want string) {
		t.Helper()
		got, ok := resolve(ifs, sel, kind, skip)
		if want == "" && ok || want != "" && got.Name != want {
			t.Errorf("resolve(%q, %s, skip %q) = %q %v, want %q", sel, kind, skip, got.Name, ok, want)
		}
	}
	check("auto", KindCorp, "", "utun4")
	check("", KindVPN, "utun4", "utun5") // a recognised client beats an unknown tunnel
	check("blancvpn", KindVPN, "", "utun5")
	check("utun3", KindVPN, "", "utun3")
	check("Happ", KindVPN, "", "")
	check("utun0", KindVPN, "", "") // not connected
	check("Check Point", KindCorp, "utun4", "")
}

func TestOwnerKind(t *testing.T) {
	if n, k := ownerKind("BlancVPN"); n != "BlancVPN" || k != KindVPN {
		t.Errorf("BlancVPN -> %s %s", n, k)
	}
	if _, k := ownerKind("Some Unknown Client"); k != KindVPN {
		t.Errorf("unknown owner of a tunnel should be a vpn, got %s", k)
	}
}

func TestParseNMActive(t *testing.T) {
	out := "Home Wi-Fi:802-11-wireless:wlp2s0\nWork\\: Check Point:vpn:tun0\nwg-home:wireguard:wg0\nlo:loopback:lo\n"
	got := parseNMActive(out)
	if got["tun0"] != "Work: Check Point" || got["wg0"] != "wg-home" || len(got) != 2 {
		t.Errorf("got %v", got)
	}
}

func TestParseFdinfoIff(t *testing.T) {
	if got := parseFdinfoIff("pos:\t0\nflags:\t0100002\nmnt_id:\t26\niff:\ttun0\n"); got != "tun0" {
		t.Errorf("got %q", got)
	}
	if got := parseFdinfoIff("pos:\t0\n"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestGuessOwners(t *testing.T) {
	ifs := []Info{
		{Name: "en0", Up: true, Addrs: []string{"192.168.1.139"}, Kind: KindPhysical},
		{Name: "utun4", Up: true, Addrs: []string{"10.0.69.116"}, Kind: KindVPN},
		{Name: "utun225", Up: true, Addrs: []string{"169.254.10.2"}, Kind: KindVPN},
		{Name: "utun5", Up: true, Addrs: []string{"198.18.0.1"}, Kind: KindVPN},
	}
	res := map[string]string{"utun5": "BlancVPN"} // known for sure
	procs := []string{
		"/Library/Application Support/Checkpoint/Endpoint Connect/TracSrvWrapper",
		"/Applications/Happ.app/Contents/MacOS/happd",
		"/Applications/BlancVPN.app/Contents/MacOS/BlancVPN",
		"C:\\Program Files\\Happ\\Happ.exe", // duplicates are fine
	}
	guessOwners(res, ifs, procs)
	want := map[string]string{"utun4": "Check Point", "utun225": "Happ", "utun5": "BlancVPN"}
	for k, v := range want {
		if res[k] != v {
			t.Errorf("%s = %q, want %q", k, res[k], v)
		}
	}
	if _, ok := res["en0"]; ok {
		t.Error("physical adapters are never guessed")
	}
}
