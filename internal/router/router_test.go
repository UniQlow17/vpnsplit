package router

import (
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

func TestParseDefaultGW(t *testing.T) {
	darwin := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#21            UCSg                utun5
default            192.168.1.1        UGScIg                en0
1                  169.254.10.1       UGSc              utun225
`
	if gw, ok := parseDefaultGW(darwin); !ok || gw != (Gateway{"en0", "192.168.1.1"}) {
		t.Errorf("darwin: %+v %v", gw, ok)
	}
	linux := "default via 10.8.0.1 dev tun0 \ndefault via 192.168.0.1 dev wlp2s0 proto dhcp metric 600\n"
	if gw, ok := parseDefaultGW(linux); !ok || gw != (Gateway{"wlp2s0", "192.168.0.1"}) {
		t.Errorf("linux: %+v %v", gw, ok)
	}
	if _, ok := parseDefaultGW("default link#21 UCSg utun5\n"); ok {
		t.Error("VPN-only default must not count as physical")
	}
}

func TestParseSCArray(t *testing.T) {
	out := `<dictionary> {
  SearchDomains : <array> {
    0 : moscow.alfaintra.net
    1 : alfaintra.net
  }
  ServerAddresses : <array> {
    0 : 10.226.0.5
    1 : 10.224.0.5
  }
}`
	if got := parseSCArray(out, "ServerAddresses"); len(got) != 2 || got[0] != "10.226.0.5" || got[1] != "10.224.0.5" {
		t.Errorf("servers %v", got)
	}
	if got := parseSCArray(out, "SearchDomains"); len(got) != 2 || got[1] != "alfaintra.net" {
		t.Errorf("domains %v", got)
	}
}

func TestSync(t *testing.T) {
	cfg := config.New()
	up := Env{Corp: netif.Info{Name: "utun4"}, CorpOK: true, Home: netif.Info{Name: "utun225"}, HomeOK: true}
	st := &config.State{}

	if apply, reset := Sync(cfg, up, st); !apply || reset {
		t.Error("fresh start with VPNs up must apply")
	}
	st.Sig = Sig(cfg, up)
	if apply, reset := Sync(cfg, up, st); apply || reset {
		t.Error("nothing changed, nothing to do")
	}
	switched := up
	switched.Home = netif.Info{Name: "utun5"} // Happ -> BlancVPN
	if apply, _ := Sync(cfg, switched, st); !apply {
		t.Error("home VPN moved to another adapter: must re-apply")
	}
	cfg.DirectDomains = []string{"telework.example.ru"}
	if apply, _ := Sync(cfg, up, st); !apply {
		t.Error("rules changed: must re-apply")
	}
	if apply, reset := Sync(cfg, Env{}, st); apply || !reset {
		t.Error("all VPNs gone: must reset")
	}
	if _, reset := Sync(cfg, Env{}, &config.State{}); reset {
		t.Error("nothing applied: nothing to reset")
	}
}

func TestParseResolvectl(t *testing.T) {
	if got := parseResolvectl("Link 5 (tun0): 10.226.0.5 10.224.0.5\n"); len(got) != 2 || got[1] != "10.224.0.5" {
		t.Errorf("got %v", got)
	}
	if got := parseResolvectl("Link 2 (wlp2s0):\n"); len(got) != 0 {
		t.Errorf("empty link: %v", got)
	}
}

func TestParseResolvConf(t *testing.T) {
	servers, search := parseResolvConf("# generated\nnameserver 10.226.0.5\nnameserver fe80::1\nsearch moscow.corp.example corp.example\n")
	if len(servers) != 1 || servers[0] != "10.226.0.5" || len(search) != 2 {
		t.Errorf("servers %v search %v", servers, search)
	}
}
