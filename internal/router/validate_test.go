package router

import (
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

func routeFor(gateway string) config.Route {
	return config.Route{Dest: "10.0.0.0/8", Iface: "Ethernet", Gateway: gateway, Via: ViaCorp}
}

func TestValidServers(t *testing.T) {
	got := validServers([]string{"10.0.0.1", " 10.0.0.2 ", "::1", "10.0.0.1", "1.1.1.1'; calc", "", "fe80::1%eth0"})
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Errorf("%q", got)
	}
}
