//go:build windows

package router

import "testing"

const routePrintSample = `Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
         10.0.0.0        255.0.0.0         On-link       10.1.1.5      2
         10.0.0.0        255.0.0.0       10.1.1.1       10.1.1.5      3
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          10.8.0.0        255.255.0.0       10.1.1.1       1
`

func TestTableHasRoute(t *testing.T) {
	for _, c := range []struct {
		ip, mask, gw string
		want         bool
	}{
		{"10.0.0.0", "255.0.0.0", "0.0.0.0", true},
		{"10.0.0.0", "255.0.0.0", "10.1.1.1", true},
		{"10.0.0.0", "255.0.0.0", "10.9.9.9", false},
		{"10.8.0.0", "255.255.0.0", "10.1.1.1", false}, // persistent table only
		{"11.0.0.0", "255.0.0.0", "0.0.0.0", false},
	} {
		if got := tableHasRoute(routePrintSample, c.ip, c.mask, c.gw); got != c.want {
			t.Errorf("%v: got %v", c, got)
		}
	}
}

// Read-only: the loopback route exists on every machine.
func TestRouteListedReal(t *testing.T) {
	listed, known := routeListed("127.0.0.0", "255.0.0.0", "0.0.0.0")
	if !known || !listed {
		t.Errorf("loopback route: listed=%v known=%v", listed, known)
	}
	if listed, known := routeListed("203.0.113.0", "255.255.255.0", "0.0.0.0"); known && listed {
		t.Error("TEST-NET route is not expected")
	}
}
