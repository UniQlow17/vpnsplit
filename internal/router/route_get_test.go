package router

import (
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

const getTagged = `   route to: 10.10.0.0
destination: 10.10.0.0
       mask: 255.255.0.0
    gateway: 10.200.0.1
  interface: utun3
      flags: <UP,GATEWAY,DONE,STATIC,PROTO2>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1380         0
`

const getOnLink = `   route to: 10.10.0.0
destination: 10.10.0.0
       mask: 255.255.0.0
    gateway: link#12
  interface: utun3
      flags: <UP,DONE,STATIC,PROTO2>
`

func TestParseRouteGet(t *testing.T) {
	ri := parseRouteGet(getTagged)
	if ri.Gateway != "10.200.0.1" || ri.Iface != "utun3" || !ri.hasFlag("PROTO2") || !ri.hasFlag("GATEWAY") || ri.hasFlag("PROTO1") {
		t.Errorf("%+v", ri)
	}
	ol := parseRouteGet(getOnLink)
	if ol.Gateway != "" || ol.Iface != "utun3" || !ol.hasFlag("PROTO2") {
		t.Errorf("%+v", ol)
	}
	if e := parseRouteGet(""); e.Gateway != "" || e.Iface != "" || len(e.Flags) != 0 {
		t.Errorf("%+v", e)
	}
}

func TestBSDOwnership(t *testing.T) {
	viaGw := config.Route{Dest: "10.10.0.0/16", Iface: "utun3", Gateway: "10.200.0.1"}
	onLink := config.Route{Dest: "10.10.0.0/16", Iface: "utun3"}
	tagged, untagged := parseRouteGet(getTagged), parseRouteGet("gateway: 10.200.0.1\ninterface: utun3\nflags: <UP,GATEWAY,DONE,STATIC>\n")
	other := parseRouteGet("gateway: 10.200.0.77\ninterface: utun3\nflags: <UP,GATEWAY,DONE,STATIC,PROTO2>\n")
	for _, c := range []struct {
		name      string
		ri        routeInfo
		r         config.Route
		supported bool
		want      bool
	}{
		{"tagged, same gateway", tagged, viaGw, true, true},
		{"tagged but another gateway", other, viaGw, true, false},
		{"a client's route: same gateway, no tag", untagged, viaGw, true, false},
		{"no -proto2 in route(8): the journal and the gateway are all there is", untagged, viaGw, false, true},
		{"no -proto2, another gateway", other, viaGw, false, false},
		{"on-link, tagged, same adapter", parseRouteGet(getOnLink), onLink, true, true},
		{"on-link route of the journal, but the route found has a gateway", tagged, onLink, true, false},
		{"on-link, another adapter", parseRouteGet("gateway: link#4\ninterface: utun9\nflags: <UP,PROTO2>\n"), onLink, true, false},
		{"on-link, untagged", parseRouteGet("gateway: link#4\ninterface: utun3\nflags: <UP>\n"), onLink, true, false},
	} {
		if got := bsdOwns(c.ri, c.r, c.supported); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
