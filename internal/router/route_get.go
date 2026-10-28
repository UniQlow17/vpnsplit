package router

import (
	"net/netip"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// BSD `route -n get` output (macOS). The parser has no build constraint so that
// it is tested on every OS; the command itself is run in router_darwin.go.

// routeInfo is what `route -n get <destination>` says about a route.
type routeInfo struct {
	Gateway string   // "": on-link ("link#12" is also on-link)
	Iface   string   // "interface:"
	Flags   []string // "flags: <UP,GATEWAY,DONE,STATIC,PROTO2>"
}

// parseRouteGet reads the output of `route -n get`, run in the C locale:
//
//	   route to: 10.10.0.0
//	destination: 10.10.0.0
//	       mask: 255.255.0.0
//	    gateway: 10.200.0.1
//	  interface: utun3
//	      flags: <UP,GATEWAY,DONE,STATIC,PROTO2>
func parseRouteGet(out string) routeInfo {
	var ri routeInfo
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "gateway":
			if !strings.HasPrefix(v, "link#") {
				ri.Gateway = v
			}
		case "interface":
			ri.Iface = v
		case "flags":
			v = strings.TrimSuffix(strings.TrimPrefix(v, "<"), ">")
			for _, f := range strings.Split(v, ",") {
				if f = strings.TrimSpace(f); f != "" {
					ri.Flags = append(ri.Flags, f)
				}
			}
		}
	}
	return ri
}

func (ri routeInfo) hasFlag(f string) bool {
	for _, x := range ri.Flags {
		if x == f {
			return true
		}
	}
	return false
}

// bsdOwns reports whether the route found by `route get` is the route of the
// journal entry r: the next hop (or, for an on-link route, the adapter) is the
// one the journal says, and the route carries RTF_PROTO2, our tag. Where the
// route tool has no -proto2 (tagSupported false) routes are created without the
// tag, and the journal with the next hop and the adapter is all there is to go
// by: a client's route with the very same destination, next hop and adapter
// would be taken for ours.
func bsdOwns(ri routeInfo, r config.Route, tagSupported bool) bool {
	if r.Gateway != "" {
		a, e1 := netip.ParseAddr(ri.Gateway)
		b, e2 := netip.ParseAddr(r.Gateway)
		if e1 != nil || e2 != nil || a != b {
			return false
		}
	} else if ri.Iface != r.Iface || ri.Gateway != "" {
		return false
	}
	return ri.hasFlag("PROTO2") || !tagSupported
}
