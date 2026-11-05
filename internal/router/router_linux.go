//go:build linux

package router

import "os"

// PrivHint tells the user how to get the rights Apply and Reset need.
const PrivHint = "run with sudo"

// IsPrivileged reports whether routes can be changed.
func IsPrivileged() bool { return os.Geteuid() == 0 }

const (
	// ownMetric is the RTA_PRIORITY of our routes. They are told from a VPN
	// client's by the protocol tag (routeProto), not by the metric.
	ownMetric = 1
	// routesTagged: the routing table marks routes as ours (rtm_protocol).
	routesTagged = true
)

// physicalGateway is the default route of a non-VPN adapter with the lowest
// metric, read from the routing table.
func physicalGateway() (Gateway, bool) {
	rs, err := listRoutes()
	if err != nil {
		return Gateway{}, false
	}
	return gatewayFrom(rs)
}

// the baseline code tells our routes by this metric on every build
const _ = uint(ownMetric-linOwnMetric) + uint(linOwnMetric-ownMetric)

// v6Halves: ::/1 and 8000::/1 are planned for a home VPN that has IPv6.
const v6Halves = true
