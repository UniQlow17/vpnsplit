//go:build windows

package router

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// PrivHint tells the user how to get the rights Apply and Reset need.
const PrivHint = "run the terminal as Administrator"

// IsPrivileged reports whether routes can be changed: the process token is elevated.
func IsPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

const (
	// ownMetric is the RouteMetric of our routes. Windows has no field to tag
	// a route with, so a characteristic low value does it, together with the
	// journal: a route is removed only if prefix, adapter, next hop AND this
	// metric match what the journal says. The OS adds the metric of the adapter
	// (1-50 for typical VPN and LAN adapters), so the sum stays low enough for
	// our routes to win over a client's route to the same prefix that goes
	// through another adapter; the longest prefix decides before the metric
	// anyway. 3 is not what the others use: DHCP and most VPN clients create
	// routes with metric 0, 1 (route.exe default, and what older versions of
	// this tool used: Route.Legacy) or 256+, and interface-wide automatic
	// metrics are added on top, not stored in the route.
	ownMetric = 3
	// routesTagged: the routing table does not mark routes as ours.
	routesTagged = false
)

// ifaceIndex finds the adapter by name. found is false only if the list of
// adapters was read and the adapter is not in it.
func ifaceIndex(name string) (idx int, found bool, err error) { return ifaceByName(name) }

// keyRow builds the lookup key of a journal route.
func keyRow(r config.Route, ifIndex int) (*mibIPForwardRow2, error) {
	p, err := netip.ParsePrefix(r.Dest)
	if err != nil {
		return nil, err
	}
	row := new(mibIPForwardRow2)
	if err := forwardKey(row, ifIndex, p.Masked(), addrOrZero(r.Gateway)); err != nil {
		return nil, err
	}
	return row, nil
}

// addRoute creates an active (not persistent) route. The key of a route in
// Windows is prefix + adapter + next hop, so a client's route with the same
// key makes the call fail with ERROR_OBJECT_ALREADY_EXISTS: it stays its own.
func addRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	idx, found, err := ifaceIndex(r.Iface)
	if err == nil && !found {
		err = fmt.Errorf("adapter %s does not exist", r.Iface)
	}
	if err != nil {
		return err
	}
	row, err := keyRow(r, idx)
	if err != nil {
		return err
	}
	row.Metric = uint32(r.EffMetric())
	row.Protocol = mibIPProtoNetMgmt
	row.Origin = nlroManual
	row.ValidLifetime, row.PreferredLifetime = infiniteLifetime, infiniteLifetime
	err = createForwardEntry(row)
	switch {
	case errors.Is(err, errObjectAlreadyExists):
		// The key of a Windows route is prefix + adapter + next hop: a route is
		// there already. Whether it is ours from a run cut short (the journal
		// lists it) is for the reconciler to say, which knows the journal: here it
		// is never taken as ours on its looks alone, a client or the user can
		// create the very same row.
		return fmt.Errorf("%w: %v", errExists, err)
	case err != nil:
		return fmt.Errorf("add route %s on %s: %w", r.Dest, r.Iface, err)
	}
	return nil
}

// delRoute removes only our route: same prefix, adapter and next hop, and our
// metric, protocol and origin, so a VPN client's own route to the same place
// stays; for it errNotOurs is returned, and the caller reports it as left.
//
// A route of an older version (Route.FromLegacy) was made by route.exe, and
// which Origin the OS gives such a row has not been checked on a live system.
// So for it the metric must be 1 (what that version always used) and the
// protocol NETMGMT, while the origin may be anything: prefix, adapter and next
// hop have matched already when the row is found. Its metric is 1 whatever the
// file said (EffMetric), which a user cannot change in the journal.
func delRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	idx, found, err := ifaceIndex(r.Iface)
	if err != nil {
		return err // the list of adapters could not be read: nothing is known about the adapter
	}
	if !found {
		return nil // adapter is gone, so are its routes
	}
	row, err := keyRow(r, idx)
	if err != nil {
		return err
	}
	if err := getForwardEntry(row); err != nil {
		if errors.Is(err, errNotFound) || errors.Is(err, errFileNotFound) {
			return nil
		}
		return fmt.Errorf("look up route %s on %s: %w", r.Dest, r.Iface, err)
	}
	if !rowIsOurs(row, r) {
		return fmt.Errorf("%w: a route to %s on %s with another metric, protocol or origin is somebody else's", errNotOurs, r.Dest, r.Iface)
	}
	if err := deleteForwardEntry(row); err != nil && !errors.Is(err, errNotFound) && !errors.Is(err, errFileNotFound) {
		return fmt.Errorf("remove route %s on %s: %w", r.Dest, r.Iface, err)
	}
	return nil
}

// ReplaceRoute puts next in the place of old, our route (see replacer). When
// the key of the two is the same (prefix, adapter and next hop: only the metric
// differs) the route is changed in place by SetIpForwardEntry2, so that there is
// no moment without a route and nothing to put back if it fails; and only if
// the route there is ours, never a client's. Otherwise next is added and old
// removed.
func (osBackend) ReplaceRoute(old, next config.Route) error {
	if err := config.ValidateRoute(next); err != nil {
		return err
	}
	if routeKey(old) != routeKey(next) {
		if err := addRoute(next); err != nil {
			return err
		}
		return ignoreNotOurs(delRoute(old))
	}
	idx, found, err := ifaceIndex(next.Iface)
	if err == nil && !found {
		err = fmt.Errorf("adapter %s does not exist", next.Iface)
	}
	if err != nil {
		return err
	}
	row, err := keyRow(next, idx)
	if err != nil {
		return err
	}
	if err := getForwardEntry(row); err != nil {
		if errors.Is(err, errNotFound) || errors.Is(err, errFileNotFound) {
			return addRoute(next) // the old one is gone: there is nothing to change
		}
		return fmt.Errorf("look up route %s on %s: %w", next.Dest, next.Iface, err)
	}
	if !rowIsOurs(row, old) && !rowIsOurs(row, next) {
		return fmt.Errorf("%w: the route there is not ours", errExists)
	}
	row.Metric = uint32(next.EffMetric())
	if err := setForwardEntry(row); err != nil {
		return fmt.Errorf("change route %s on %s: %w", next.Dest, next.Iface, err)
	}
	return nil
}

var _ replacer = osBackend{}

// listRoutes reads the IPv4 routing table.
// The metric of the adapter (adapterMetrics) is not read here: only the choice
// of the physical gateway needs it, and the table is read for every drift check.
func listRoutes() ([]OSRoute, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("read routes: list of adapters: %w", err) // the table is unknown, not empty
	}
	names := map[int]string{}
	for _, i := range ifs {
		names[i.Index] = i.Name
	}
	var out []OSRoute
	err = forwardRows(func(row *mibIPForwardRow2) {
		dst, ok := row.DestinationPrefix.Prefix.v4()
		if !ok {
			return
		}
		p, err := dst.Prefix(int(row.DestinationPrefix.PrefixLength))
		if err != nil {
			return
		}
		gw, _ := row.NextHop.v4()
		if gw.IsUnspecified() {
			gw = netip.Addr{}
		}
		out = append(out, OSRoute{
			Dest: p, Iface: names[int(row.InterfaceIndex)], IfIndex: int(row.InterfaceIndex),
			Gateway: gw, Metric: int(row.Metric), NotOurs: !rowCreatedLikeOurs(row),
			Proto: int(row.Protocol), Origin: int(row.Origin), LUID: row.InterfaceLuid,
		})
	})
	return out, err
}

// adapterMetrics is the IPv4 metric of each adapter by index (the OS adds it
// to the metric of a route); nil if it cannot be read.
func adapterMetrics() map[int]int {
	size := uint32(15000)
	var buf []byte
	for range 3 {
		buf = make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER|windows.GAA_FLAG_SKIP_UNICAST,
			0, aa, &size)
		if err == nil {
			res := map[int]int{}
			for a := aa; a != nil; a = a.Next {
				if a.IfIndex == 0 { // an adapter with no IPv4 has no index here
					continue
				}
				res[int(a.IfIndex)] = int(a.Ipv4Metric)
			}
			return res
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil
		}
	}
	return nil
}

// physicalGateway is the default route of a non-VPN adapter with the lowest
// total metric (route + adapter), read from the routing table.
func physicalGateway() (Gateway, bool) {
	rs, err := listRoutes()
	if err != nil {
		return Gateway{}, false
	}
	metrics := adapterMetrics()
	for i := range rs {
		rs[i].IfMetric = metrics[rs[i].IfIndex]
	}
	return gatewayFrom(rs)
}

// the baseline code tells our routes by this metric on every build
const _ = uint(ownMetric-winOwnMetric) + uint(winOwnMetric-ownMetric)

// the same for the protocol of the routes we create
const _ = uint(mibIPProtoNetMgmt-mibNetMgmt) + uint(mibNetMgmt-mibIPProtoNetMgmt)
