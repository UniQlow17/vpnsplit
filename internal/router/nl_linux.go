//go:build linux

package router

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

const nlTimeout = 10 * time.Second

var nlSeq atomic.Uint32

// nlSock is a NETLINK_ROUTE socket. Every operation opens its own: a socket
// costs microseconds, and operations then never share a reply stream.
type nlSock struct{ fd int }

func nlOpen() (*nlSock, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	tv := unix.NsecToTimeval(int64(nlTimeout))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	return &nlSock{fd}, nil
}

func (s *nlSock) close() { unix.Close(s.fd) }

// do sends one request and returns the payloads of the replies (a dump has
// many) or the errno of the kernel as unix.Errno. The reading of the answer is
// nlExchange, which is tested on every OS.
func (s *nlSock) do(build func(seq uint32) []byte) ([][]byte, error) {
	seq := nlSeq.Add(1)
	req := build(seq)
	out, err := nlExchange(
		func() error { return unix.Sendto(s.fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) },
		func(buf []byte) (int, error) {
			for {
				n, _, err := unix.Recvfrom(s.fd, buf, 0)
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return n, err
			}
		}, seq)
	var ne *nlError
	if errors.As(err, &ne) {
		return nil, unix.Errno(ne.errno)
	}
	return out, err
}

func nlRun(build func(seq uint32) []byte) ([][]byte, error) {
	s, err := nlOpen()
	if err != nil {
		return nil, err
	}
	defer s.close()
	return s.do(build)
}

// nlDumpRun is a dump: asked for again if the kernel says the table changed while it was read.
func nlDumpRun(build func(seq uint32) []byte) ([][]byte, error) {
	return nlDump(func() ([][]byte, error) { return nlRun(build) })
}

// routeSpecOf turns a journal route into a netlink request. gone is true
// when the adapter does not exist (any more); an error means that could not
// be found out.
func routeSpecOf(r config.Route) (s routeSpec, gone bool, err error) {
	p, err := netip.ParsePrefix(r.Dest)
	if err != nil {
		return s, false, err
	}
	s = routeSpec{dest: p.Masked(), gw: addrOrZero(r.Gateway), metric: r.EffMetric(), proto: routeProto, table: r.Table}
	if r.Legacy() {
		s.proto = 0 // routes of older versions carry no tag (delRoute narrows it down for FromLegacy)
	}
	idx, found, err := ifaceByName(r.Iface)
	if err != nil {
		return s, false, err
	}
	if !found {
		return s, true, nil
	}
	s.ifIndex = idx
	return s, false, nil
}

func addRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	s, gone, err := routeSpecOf(r)
	if err == nil && gone {
		err = fmt.Errorf("adapter %s does not exist", r.Iface)
	}
	if err != nil {
		return err
	}
	return sendAddRoute(r, s)
}

func sendAddRoute(r config.Route, s routeSpec) error {
	_, err := nlRun(func(seq uint32) []byte { return buildAddRoute(seq, s) })
	switch {
	case errors.Is(err, unix.EEXIST):
		return fmt.Errorf("%w: %v", errExists, err)
	case err != nil:
		return fmt.Errorf("add route %s dev %s: %w", r.Dest, r.Iface, err)
	}
	return nil
}

// ReplaceRoute puts next in the place of old, our route to the same
// destination (see replacer). When both have the same destination, table and
// metric the kernel allows one of them only: the route there is replaced in
// one step, but only if it is ours, never a client's. Otherwise next is added
// and old removed.
func (osBackend) ReplaceRoute(old, next config.Route) error {
	if err := config.ValidateRoute(next); err != nil {
		return err
	}
	s, gone, err := routeSpecOf(next)
	if err == nil && gone {
		err = fmt.Errorf("adapter %s does not exist", next.Iface)
	}
	if err != nil {
		return err
	}
	if slotOf(old) == slotOf(next) && old.EffMetric() == next.EffMetric() {
		routes, err := listRoutes()
		if err != nil {
			return err
		}
		for _, o := range routes {
			if o.Table != next.Table || o.Dest != s.dest || o.Metric != next.EffMetric() {
				continue
			}
			ours := o.Ours || (old.Legacy() && o.Iface == old.Iface && o.Gateway == addrOrZero(old.Gateway))
			if !ours {
				return fmt.Errorf("%w: the route there is not ours", errExists)
			}
			s.replace = true
			break
		}
		if s.replace {
			return sendAddRoute(next, s)
		}
	}
	if err := sendAddRoute(next, s); err != nil {
		return err
	}
	return ignoreNotOurs(delRoute(old))
}

// delRoute removes only our route: same destination, adapter, next hop,
// metric and table and our protocol tag, so a VPN client's own route to the
// same place stays. A route of an older version has no tag and metric 1.
func delRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	standDelay()
	s, gone, err := routeSpecOf(r)
	if err != nil {
		return err
	}
	if gone {
		return nil // the adapter is gone, and so are its routes
	}
	if r.FromLegacy {
		// The journal came from a file the user can edit and the route has no tag,
		// so a delete with "any protocol" could take a route of somebody else. The
		// table is read, and only a route with exactly this destination, adapter,
		// next hop, metric and table is deleted, with the protocol it has.
		routes, lerr := listRoutes()
		if lerr != nil {
			return lerr
		}
		found := false
		for _, o := range routes {
			if o.key() == keyOf(r) {
				s.proto, found = uint8(o.Proto), true
				break
			}
		}
		if !found {
			return nil // already gone
		}
	}
	_, err = nlRun(func(seq uint32) []byte { return buildDelRoute(seq, s) })
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove route %s dev %s: %w", r.Dest, r.Iface, err)
	}
	return nil
}

func listRoutes() ([]OSRoute, error) {
	msgs, err := nlDumpRun(buildDumpRoutes)
	if err != nil {
		return nil, fmt.Errorf("read routes: %w", err)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("read routes: list of adapters: %w", err) // the table is unknown, not empty
	}
	names := map[int]string{}
	for _, i := range ifs {
		names[i.Index] = i.Name
	}
	var out []OSRoute
	for _, m := range msgs {
		if r, ok := parseRoute(m); ok {
			r.Iface = names[r.IfIndex]
			out = append(out, r)
		}
	}
	return out, nil
}

func listRules() ([]OSRule, error) {
	msgs, err := nlDumpRun(buildDumpRules)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var out []OSRule
	for _, m := range msgs {
		if r, ok := parseRule(m); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func addRule(r config.Rule) error {
	if err := config.ValidateRule(r); err != nil {
		return err
	}
	_, err := nlRun(func(seq uint32) []byte { return buildRule(rtmNewRule, seq, r.Table, r.Pref) })
	switch {
	case errors.Is(err, unix.EEXIST):
		return fmt.Errorf("%w: %v", errExists, err)
	case err != nil:
		return fmt.Errorf("add rule lookup %d pref %d: %w", r.Table, r.Pref, err)
	}
	return nil
}

func delRule(r config.Rule) error {
	if err := config.ValidateRule(r); err != nil {
		return err
	}
	standDelay()
	_, err := nlRun(func(seq uint32) []byte { return buildRule(rtmDelRule, seq, r.Table, r.Pref) })
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove rule lookup %d pref %d: %w", r.Table, r.Pref, err)
	}
	return nil
}
