//go:build windows

package router

import (
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// The layouts are fixed by the Windows SDK (netioapi.h, nldef.h): the sizes
// and offsets below are what the C compiler gives MIB_IPFORWARD_ROW2 and
// friends on x86 and x64. A mistake here corrupts the memory of the call.
func TestForwardRowLayout(t *testing.T) {
	var row mibIPForwardRow2
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"sizeof(SOCKADDR_INET)", unsafe.Sizeof(sockaddrInet{}), 28},
		{"sizeof(IP_ADDRESS_PREFIX)", unsafe.Sizeof(ipAddressPrefix{}), 32},
		{"sizeof(MIB_IPFORWARD_ROW2)", unsafe.Sizeof(row), 104},
		{"InterfaceLuid", unsafe.Offsetof(row.InterfaceLuid), 0},
		{"InterfaceIndex", unsafe.Offsetof(row.InterfaceIndex), 8},
		{"DestinationPrefix", unsafe.Offsetof(row.DestinationPrefix), 12},
		{"DestinationPrefix.PrefixLength", unsafe.Offsetof(row.DestinationPrefix) + unsafe.Offsetof(row.DestinationPrefix.PrefixLength), 40},
		{"NextHop", unsafe.Offsetof(row.NextHop), 44},
		{"SitePrefixLength", unsafe.Offsetof(row.SitePrefixLength), 72},
		{"ValidLifetime", unsafe.Offsetof(row.ValidLifetime), 76},
		{"PreferredLifetime", unsafe.Offsetof(row.PreferredLifetime), 80},
		{"Metric", unsafe.Offsetof(row.Metric), 84},
		{"Protocol", unsafe.Offsetof(row.Protocol), 88},
		{"Loopback", unsafe.Offsetof(row.Loopback), 92},
		{"Immortal", unsafe.Offsetof(row.Immortal), 95},
		{"Age", unsafe.Offsetof(row.Age), 96},
		{"Origin", unsafe.Offsetof(row.Origin), 100},
		{"MIB_IPFORWARD_TABLE2.Table", unsafe.Offsetof(mibIPForwardTable2{}.Table), 8},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d, want %d", c.name, c.got, c.want)
		}
	}
	if unsafe.Sizeof(row) != 104 {
		t.Fatal("size")
	}
}

func TestSockaddrInet(t *testing.T) {
	var s sockaddrInet
	s.setV4(netip.MustParseAddr("192.168.1.1"))
	if s[0] != 2 || s[1] != 0 || s[4] != 192 || s[7] != 1 {
		t.Errorf("%x", s[:])
	}
	if a, ok := s.v4(); !ok || a != netip.MustParseAddr("192.168.1.1") {
		t.Errorf("%v %v", a, ok)
	}
	var zero sockaddrInet // AF_UNSPEC: a row without a next hop
	if _, ok := zero.v4(); ok {
		t.Error("AF_UNSPEC is not IPv4")
	}
}

// Read-only: the routing table of this machine is parsed without a failure
// and has what every Windows has: the loopback network and a default route.
func TestListRoutesOnThisMachine(t *testing.T) {
	rs, err := listRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("empty table")
	}
	var loop, def bool
	for _, r := range rs {
		if r.Dest == netip.MustParsePrefix("127.0.0.0/8") {
			loop = true
		}
		if r.Dest.Bits() == 0 {
			def = true
		}
		if r.Ours || r.Table != 0 {
			t.Errorf("%+v: Windows routes have no tag and no table number", r)
		}
	}
	if !loop {
		t.Error("no 127.0.0.0/8")
	}
	if !def {
		t.Log("no default route (offline?)")
	}
	t.Logf("%d routes", len(rs))
	if m := adapterMetrics(); len(m) == 0 {
		t.Error("no adapter metrics")
	}
	physicalGateway() // must not panic or hang
}

// The calls are checked against the routes of this machine without changing
// it: looking up a route that is there, and one that is not.
func TestGetForwardEntryReadOnly(t *testing.T) {
	rs, err := listRoutes()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range rs {
		if r.Dest != netip.MustParsePrefix("127.0.0.0/8") {
			continue
		}
		var row mibIPForwardRow2
		if err := forwardKey(&row, r.IfIndex, r.Dest, r.Gateway); err != nil {
			t.Fatal(err)
		}
		if err := getForwardEntry(&row); err != nil {
			t.Fatalf("GetIpForwardEntry2 for a route of the table: %v", err)
		}
		if int(row.Metric) != r.Metric {
			t.Errorf("metric %d, table says %d", row.Metric, r.Metric)
		}
		found = true
		break
	}
	if !found {
		t.Skip("no loopback route")
	}
	var row mibIPForwardRow2
	if err := forwardKey(&row, rs[0].IfIndex, netip.MustParsePrefix("192.0.2.0/24"), netip.MustParseAddr("192.0.2.77")); err != nil {
		t.Fatal(err)
	}
	if err := getForwardEntry(&row); err == nil {
		t.Error("TEST-NET-1 must not be in the table")
	} else if err != errNotFound && err != errFileNotFound {
		t.Errorf("a missing route must be ERROR_NOT_FOUND, got %v", err)
	}
}

// The write calls are exercised against an adapter that does not exist, so
// they cannot change anything: this only shows that the exports resolve, the
// row is accepted by the API's argument check up to the adapter lookup, and
// the error codes are the ones the code relies on.
func TestWriteCallsRejectUnknownAdapter(t *testing.T) {
	const bogus = 0x7ffffff0
	var row mibIPForwardRow2
	initForwardRow(&row)
	row.InterfaceIndex = bogus
	row.DestinationPrefix.Prefix.setV4(netip.MustParseAddr("192.0.2.0"))
	row.DestinationPrefix.PrefixLength = 24
	row.NextHop.setV4(netip.IPv4Unspecified())
	row.Metric = ownMetric
	row.Protocol = mibIPProtoNetMgmt
	row.ValidLifetime, row.PreferredLifetime = infiniteLifetime, infiniteLifetime
	err := createForwardEntry(&row)
	if err == nil {
		t.Fatal("a route on an adapter that does not exist was created")
	}
	t.Logf("CreateIpForwardEntry2 on an unknown adapter: %v", err)
	err = deleteForwardEntry(&row)
	if err == nil {
		t.Fatal("deleted a route that cannot exist")
	}
	t.Logf("DeleteIpForwardEntry2 on an unknown adapter: %v", err)
	if err := getForwardEntry(&row); err != errNotFound && err != errFileNotFound {
		t.Logf("GetIpForwardEntry2 on an unknown adapter: %v", err)
	}
	// the change in place (a route of ours whose metric differs): the export resolves and
	// refuses a route that does not exist
	if err := procSetIPForwardEntry2.Find(); err != nil {
		t.Fatalf("SetIpForwardEntry2 is not exported: %v", err)
	}
	if err := setForwardEntry(&row); err == nil {
		t.Fatal("changed a route that cannot exist")
	}
}

// ReplaceRoute changes the metric of a route of ours in place only for the same
// key (prefix, adapter, next hop); the check that decides it.
func TestReplaceRouteDecidesOnTheKey(t *testing.T) {
	a := config.Route{Dest: "10.0.0.0/8", Iface: "x", Gateway: "10.0.0.1", Metric: 1}
	b := a
	b.Metric = 3
	if routeKey(a) != routeKey(b) {
		t.Error("only the metric differs: the same key, changed in place")
	}
	b.Gateway = "10.0.0.2"
	if routeKey(a) == routeKey(b) {
		t.Error("another next hop is another route")
	}
	var _ replacer = osBackend{}
}

func TestApiErrUsesTheLowDword(t *testing.T) {
	if apiErr(0) != nil {
		t.Error("0 is success")
	}
	if err := apiErr(5010); err != errObjectAlreadyExists {
		t.Errorf("%v", err)
	}
}

// A row is ours only if the metric, the protocol and the origin all are: the
// key of a route (prefix, adapter, next hop) is shared with a client's route.
func TestRowOwnership(t *testing.T) {
	r := config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", Metric: ownMetric}
	row := func(metric, proto, origin uint32) *mibIPForwardRow2 {
		return &mibIPForwardRow2{Metric: metric, Protocol: proto, Origin: origin}
	}
	for _, c := range []struct {
		name string
		row  *mibIPForwardRow2
		want bool
	}{
		{"ours", row(ownMetric, mibIPProtoNetMgmt, nlroManual), true},
		{"another metric", row(ownMetric+1, mibIPProtoNetMgmt, nlroManual), false},
		{"another protocol (a dynamic route)", row(ownMetric, 2, nlroManual), false}, // MIB_IPPROTO_NETMGMT is 3; 2 is local
		{"dhcp origin", row(ownMetric, mibIPProtoNetMgmt, 2), false},                 // NlroDHCP
		{"router advertisement origin", row(ownMetric, mibIPProtoNetMgmt, 3), false},
	} {
		if got := rowIsOurs(c.row, r); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	legacy := config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp"} // metric 1
	if !rowIsOurs(row(1, mibIPProtoNetMgmt, nlroManual), legacy) || rowIsOurs(row(ownMetric, mibIPProtoNetMgmt, nlroManual), legacy) {
		t.Error("a route of an older version has metric 1")
	}
	// from the untrusted old journal: metric 1 and NETMGMT, whatever the origin
	// route.exe gives (not checked on a live system); never another metric or protocol
	fromOld := config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", FromLegacy: true}
	if !rowIsOurs(row(1, mibIPProtoNetMgmt, nlroManual), fromOld) || !rowIsOurs(row(1, mibIPProtoNetMgmt, 2), fromOld) {
		t.Error("an old route: metric 1, NETMGMT, any origin")
	}
	if rowIsOurs(row(ownMetric, mibIPProtoNetMgmt, nlroManual), fromOld) || rowIsOurs(row(1, 2, nlroManual), fromOld) {
		t.Error("an old route has metric 1 and protocol NETMGMT")
	}
}

// What listRoutes reports as not ours makes the table not find it as ours.
func TestTableDoesNotTakeAForeignRowForOurs(t *testing.T) {
	r := config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", Metric: ownMetric}
	o := OSRoute{Dest: netip.MustParsePrefix("10.10.0.0/16"), Iface: "wgcorp", Metric: ownMetric}
	if !newTable([]OSRoute{o}).has(r) {
		t.Fatal("same key: ours")
	}
	o.NotOurs = true
	if newTable([]OSRoute{o}).has(r) {
		t.Error("a row with another protocol or origin is not ours")
	}
}

func TestIfaceIndexTellsMissingFromUnreadable(t *testing.T) {
	if _, found, err := ifaceIndex("No Such Adapter 7f3a"); found || err != nil {
		t.Errorf("found=%v err=%v", found, err)
	}
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no adapters")
	}
	if idx, found, err := ifaceIndex(ifs[0].Name); !found || err != nil || idx != ifs[0].Index {
		t.Errorf("%d %v %v", idx, found, err)
	}
}

func TestNrptNamespaces(t *testing.T) {
	have, err := parseNrptNamespaces([]byte(`[".corp.example","corp.example",".a.b"]`))
	if err != nil || !have[".corp.example"] || !have[".a.b"] || have[".x"] {
		t.Errorf("%v %v", have, err)
	}
	one, err := parseNrptNamespaces([]byte("\".corp.example\"\r\n")) // PowerShell writes one element as a string
	if err != nil || !one[".corp.example"] {
		t.Errorf("%v %v", one, err)
	}
	if none, err := parseNrptNamespaces(nil); err != nil || len(none) != 0 {
		t.Errorf("%v %v", none, err)
	}
	if _, err := parseNrptNamespaces([]byte("{")); err == nil {
		t.Error("garbage")
	}
}

// IPv6 in the union: the address sits at 8..24, the scope id at 24..28 (zero
// unless a link-local next hop sets it), and the family decides what is read.
func TestSockaddrInetV6(t *testing.T) {
	for _, in := range []string{"::", "::1", "8000::", "fe80::1", "2001:db8::77"} {
		a := netip.MustParseAddr(in)
		var s sockaddrInet
		s.setAddr(a)
		if s[0] != winAfInet6 || s[1] != 0 {
			t.Errorf("%s: family %x", in, s[:2])
		}
		b := a.As16()
		for i := range 16 {
			if s[8+i] != b[i] {
				t.Errorf("%s: byte %d", in, i)
			}
		}
		for i := 24; i < 28; i++ {
			if s[i] != 0 {
				t.Errorf("%s: scope id byte %d is %x", in, i, s[i])
			}
		}
		if got, ok := s.addr(); !ok || got != a {
			t.Errorf("%s: read back %v %v", in, got, ok)
		}
		if _, ok := s.v4(); ok {
			t.Errorf("%s: an IPv6 address is not IPv4", in)
		}
	}
	// a row of family 0 (no next hop, a destination of another kind) is skipped
	var zero sockaddrInet
	if _, ok := zero.addr(); ok {
		t.Error("AF_UNSPEC must not read as an address")
	}
	// the setter of an IPv4 address clears what an IPv6 one left
	var s sockaddrInet
	s.setAddr(netip.MustParseAddr("fe80::1"))
	s.setScope(7)
	s.setAddr(netip.MustParseAddr("10.0.0.1"))
	if a, ok := s.addr(); !ok || a != netip.MustParseAddr("10.0.0.1") || s.scopeID() != 0 || s[8] != 0 {
		t.Errorf("%x", s[:])
	}
}

// The key of a route in IPv6: the halves of the default route on-link, a
// link-local next hop with the zone of the adapter, a global one without.
func TestForwardKeyV6(t *testing.T) {
	var row mibIPForwardRow2
	for _, d := range []string{"::/1", "8000::/1"} {
		p := netip.MustParsePrefix(d)
		fillForwardKey(&row, 0x1234, 12, p, netip.Addr{})
		dst, ok := row.DestinationPrefix.Prefix.addr()
		if !ok || dst != p.Addr() || int(row.DestinationPrefix.PrefixLength) != p.Bits() {
			t.Errorf("%s: %v %v %d", d, dst, ok, row.DestinationPrefix.PrefixLength)
		}
		if gw, ok := row.NextHop.addr(); !ok || gw != netip.IPv6Unspecified() || row.NextHop.scopeID() != 0 {
			t.Errorf("%s: on-link next hop is %v %v scope %d", d, gw, ok, row.NextHop.scopeID())
		}
		if row.InterfaceLuid != 0x1234 || row.InterfaceIndex != 12 {
			t.Errorf("%s: adapter %x %d", d, row.InterfaceLuid, row.InterfaceIndex)
		}
	}
	p := netip.MustParsePrefix("2001:db8:ff::/48")
	fillForwardKey(&row, 1, 12, p, netip.MustParseAddr("fe80::1"))
	if gw, ok := row.NextHop.addr(); !ok || gw != netip.MustParseAddr("fe80::1") || row.NextHop.scopeID() != 12 {
		t.Errorf("link-local next hop: %v %v scope %d", gw, ok, row.NextHop.scopeID())
	}
	fillForwardKey(&row, 1, 12, p, netip.MustParseAddr("2001:db8::1"))
	if gw, _ := row.NextHop.addr(); gw != netip.MustParseAddr("2001:db8::1") || row.NextHop.scopeID() != 0 {
		t.Errorf("global next hop: %v scope %d", gw, row.NextHop.scopeID())
	}
	// IPv4 is as before
	fillForwardKey(&row, 1, 12, netip.MustParsePrefix("10.0.0.0/8"), netip.Addr{})
	if gw, ok := row.NextHop.v4(); !ok || gw != netip.IPv4Unspecified() {
		t.Errorf("v4 on-link: %v %v", gw, ok)
	}
}

// What listRoutes makes of the next hop: the scope id of a link-local address
// does not take part, an unspecified one is on-link.
func TestNextHopComparisonIgnoresScope(t *testing.T) {
	var a, b sockaddrInet
	a.setAddr(netip.MustParseAddr("fe80::1"))
	b.setAddr(netip.MustParseAddr("fe80::1"))
	b.setScope(14)
	ga, _ := a.addr()
	gb, _ := b.addr()
	if ga != gb {
		t.Errorf("%v != %v: the scope id must not matter", ga, gb)
	}
	o := OSRoute{Dest: netip.MustParsePrefix("2001:db8::/32"), Iface: "wg", Gateway: gb, Metric: ownMetric}
	r := config.Route{Dest: "2001:db8::/32", Iface: "wg", Gateway: "fe80::1", Metric: ownMetric}
	if !newTable([]OSRoute{o}).has(r) {
		t.Error("the route with a link-local next hop is not found as ours")
	}
}
