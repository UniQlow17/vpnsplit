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
