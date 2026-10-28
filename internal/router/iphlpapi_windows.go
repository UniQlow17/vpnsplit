//go:build windows

package router

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// The routing API of Windows (iphlpapi), described by hand: x/sys/windows
// has no wrappers for it. Layouts follow netioapi.h / nldef.h; the tests
// check sizes and offsets.

var (
	modIphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procCreateIPForwardEntry2       = modIphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIPForwardEntry2       = modIphlpapi.NewProc("DeleteIpForwardEntry2")
	procGetIPForwardEntry2          = modIphlpapi.NewProc("GetIpForwardEntry2")
	procSetIPForwardEntry2          = modIphlpapi.NewProc("SetIpForwardEntry2")
	procGetIPForwardTable2          = modIphlpapi.NewProc("GetIpForwardTable2")
	procFreeMibTable                = modIphlpapi.NewProc("FreeMibTable")
	procInitializeIPForwardEntry    = modIphlpapi.NewProc("InitializeIpForwardEntry")
	procConvertInterfaceIndexToLuid = modIphlpapi.NewProc("ConvertInterfaceIndexToLuid")
)

const (
	winAfInet = 2

	// Win32 codes the route calls return (NETIO_STATUS is a Win32 error).
	errFileNotFound        = syscall.Errno(2)    // ERROR_FILE_NOT_FOUND
	errNotFound            = syscall.Errno(1168) // ERROR_NOT_FOUND
	errObjectAlreadyExists = syscall.Errno(5010) // ERROR_OBJECT_ALREADY_EXISTS

	mibIPProtoNetMgmt = 3          // MIB_IPPROTO_NETMGMT: what `route add` and netsh create
	nlroManual        = 0          // NlroManual: configured by hand, not by DHCP or a router advertisement
	infiniteLifetime  = 0xffffffff // INFINITE
)

// sockaddrInet is SOCKADDR_INET, a union of sockaddr_in and sockaddr_in6
// (28 bytes). Only IPv4 is used.
type sockaddrInet [28]byte

func (s *sockaddrInet) setV4(a netip.Addr) {
	*s = sockaddrInet{}
	binary.LittleEndian.PutUint16(s[0:], winAfInet)
	b := a.As4()
	copy(s[4:8], b[:])
}

// v4 returns the address; ok is false for anything but IPv4.
func (s *sockaddrInet) v4() (netip.Addr, bool) {
	if binary.LittleEndian.Uint16(s[0:]) != winAfInet {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(s[4:8])), true
}

// ipAddressPrefix is IP_ADDRESS_PREFIX: SOCKADDR_INET and the length (32 bytes with padding).
type ipAddressPrefix struct {
	Prefix       sockaddrInet
	PrefixLength uint8
	_            [3]byte
}

// mibIPForwardRow2 is MIB_IPFORWARD_ROW2 (104 bytes). A route is identified by
// InterfaceLuid (or InterfaceIndex), DestinationPrefix and NextHop; the
// metric is not part of the key.
type mibIPForwardRow2 struct {
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	DestinationPrefix    ipAddressPrefix
	NextHop              sockaddrInet
	SitePrefixLength     uint8
	_                    [3]byte
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32 // NL_ROUTE_PROTOCOL
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32 // NL_ROUTE_ORIGIN
}

// mibIPForwardTable2 is MIB_IPFORWARD_TABLE2; the rows follow NumEntries
// (the row type has 8-byte alignment, so they start at offset 8).
type mibIPForwardTable2 struct {
	NumEntries uint32
	_          uint32
	Table      [1]mibIPForwardRow2
}

// apiErr turns a NETIO_STATUS (a Win32 error code: a DWORD, so the upper half
// of the register is not looked at) into an error.
func apiErr(code uint32) error {
	if code == 0 {
		return nil
	}
	return syscall.Errno(code)
}

// rowCreatedLikeOurs reports whether a row has the protocol and origin of the
// routes we create (CreateIpForwardEntry2 with MIB_IPPROTO_NETMGMT, NlroManual).
func rowCreatedLikeOurs(row *mibIPForwardRow2) bool {
	return row.Protocol == mibIPProtoNetMgmt && row.Origin == nlroManual
}

// rowIsOurs reports whether the row that the key of r found is the route we
// created for r, and not somebody else's with the same prefix, adapter and next
// hop: the metric, protocol and origin all have to be ours.
func rowIsOurs(row *mibIPForwardRow2, r config.Route) bool {
	return int(row.Metric) == r.EffMetric() && rowCreatedLikeOurs(row)
}

func initForwardRow(row *mibIPForwardRow2) {
	*row = mibIPForwardRow2{}
	procInitializeIPForwardEntry.Call(uintptr(unsafe.Pointer(row)))
}

func ifIndexToLuid(index uint32) (uint64, error) {
	var luid uint64
	r1, _, _ := procConvertInterfaceIndexToLuid.Call(uintptr(index), uintptr(unsafe.Pointer(&luid)))
	if err := apiErr(uint32(r1)); err != nil {
		return 0, fmt.Errorf("ConvertInterfaceIndexToLuid(%d): %w", index, err)
	}
	return luid, nil
}

func createForwardEntry(row *mibIPForwardRow2) error {
	r1, _, _ := procCreateIPForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return apiErr(uint32(r1))
}

func deleteForwardEntry(row *mibIPForwardRow2) error {
	r1, _, _ := procDeleteIPForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return apiErr(uint32(r1))
}

// setForwardEntry changes the route of the key set in row in place (the
// metric, for one), without removing it first.
func setForwardEntry(row *mibIPForwardRow2) error {
	r1, _, _ := procSetIPForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return apiErr(uint32(r1))
}

// getForwardEntry fills row for the key set in it.
func getForwardEntry(row *mibIPForwardRow2) error {
	r1, _, _ := procGetIPForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	return apiErr(uint32(r1))
}

// forwardRows reads the IPv4 forwarding table and calls fn for every row.
func forwardRows(fn func(*mibIPForwardRow2)) error {
	var tbl *mibIPForwardTable2
	r1, _, _ := procGetIPForwardTable2.Call(winAfInet, uintptr(unsafe.Pointer(&tbl)))
	if err := apiErr(uint32(r1)); err != nil {
		return fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	if tbl == nil {
		return nil
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(tbl)))
	if tbl.NumEntries == 0 {
		return nil
	}
	rows := unsafe.Slice(&tbl.Table[0], tbl.NumEntries)
	for i := range rows {
		fn(&rows[i])
	}
	return nil
}

// forwardKey fills the key of a route in row: adapter, destination, next hop.
func forwardKey(row *mibIPForwardRow2, ifIndex int, dest netip.Prefix, gw netip.Addr) error {
	luid, err := ifIndexToLuid(uint32(ifIndex))
	if err != nil {
		return err
	}
	initForwardRow(row)
	row.InterfaceLuid = luid
	row.InterfaceIndex = uint32(ifIndex)
	row.DestinationPrefix.Prefix.setV4(dest.Addr())
	row.DestinationPrefix.PrefixLength = uint8(dest.Bits())
	if gw.IsValid() {
		row.NextHop.setV4(gw)
	} else {
		row.NextHop.setV4(netip.IPv4Unspecified()) // on-link
	}
	return nil
}
