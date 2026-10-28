//go:build windows

package router

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// PrivHint tells the user how to get the rights Apply and Reset need.
const PrivHint = "run the terminal as Administrator"

// IsPrivileged reports whether routes can be changed: the process token is elevated.
func IsPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

func ipMask(cidr string) (string, string) {
	_, n, _ := net.ParseCIDR(cidr)
	return n.IP.String(), net.IP(n.Mask).String()
}

var getOEMCP = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetOEMCP")

// oemString decodes console output of native tools (CP866 on Russian
// Windows) so that error messages are readable. It is for display only.
func oemString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	cp, _, _ := getOEMCP.Call()
	n, err := windows.MultiByteToWideChar(uint32(cp), 0, &b[0], int32(len(b)), nil, 0)
	if err != nil || n == 0 {
		return string(b)
	}
	w := make([]uint16, n)
	if _, err := windows.MultiByteToWideChar(uint32(cp), 0, &b[0], int32(len(b)), &w[0], n); err != nil {
		return string(b)
	}
	return windows.UTF16ToString(w)
}

// runRoute runs route.exe; success is its exit code, not its (localized) text.
func runRoute(args ...string) error {
	out, err := sysexec.Command("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(oemString(out)))
	}
	return nil
}

func onLink(gateway string) string {
	if gateway == "" {
		return "0.0.0.0" // on-link
	}
	return gateway
}

// routeExists asks the route table (not a command's message) whether the
// prefix is already routed through the adapter with that next hop.
func routeExists(prefix string, ifIndex int, hop string) bool {
	_, err := ps(map[string]string{"DEST": prefix, "IDX": strconv.Itoa(ifIndex), "HOP": hop},
		"if (Get-NetRoute -DestinationPrefix $env:VS_DEST -InterfaceIndex ([int]$env:VS_IDX) -NextHop $env:VS_HOP -ErrorAction SilentlyContinue) { exit 0 } else { exit 3 }")
	return err == nil
}

func addRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	ifi, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return err
	}
	ip, mask := ipMask(r.Dest)
	gw := onLink(r.Gateway)
	err = runRoute("add", ip, "mask", mask, gw, "metric", "1", "if", strconv.Itoa(ifi.Index))
	if err != nil {
		if routeExists(r.Dest, ifi.Index, gw) {
			return fmt.Errorf("%w: %v", errExists, err)
		}
		return err
	}
	// route.exe's exit code is not proof: ask the route table
	if listed, known := routeListed(ip, mask, gw); known && !listed {
		return fmt.Errorf("route add %s reported success, but the route is not in the table", r.Dest)
	}
	return nil
}

// delRoute removes only our route: same prefix, adapter, next hop and our
// metric, so a VPN client's own route to the same place stays. Whether the
// route exists is asked of the route table first, so a missing route is not
// recognized by (localized) error text.
func delRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	ifi, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return nil // adapter is gone, so are its routes
	}
	_, n, err := net.ParseCIDR(r.Dest)
	if err != nil {
		return err
	}
	_, err = ps(map[string]string{"DEST": n.String(), "IDX": strconv.Itoa(ifi.Index), "HOP": onLink(r.Gateway)},
		"$ErrorActionPreference='Stop'; try { "+
			"$r=@(Get-NetRoute -DestinationPrefix $env:VS_DEST -InterfaceIndex ([int]$env:VS_IDX) -NextHop $env:VS_HOP -ErrorAction SilentlyContinue | Where-Object { $_.RouteMetric -eq 1 }); "+
			"if ($r.Count -eq 0) { exit 0 }; "+
			"$r | Remove-NetRoute -Confirm:$false -ErrorAction Stop "+
			"} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
	if err != nil {
		return fmt.Errorf("remove route %s: %w", r.Dest, err)
	}
	return nil
}

// physicalGateway is the lowest-metric default route of a non-VPN adapter.
func physicalGateway() (Gateway, bool) {
	out, err := ps(nil,
		"Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | "+
			"Select-Object InterfaceAlias,NextHop | ConvertTo-Json -Compress")
	if err != nil {
		return Gateway{}, false
	}
	var arr []struct{ InterfaceAlias, NextHop string }
	if json.Unmarshal(out, &arr) != nil {
		var one struct{ InterfaceAlias, NextHop string }
		if json.Unmarshal(out, &one) == nil {
			arr = append(arr, one)
		}
	}
	ifs, _ := netif.List()
	for _, r := range arr {
		hop, err := config.ParseIPv4(r.NextHop)
		if err != nil || hop == "0.0.0.0" || !config.ValidIface(r.InterfaceAlias) {
			continue
		}
		for _, i := range ifs {
			if i.Name == r.InterfaceAlias && i.Kind == netif.KindPhysical {
				return Gateway{Iface: r.InterfaceAlias, Router: hop}, true
			}
		}
	}
	return Gateway{}, false
}
