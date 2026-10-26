//go:build windows

package router

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// PrivHint tells the user how to get the rights Apply and Reset need.
const PrivHint = "run the terminal as Administrator"

// IsPrivileged reports whether routes can be changed.
func IsPrivileged() bool { return exec.Command("net", "session").Run() == nil }

func ipMask(cidr string) (string, string) {
	_, n, _ := net.ParseCIDR(cidr)
	return n.IP.String(), net.IP(n.Mask).String()
}

func runRoute(args ...string) error {
	out, err := exec.Command("route", args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil || strings.Contains(strings.ToLower(s), "failed") {
		return fmt.Errorf("route %s: %s", strings.Join(args, " "), s)
	}
	return nil
}

func addRoute(r config.Route) error {
	ifi, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return err
	}
	ip, mask := ipMask(r.Dest)
	gw := r.Gateway
	if gw == "" {
		gw = "0.0.0.0" // on-link
	}
	return runRoute("add", ip, "mask", mask, gw, "metric", "1", "if", strconv.Itoa(ifi.Index))
}

// delRoute removes only our route: same prefix, adapter, next hop and our
// metric, so a VPN client's own route to the same place stays.
func delRoute(r config.Route) error {
	ifi, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return nil // adapter is gone, so are its routes
	}
	_, n, err := net.ParseCIDR(r.Dest)
	if err != nil {
		return err
	}
	hop := r.Gateway
	if hop == "" {
		hop = "0.0.0.0" // on-link
	}
	script := fmt.Sprintf("Remove-NetRoute -DestinationPrefix '%s' -InterfaceIndex %d -NextHop '%s' -RouteMetric 1 -Confirm:$false -ErrorAction Stop",
		n.String(), ifi.Index, hop)
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "+script).CombinedOutput()
	if err != nil {
		s := strings.TrimSpace(string(out))
		low := strings.ToLower(s)
		if strings.Contains(s, "No matching") || strings.Contains(low, "not found") || strings.Contains(low, "notfound") {
			return nil
		}
		return fmt.Errorf("remove route %s: %s", r.Dest, s)
	}
	return nil
}

// physicalGateway is the lowest-metric default route of a non-VPN adapter.
func physicalGateway() (Gateway, bool) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "+
			"Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric | "+
			"Select-Object InterfaceAlias,NextHop | ConvertTo-Json -Compress").Output()
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
		if r.NextHop == "" || r.NextHop == "0.0.0.0" {
			continue
		}
		for _, i := range ifs {
			if i.Name == r.InterfaceAlias && i.Kind == netif.KindPhysical {
				return Gateway{Iface: r.InterfaceAlias, Router: r.NextHop}, true
			}
		}
	}
	return Gateway{}, false
}
