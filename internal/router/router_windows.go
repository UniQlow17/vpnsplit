//go:build windows

package router

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
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

func delRoute(r config.Route) error {
	ifi, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return nil // adapter is gone, so are its routes
	}
	ip, mask := ipMask(r.Dest)
	err = runRoute("delete", ip, "mask", mask, "if", strconv.Itoa(ifi.Index))
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "not found") {
		return nil
	}
	return err
}
