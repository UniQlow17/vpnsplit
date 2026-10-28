//go:build linux

package router

import (
	"fmt"
	"os"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// PrivHint tells the user how to get the rights Apply and Reset need.
const PrivHint = "run with sudo"

// IsPrivileged reports whether routes can be changed.
func IsPrivileged() bool { return os.Geteuid() == 0 }

func ipCmd(args ...string) error {
	out, err := sysexec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func addRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	// "add", not "replace": a route the VPN client already set up must stay its own
	args := []string{"route", "add", r.Dest}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	err := ipCmd(append(args, "dev", r.Iface, "metric", "1")...)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "exists") {
		return fmt.Errorf("%w: %v", errExists, err)
	}
	return err
}

func delRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	// the metric picks our route, not a VPN client's own one to the same place
	err := ipCmd("route", "del", r.Dest, "dev", r.Iface, "metric", "1")
	if err != nil && (strings.Contains(err.Error(), "No such") || strings.Contains(err.Error(), "Cannot find device")) {
		return nil
	}
	return err
}

// physicalGateway is the default route of a non-VPN adapter.
func physicalGateway() (Gateway, bool) {
	out, err := sysexec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return Gateway{}, false
	}
	return parseDefaultGW(string(out))
}
