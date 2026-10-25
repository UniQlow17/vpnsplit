//go:build darwin

package router

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// PrivHint tells the user how to get the rights Apply and Reset need.
const PrivHint = "run with sudo"

// IsPrivileged reports whether routes can be changed.
func IsPrivileged() bool { return os.Geteuid() == 0 }

func routeCmd(args ...string) error {
	out, err := exec.Command("route", append([]string{"-n"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func addRoute(r config.Route) error {
	if r.Gateway != "" {
		return routeCmd("add", "-net", r.Dest, r.Gateway)
	}
	return routeCmd("add", "-net", r.Dest, "-interface", r.Iface)
}

func delRoute(r config.Route) error {
	var err error
	if r.Gateway != "" {
		err = routeCmd("delete", "-net", r.Dest, r.Gateway)
	} else {
		err = routeCmd("delete", "-net", r.Dest, "-interface", r.Iface)
	}
	if err != nil && strings.Contains(err.Error(), "not in table") {
		return nil
	}
	return err
}
