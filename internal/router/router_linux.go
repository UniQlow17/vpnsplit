//go:build linux

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

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func addRoute(r config.Route) error {
	args := []string{"route", "replace", r.Dest}
	if r.Gateway != "" {
		args = append(args, "via", r.Gateway)
	}
	return ipCmd(append(args, "dev", r.Iface, "metric", "1")...)
}

func delRoute(r config.Route) error {
	err := ipCmd("route", "del", r.Dest, "dev", r.Iface)
	if err != nil && (strings.Contains(err.Error(), "No such") || strings.Contains(err.Error(), "Cannot find device")) {
		return nil
	}
	return err
}
