//go:build linux

package clientcfg

import (
	"fmt"
	"os"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// readProxy asks gsettings for the proxy of the desktop of the user. Under
// sudo or pkexec the question is put as that user (runuser) on the bus of
// that user's session; a root without such a user, a machine without gsettings
// or without a session bus (a server) gives "unknown".
func readProxy() Proxy {
	var bus string
	var args []string
	if name, uid, ok := config.RealUser(); ok {
		bus = fmt.Sprintf("/run/user/%d/bus", uid)
		args = []string{"-u", name, "--", "env", "DBUS_SESSION_BUS_ADDRESS=unix:path=" + bus, "gsettings", "list-recursively", "org.gnome.system.proxy"}
	} else if os.Geteuid() != 0 {
		bus = fmt.Sprintf("/run/user/%d/bus", os.Getuid())
	} else {
		return Proxy{}
	}
	if fi, err := os.Lstat(bus); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return Proxy{}
	}
	if _, err := sysexec.LookPath("gsettings"); err != nil {
		return Proxy{}
	}
	var cmd = sysexec.Command("gsettings", "list-recursively", "org.gnome.system.proxy")
	if args != nil {
		if _, err := sysexec.LookPath("runuser"); err != nil {
			return Proxy{}
		}
		cmd = sysexec.Command("runuser", args...)
	} else {
		cmd.Env = append(cmd.Env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+bus)
	}
	out, err := runLimited(cmd)
	if err != nil {
		return Proxy{}
	}
	return ParseGsettingsProxy(out)
}

// readGPONRPT: there is no Group Policy for DNS here.
func readGPONRPT() (known bool, rules int) { return false, 0 }
