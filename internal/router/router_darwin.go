//go:build darwin

package router

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// PrivHint tells the user how to get the rights Apply and Reset need.
const PrivHint = "run with sudo"

// IsPrivileged reports whether routes can be changed.
func IsPrivileged() bool { return os.Geteuid() == 0 }

func routeCmd(args ...string) error {
	out, err := sysexec.Command("route", append([]string{"-n"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func addRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	err := addRouteCmd(r)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "exists") {
		return fmt.Errorf("%w: %v", errExists, err)
	}
	return err
}

func addRouteCmd(r config.Route) error {
	if r.Gateway != "" {
		return routeCmd("add", "-net", r.Dest, r.Gateway)
	}
	return routeCmd("add", "-net", r.Dest, "-interface", r.Iface)
}

func delRoute(r config.Route) error {
	if err := config.ValidateRoute(r); err != nil {
		return err
	}
	if _, err := net.InterfaceByName(r.Iface); err != nil && r.Gateway == "" {
		return nil // the tunnel is gone and took its routes with it
	}
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

// physicalGateway is the default route of Wi-Fi/Ethernet; it stays in the
// table (as a scoped default) even when a VPN takes over the default route.
func physicalGateway() (Gateway, bool) {
	out, err := sysexec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return Gateway{}, false
	}
	return parseDefaultGW(string(out))
}

// ifaceFor is the adapter the OS uses to reach ip.
func ifaceFor(ip string) string {
	out, _ := sysexec.Command("route", "-n", "get", ip).Output()
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "interface:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// corpDNS finds DNS servers reachable through the corp adapter and the
// domains they serve. Corp clients register them with the system (Check Point
// puts them on the Wi-Fi service), and they stay there even when another VPN
// takes over the system DNS.
func corpDNS(corpIface string) (servers, zones []string) {
	cmd := sysexec.Command("scutil")
	cmd.Stdin = strings.NewReader("list .*/DNS\n")
	keys, err := cmd.Output()
	if err != nil {
		return nil, nil
	}
	for _, l := range strings.Split(string(keys), "\n") {
		_, key, ok := strings.Cut(l, " = ")
		if !ok || !strings.Contains(key, "/Service/") {
			continue
		}
		cmd := sysexec.Command("scutil")
		cmd.Stdin = strings.NewReader("show " + strings.TrimSpace(key) + "\n")
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		var mine []string
		for _, s := range parseSCArray(string(out), "ServerAddresses") {
			if ip := net.ParseIP(s); ip != nil && ip.To4() != nil && ifaceFor(s) == corpIface {
				mine = append(mine, s)
			}
		}
		if len(mine) == 0 {
			continue
		}
		for _, s := range mine {
			servers = config.AddUnique(servers, s)
		}
		for _, k := range []string{"SearchDomains", "SupplementalMatchDomains"} {
			for _, d := range parseSCArray(string(out), k) {
				zones = config.AddUnique(zones, d)
			}
		}
	}
	return servers, zones
}

// resolverPlan: macOS reads per-domain DNS servers from /etc/resolver/<zone>;
// the journal holds the file paths.
func resolverPlan(_ string, _, zones []string) []string {
	var ids []string
	for _, z := range zones {
		ids = append(ids, filepath.Join(resolverDir, z))
	}
	return ids
}

const resolverDir = "/etc/resolver"

// checkResolverPath: only <resolverDir>/<valid zone>, nothing else, is ever
// written or removed, whatever a journal or a DNS answer says.
func checkResolverPath(path string) error {
	if !config.ValidResolverEntry(path) || filepath.Dir(path) != resolverDir {
		return fmt.Errorf("invalid resolver file %q", path)
	}
	return nil
}

// ourFile reports whether path is a regular file written by vpnsplit.
// A symlink or anything else is never ours.
func ourFile(path string) (exists, ours bool, err error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if !fi.Mode().IsRegular() {
		return true, false, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return true, false, err
	}
	return true, strings.Contains(string(b), resolverMarker), nil
}

func addResolver(path string, servers []string) error {
	if err := checkResolverPath(path); err != nil {
		return err
	}
	if err := config.ValidateServers(servers); err != nil {
		return err
	}
	exists, ours, err := ourFile(path)
	if err != nil {
		return err
	}
	if exists && !ours {
		return fmt.Errorf("%s exists and is not ours, left as is", path)
	}
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return err
	}
	if exists {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	var b strings.Builder
	b.WriteString(resolverMarker + "\n")
	for _, s := range servers {
		b.WriteString("nameserver " + s + "\n")
	}
	// O_EXCL|O_NOFOLLOW: never write through a link planted at the path
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func delResolver(path string) error {
	if err := checkResolverPath(path); err != nil {
		return err
	}
	if _, ours, err := ourFile(path); err != nil || !ours {
		return nil // gone, or replaced by someone else
	}
	return os.Remove(path)
}

func flushDNS() {
	_ = sysexec.Command("dscacheutil", "-flushcache").Run()
	_ = sysexec.Command("killall", "-HUP", "mDNSResponder").Run()
}
