//go:build darwin

package router

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	out, err := exec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return Gateway{}, false
	}
	return parseDefaultGW(string(out))
}

// ifaceFor is the adapter the OS uses to reach ip.
func ifaceFor(ip string) string {
	out, _ := exec.Command("route", "-n", "get", ip).Output()
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
	cmd := exec.Command("scutil")
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
		cmd := exec.Command("scutil")
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
		ids = append(ids, filepath.Join("/etc/resolver", z))
	}
	return ids
}

func addResolver(path string, servers []string) error {
	if b, err := os.ReadFile(path); err == nil && !strings.Contains(string(b), resolverMarker) {
		return fmt.Errorf("%s exists and is not ours, left as is", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(resolverMarker + "\n")
	for _, s := range servers {
		b.WriteString("nameserver " + s + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func delResolver(path string) error {
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), resolverMarker) {
		return nil // gone, or replaced by someone else
	}
	return os.Remove(path)
}

func flushDNS() {
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}
