//go:build linux

package router

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// corpDNS: systemd-resolved knows the DNS servers and domains of each link,
// which is where VPN clients (or NetworkManager for them) put the corp DNS.
// Without it, /etc/resolv.conf servers that are reached through corp are used.
func corpDNS(iface string) (servers, zones []string) {
	if hasResolved() {
		servers = resolvectlList("dns", iface)
		for _, d := range resolvectlList("domain", iface) {
			zones = config.AddUnique(zones, strings.TrimPrefix(d, "~"))
		}
		if len(servers) > 0 {
			return servers, zones
		}
	}
	b, _ := os.ReadFile("/etc/resolv.conf")
	all, search := parseResolvConf(string(b))
	for _, s := range all {
		if ifaceFor(s) == iface {
			servers = append(servers, s)
		}
	}
	if len(servers) > 0 {
		zones = append(zones, search...)
	}
	return servers, zones
}

func ifaceFor(ip string) string {
	out, _ := sysexec.Command("ip", "-4", "route", "get", ip).Output()
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}

func hasResolved() bool {
	_, err := sysexec.LookPath("resolvectl")
	return err == nil && sysexec.Command("resolvectl", "status").Run() == nil
}

func resolvectl(args ...string) error {
	out, err := sysexec.Command("resolvectl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("resolvectl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func resolvectlList(what, iface string) []string {
	out, err := sysexec.Command("resolvectl", what, iface).Output()
	if err != nil {
		return nil
	}
	return parseResolvectl(string(out))
}

// resolverPlan: systemd-resolved sends a zone to a link's DNS when the link
// has it as a routing domain ("~corp.example"). The journal holds
// "domain <link> <zone>", plus "dns <link>" if the link had no DNS servers.
func resolverPlan(iface string, _, zones []string) []string {
	if len(zones) == 0 || !hasResolved() {
		return nil
	}
	var ids []string
	if len(resolvectlList("dns", iface)) == 0 {
		ids = append(ids, "dns "+iface)
	}
	for _, z := range zones {
		ids = append(ids, "domain "+iface+" "+z)
	}
	return ids
}

func addResolver(id string, servers []string) error {
	if !config.ValidResolverEntry(id) {
		return fmt.Errorf("invalid DNS entry %q", id)
	}
	if err := config.ValidateServers(servers); err != nil {
		return err
	}
	f := strings.Fields(id)
	switch {
	case len(f) == 2 && f[0] == "dns":
		return resolvectl(append([]string{"dns", f[1]}, servers...)...)
	case len(f) == 3 && f[0] == "domain":
		cur := resolvectlList("domain", f[1])
		for _, d := range cur {
			if strings.TrimPrefix(d, "~") == f[2] {
				return fmt.Errorf("already set up on %s, left as is", f[1])
			}
		}
		return resolvectl(append([]string{"domain", f[1]}, append(cur, "~"+f[2])...)...)
	}
	return fmt.Errorf("unknown DNS entry %q", id)
}

func delResolver(id string) error {
	if !config.ValidResolverEntry(id) {
		return fmt.Errorf("invalid DNS entry %q", id)
	}
	f := strings.Fields(id)
	if len(f) < 2 {
		return nil
	}
	if _, err := net.InterfaceByName(f[1]); err != nil {
		return nil // the link is gone and took its DNS settings with it
	}
	switch {
	case len(f) == 2 && f[0] == "dns":
		return resolvectl("dns", f[1], "")
	case len(f) == 3 && f[0] == "domain":
		var keep []string
		for _, d := range resolvectlList("domain", f[1]) {
			if d != "~"+f[2] {
				keep = append(keep, d)
			}
		}
		if len(keep) == 0 {
			keep = []string{""}
		}
		return resolvectl(append([]string{"domain", f[1]}, keep...)...)
	}
	return nil
}

func flushDNS() { _ = sysexec.Command("resolvectl", "flush-caches").Run() }
