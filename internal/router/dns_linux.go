//go:build linux

package router

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

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

// hasResolved reports whether systemd-resolved answers; asked once per apply.
func hasResolved() bool {
	return probes.get("resolved", func() bool {
		_, err := sysexec.LookPath("resolvectl")
		return err == nil && sysexec.Command("resolvectl", "status").Run() == nil
	})
}

func resolvectl(args ...string) error {
	out, err := sysexec.Command("resolvectl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("resolvectl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

func resolvectlList(what, iface string) []string {
	l, _ := resolvectlGet(what, iface)
	return l
}

// resolvectlGet is resolvectlList that says when it could not ask.
func resolvectlGet(what, iface string) ([]string, error) {
	out, err := sysexec.Command("resolvectl", what, iface).Output()
	if err != nil {
		return nil, err
	}
	return parseResolvectl(string(out)), nil
}

// MissingResolvers lists the journal entries that systemd-resolved no longer
// has on their link (the link was recreated, or somebody reset it). An error
// means it could not be asked.
func (osBackend) MissingResolvers(ids []string) ([]string, error) {
	var missing []string
	for _, id := range ids {
		f := strings.Fields(id)
		if len(f) < 2 {
			continue
		}
		if _, found, err := ifaceByName(f[1]); err != nil {
			return nil, err
		} else if !found {
			missing = append(missing, id)
			continue
		}
		switch {
		case len(f) == 2 && f[0] == "dns":
			l, err := resolvectlGet("dns", f[1])
			if err != nil {
				return nil, err
			}
			if len(l) == 0 {
				missing = append(missing, id)
			}
		case len(f) == 3 && f[0] == "domain":
			l, err := resolvectlGet("domain", f[1])
			if err != nil {
				return nil, err
			}
			has := false
			for _, d := range l {
				has = has || d == "~"+f[2]
			}
			if !has {
				missing = append(missing, id)
			}
		}
	}
	return missing, nil
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

// resolvedMu serializes the changes of the DNS settings of the links: the domains
// of a link are read, changed and written back as a whole, and two of them at the
// same time (the entries are removed by several workers) would lose one change.
var resolvedMu sync.Mutex

func addResolver(id string, servers []string) error {
	resolvedMu.Lock()
	defer resolvedMu.Unlock()
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
				return fmt.Errorf("%w: already set up on %s, left as is", errResolverExists, f[1])
			}
		}
		return resolvectl(append([]string{"domain", f[1]}, append(cur, "~"+f[2])...)...)
	}
	return fmt.Errorf("unknown DNS entry %q", id)
}

func delResolver(id string) error {
	resolvedMu.Lock()
	defer resolvedMu.Unlock()
	if !config.ValidResolverEntry(id) {
		return fmt.Errorf("invalid DNS entry %q", id)
	}
	f := strings.Fields(id)
	if len(f) < 2 {
		return nil
	}
	if _, found, err := ifaceByName(f[1]); err != nil {
		return err
	} else if !found {
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

// ListResolvers: the per-link DNS settings of systemd-resolved are not part of
// the baseline; the journal is the record of what vpnsplit set.
func (osBackend) ListResolvers() ([]OSResolver, error) { return nil, ErrNoTable }

// restDNS: systemd-resolved sends everything else to the home link as the
// routing domain "~.".
const restDNS = true

// physicalDNS finds the DNS servers of the provider on the physical link:
// systemd-resolved first, then NetworkManager, then the servers of resolv.conf
// (also the upstream list of resolved) that are reached through that link. The
// stub of resolved (127.0.0.53) and other loopback addresses are not a provider's.
func physicalDNS(iface string) []string {
	var out []string
	keep := func(list []string) {
		for _, s := range validServers(list) {
			if a, err := netip.ParseAddr(s); err == nil && !a.IsLoopback() && !a.IsUnspecified() {
				out = config.AddUnique(out, s)
			}
		}
	}
	if hasResolved() {
		keep(resolvectlList("dns", iface))
	}
	if len(out) == 0 {
		if o, err := sysexec.Command("nmcli", "-g", "IP4.DNS", "device", "show", iface).Output(); err == nil {
			keep(strings.FieldsFunc(string(o), func(r rune) bool { return r == '\n' || r == ' ' || r == '|' }))
		}
	}
	if len(out) == 0 {
		for _, p := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			all, _ := parseResolvConf(string(b))
			var mine []string
			for _, s := range all {
				if ifaceFor(s) == iface {
					mine = append(mine, s)
				}
			}
			keep(mine)
			if len(out) > 0 {
				break
			}
		}
	}
	return out
}
