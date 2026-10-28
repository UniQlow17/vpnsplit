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

// resolversLostOnReboot: the settings that resolvectl makes live in the memory
// of systemd-resolved only, until the computer is restarted or the link is made
// again. (An NRPT rule or a file in /etc/resolver stays.)
func (osBackend) resolversLostOnReboot() bool { return true }

// resolverLink finds the link of a journal entry and tells whether the entry can
// still be ours there: an entry with an index is not, when the link is gone or
// was made again (resolved forgot its settings, and what is there now was set by
// somebody else). ours false carries why.
func resolverLink(r config.LinuxResolver) (ours bool, why string, err error) {
	idx, found, err := ifaceByName(r.Link)
	if err != nil {
		return false, "", err
	}
	switch {
	case !found && r.Index == 0:
		return false, "the link is gone", nil
	case !found:
		return false, fmt.Sprintf("the link %s is gone", r.Link), nil
	case r.Index != 0 && idx != r.Index:
		return false, fmt.Sprintf("the link %s was made again (index %d, now %d)", r.Link, r.Index, idx), nil
	}
	return true, "", nil
}

// MissingResolvers lists the journal entries that systemd-resolved no longer
// has on their link (somebody reset it). An entry on a link that is gone or
// was made again, or a "dns" entry whose servers were changed, is not listed:
// it is not ours any more, and is not made again under the name of the old one.
// An error means it could not be asked.
func (osBackend) MissingResolvers(ids []string) ([]string, error) {
	var missing []string
	for _, id := range ids {
		r, ok := config.ParseLinuxResolver(id)
		if !ok {
			continue
		}
		ours, _, err := resolverLink(r)
		if err != nil {
			return nil, err
		}
		if !ours {
			if r.Index == 0 {
				missing = append(missing, id) // the old format: the link is gone, so the entry is
			}
			continue
		}
		switch r.Kind {
		case "dns":
			l, err := resolvectlGet("dns", r.Link)
			if err != nil {
				return nil, err
			}
			if len(l) == 0 {
				missing = append(missing, id)
			}
		case "domain":
			l, err := resolvectlGet("domain", r.Link)
			if err != nil {
				return nil, err
			}
			has := false
			for _, d := range l {
				has = has || d == "~"+r.Zone
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
// "domain <link> <zone> <ifindex>", plus "dns <link> <ifindex> <servers>" if the
// link had no DNS servers. When the link or its settings cannot be read nothing
// is planned for it: not knowing whether it has DNS servers is no reason to set
// or to clear any.
func resolverPlan(iface string, servers, zones []string) []string {
	if len(zones) == 0 || !hasResolved() {
		return nil
	}
	idx, found, err := ifaceByName(iface)
	if err != nil || !found {
		return nil
	}
	cur, err := resolvectlGet("dns", iface)
	if err != nil {
		return nil
	}
	var ids []string
	if srv := validServers(servers); len(cur) == 0 && len(srv) > 0 {
		ids = append(ids, config.FormatLinuxResolver(iface, idx, "", srv))
	}
	for _, z := range zones {
		ids = append(ids, config.FormatLinuxResolver(iface, idx, z, nil))
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
	r, ok := config.ParseLinuxResolver(id)
	if !ok {
		return fmt.Errorf("invalid DNS entry %q", id)
	}
	if err := config.ValidateServers(servers); err != nil {
		return err
	}
	if ours, why, err := resolverLink(r); err != nil {
		return err
	} else if !ours {
		return fmt.Errorf("DNS entry %q: %s", id, why)
	}
	switch {
	case r.Kind == "dns" && r.Index != 0:
		return resolvectl(append([]string{"dns", r.Link}, r.Servers...)...)
	case r.Kind == "dns":
		return resolvectl(append([]string{"dns", r.Link}, servers...)...)
	case r.Kind == "domain":
		cur, err := resolvectlGet("domain", r.Link)
		if err != nil {
			return fmt.Errorf("cannot read the domains of %s, nothing changed: %w", r.Link, err)
		}
		for _, d := range cur {
			if strings.TrimPrefix(d, "~") == r.Zone {
				return fmt.Errorf("%w: already set up on %s, left as is", errResolverExists, r.Link)
			}
		}
		return resolvectl(append([]string{"domain", r.Link}, append(cur, "~"+r.Zone)...)...)
	}
	return fmt.Errorf("unknown DNS entry %q", id)
}

// delResolver takes the entry away, if it is ours: on the same link (the index
// is the one in the journal), and for "dns" with the servers that were set. What
// cannot be told (resolvectl does not answer) is an error, and the entry stays in
// the journal; what is not ours is errNotOurs.
func delResolver(id string) error {
	resolvedMu.Lock()
	defer resolvedMu.Unlock()
	r, ok := config.ParseLinuxResolver(id)
	if !ok {
		return fmt.Errorf("invalid DNS entry %q", id)
	}
	ours, why, err := resolverLink(r)
	if err != nil {
		return err
	}
	if !ours {
		if r.Index == 0 {
			return nil // the link is gone and took its DNS settings with it
		}
		return fmt.Errorf("%w: %s", errNotOurs, why)
	}
	switch r.Kind {
	case "dns":
		if r.Index == 0 {
			return resolvectl("dns", r.Link, "")
		}
		cur, err := resolvectlGet("dns", r.Link)
		if err != nil {
			return fmt.Errorf("cannot read the DNS servers of %s, left as they are: %w", r.Link, err)
		}
		switch {
		case len(cur) == 0:
			return nil // already gone
		case !sameSet(cur, r.Servers):
			return fmt.Errorf("%w: the DNS servers of %s are not the ones that were set (%s)", errNotOurs, r.Link, strings.Join(cur, ","))
		}
		return resolvectl("dns", r.Link, "")
	case "domain":
		cur, err := resolvectlGet("domain", r.Link)
		if err != nil {
			return fmt.Errorf("cannot read the domains of %s, left as they are: %w", r.Link, err)
		}
		var keep []string
		found := false
		for _, d := range cur {
			if d == "~"+r.Zone {
				found = true
				continue
			}
			keep = append(keep, d)
		}
		if !found {
			return nil // already gone
		}
		if len(keep) == 0 {
			keep = []string{""}
		}
		return resolvectl(append([]string{"domain", r.Link}, keep...)...)
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
