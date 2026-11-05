package router

import "github.com/UniQlow17/vpnsplit/internal/config"

// ownDNSEntry finds the "dns" entry of the journal for the link iface (with
// this index) whose servers are the ones the link has now: the entry is ours
// and still stands.
func ownDNSEntry(journal []string, iface string, idx int, cur []string) (config.LinuxResolver, bool) {
	if len(cur) == 0 {
		return config.LinuxResolver{}, false
	}
	for _, id := range journal {
		if r, ok := config.ParseLinuxResolver(id); ok && r.Kind == "dns" && r.Link == iface && r.Index == idx && sameSet(cur, r.Servers) {
			return r, true
		}
	}
	return config.LinuxResolver{}, false
}
