package config

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf16"
)

const stateFile = "state.json"

// Route is one route added by this tool.
type Route struct {
	Dest    string `json:"dest"` // CIDR
	Iface   string `json:"iface"`
	Gateway string `json:"gateway,omitempty"`
	Via     string `json:"via,omitempty"` // corp, home, direct or pin; for display
	// Metric is the route metric the route was created with; it is part of
	// what marks the route as ours (see EffMetric). 0 in a journal written
	// before the metric was recorded: such routes have metric 1.
	Metric int `json:"metric,omitempty"`
	// Table is the routing table the route lives in: 0 is the main one,
	// an own one (Linux, see Rule; OwnTable or the next free of 247-250). Routes of older journals are in main.
	Table int `json:"table,omitempty"`
	// FromLegacy marks a route taken over from the old journal in the user's
	// directory, which is untrusted. It is set by trustLegacy only; removal is
	// more careful with such a route (a VPN client's adapter, /1 and shorter
	// stay; on Windows the OS row must be a metric-1 route of an old version).
	FromLegacy bool `json:"from_legacy,omitempty"`
}

// OwnTable is the routing table (Linux) in which routes live that must be seen
// by a policy rule of ours. 247 (0xF7) is the number our routes and rules carry
// as their protocol too; it is not in the rt_tables of iproute2, and Apply
// leaves the table alone if somebody else has put routes into it.
const OwnTable = 247

// OwnTableLast ends the range from which a table is picked when OwnTable is
// taken by somebody else (see IsOwnTable): 247 to 250.
const OwnTableLast = 250

// IsOwnTable reports whether t is one of the tables vpnsplit may use.
func IsOwnTable(t int) bool { return t >= OwnTable && t <= OwnTableLast }

// LegacyMetric is the metric every route had before the journal recorded one.
const LegacyMetric = 1

// EffMetric is the metric the route has in the OS table.
func (r Route) EffMetric() int {
	if r.Metric == 0 {
		return LegacyMetric
	}
	return r.Metric
}

// Legacy reports whether the route comes from a journal that recorded no
// metric (and, on OSes that tag routes, no tag either).
func (r Route) Legacy() bool { return r.Metric == 0 }

// Rule is the policy routing rule added by this tool (Linux): "lookup Table"
// at preference Pref, with no selector, before the rules of a VPN client that
// sends everything into its own table. Our routes for corp and direct
// networks live in Table. A packet that finds no route there goes on to the
// next rule, so a missing route of ours never lets traffic around the client.
type Rule struct {
	Table int `json:"table"`
	Pref  int `json:"pref"`
}

// How the journal's owner treats what it applied when it exits.
const (
	// ModeSession: everything is removed when the owner exits, and by the
	// next start if the owner died without doing it.
	ModeSession = "session"
	// ModePersistent: what was applied stays after the owner exits (the
	// one-shot `apply`, `watch`); only `reset` or a session removes it.
	ModePersistent = "persistent"
)

// JournalVersion is the format written by this version. Version 0 (no
// header) is the journal of older versions, which only had the entries.
const JournalVersion = 2

// Owner identifies the process that applied what the journal lists.
type Owner struct {
	PID   int    `json:"pid"`
	Start int64  `json:"start,omitempty"` // process start time (OS unit): a reused PID has another
	Boot  string `json:"boot,omitempty"`  // boot id: entries that live in memory are gone after a reboot
}

// State is the journal of what we own. Each entry is written BEFORE it is
// created, so a reset can always undo it, even after a crash.
type State struct {
	Version   int      `json:"version,omitempty"`
	Owner     *Owner   `json:"owner,omitempty"` // nil: journal of an older version
	Mode      string   `json:"mode,omitempty"`  // ModeSession or ModePersistent; "" with no owner
	Routes    []Route  `json:"routes"`
	Rules     []Rule   `json:"rules,omitempty"`     // policy routing rules we created (Linux)
	Resolvers []string `json:"resolvers,omitempty"` // per-domain DNS entries we created
	Sig       string   `json:"sig,omitempty"`       // what was connected when applied
	DNSSig    string   `json:"dns_sig,omitempty"`   // what the DNS entries were created for
	// Tun6 is the state of the automatic IPv6 tunnels of Windows (Teredo, 6to4,
	// ISATAP) as it was before they were turned off; they are put back at the end.
	Tun6 *Tunnels6 `json:"tun6,omitempty"`
}

// Tunnels6 holds the settings of the automatic IPv6 tunnelling of Windows that
// were turned off: the value each had before, "" for one that was not touched.
// The values are the names the cmdlets use (see Canon); nothing else is ever
// handed to them.
type Tunnels6 struct {
	Teredo    string `json:"teredo,omitempty"`    // Get-NetTeredoConfiguration .Type
	SixToFour string `json:"sixtofour,omitempty"` // Get-Net6to4Configuration .State
	ISATAP    string `json:"isatap,omitempty"`    // Get-NetIsatapConfiguration .State
}

var (
	teredoTypes = []string{"Default", "Disabled", "Client", "EnterpriseClient", "Server", "NATAwareClient", "NATAwareServer"}
	tunStates6  = []string{"Default", "Automatic", "Enabled", "Disabled"}
	isatapState = []string{"Default", "Enabled", "Disabled"}
)

func canonOf(list []string, v string) (string, bool) {
	for _, c := range list {
		if strings.EqualFold(c, v) {
			return c, true
		}
	}
	return "", false
}

// CanonTeredo, CanonSixToFour and CanonISATAP return the canonical spelling of a
// value a cmdlet reported or the journal holds; ok is false for anything else.
func CanonTeredo(v string) (string, bool)    { return canonOf(teredoTypes, v) }
func CanonSixToFour(v string) (string, bool) { return canonOf(tunStates6, v) }
func CanonISATAP(v string) (string, bool)    { return canonOf(isatapState, v) }

// Empty reports whether no setting is recorded.
func (t *Tunnels6) Empty() bool { return t == nil || *t == Tunnels6{} }

// Sanitize keeps the values that are in the lists above and clears the rest.
func (t *Tunnels6) Sanitize() (dropped int) {
	for _, f := range []struct {
		p    *string
		list []string
	}{{&t.Teredo, teredoTypes}, {&t.SixToFour, tunStates6}, {&t.ISATAP, isatapState}} {
		if *f.p == "" {
			continue
		}
		if c, ok := canonOf(f.list, *f.p); ok {
			*f.p = c
		} else {
			*f.p = ""
			dropped++
		}
	}
	return dropped
}

// Empty reports whether nothing is applied.
func (s *State) Empty() bool {
	return len(s.Routes) == 0 && len(s.Rules) == 0 && len(s.Resolvers) == 0 && s.Sig == "" && s.Tun6.Empty()
}

// ValidResolverEntry reports whether id is a DNS journal entry in the format
// of this OS (see resolverPlan in internal/router).
func ValidResolverEntry(id string) bool { return validResolverEntry(runtime.GOOS, id) }

func validResolverEntry(goos, id string) bool {
	switch goos {
	case "windows": // the zone, or "." for the rule that sends everything else to the home DNS
		return ValidZone(id) || id == "."
	case "darwin": // /etc/resolver/<zone>
		zone := filepath.Base(id)
		return id == "/etc/resolver/"+zone && ValidZone(zone)
	default: // Linux, see ParseLinuxResolver
		_, ok := ParseLinuxResolver(id)
		return ok
	}
}

// LinuxResolver is a DNS journal entry of systemd-resolved, see ParseLinuxResolver.
type LinuxResolver struct {
	Kind    string   // "dns" or "domain"
	Link    string   // the link
	Index   int      // the index of the link when the entry was made; 0 in the old format, which has none
	Zone    string   // "domain": the zone, "." for everything else
	Servers []string // "dns": the servers that were set
}

// ParseLinuxResolver reads a journal entry of systemd-resolved. The formats:
//
//	dns <link> <ifindex> <server>[,<server>...]
//	domain <link> <zone> <ifindex>
//	dns <link>, domain <link> <zone>   (old: no index, not trusted after a
//	                                    restart of the computer)
//
// The index and the servers tell the entry apart from the settings that
// somebody else made later under the same name: resolved forgets the settings of
// a gone link, and a link that is made again has another index.
func ParseLinuxResolver(id string) (LinuxResolver, bool) {
	f := strings.Fields(id)
	if len(f) < 2 || strings.Join(f, " ") != id || !ValidIface(f[1]) {
		return LinuxResolver{}, false
	}
	r := LinuxResolver{Kind: f[0], Link: f[1]}
	var ok bool
	switch {
	case len(f) == 2 && f[0] == "dns":
		return r, true
	case len(f) == 4 && f[0] == "dns":
		if r.Index, ok = parseIfIndex(f[2]); !ok {
			return LinuxResolver{}, false
		}
		for _, s := range strings.Split(f[3], ",") {
			if _, err := ParseIPv4(s); err != nil {
				return LinuxResolver{}, false
			}
			r.Servers = append(r.Servers, s)
		}
		return r, true
	case len(f) == 3 && f[0] == "domain" && validLinuxZone(f[2]):
		r.Zone = f[2]
		return r, true
	case len(f) == 4 && f[0] == "domain" && validLinuxZone(f[2]):
		if r.Index, ok = parseIfIndex(f[3]); !ok {
			return LinuxResolver{}, false
		}
		r.Zone = f[2]
		return r, true
	}
	return LinuxResolver{}, false
}

func validLinuxZone(z string) bool { return ValidZone(z) || z == "." } // "." is the routing domain "~." of everything else

func parseIfIndex(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 1<<30 || strconv.Itoa(n) != s {
		return 0, false
	}
	return n, true
}

// FormatLinuxResolver makes the journal entry for "dns" (zone empty) or
// "domain" (zone set) of a link.
func FormatLinuxResolver(link string, index int, zone string, servers []string) string {
	if zone == "" {
		return fmt.Sprintf("dns %s %d %s", link, index, strings.Join(servers, ","))
	}
	return fmt.Sprintf("domain %s %s %d", link, zone, index)
}

// Sanitize drops every journal entry that could not have been written by this
// tool: the journal is executed with administrator rights.
func (s *State) Sanitize() (warnings []string) {
	var routes []Route
	for _, r := range s.Routes {
		if err := ValidateRoute(r); err != nil {
			warnings = append(warnings, "journal: entry dropped: "+err.Error())
			continue
		}
		routes = append(routes, r)
	}
	s.Routes = routes
	var rules []Rule
	for _, r := range s.Rules {
		if err := ValidateRule(r); err != nil {
			warnings = append(warnings, "journal: entry dropped: "+err.Error())
			continue
		}
		rules = append(rules, r)
	}
	s.Rules = rules
	var res []string
	for _, id := range s.Resolvers {
		if !ValidResolverEntry(id) {
			warnings = append(warnings, fmt.Sprintf("journal: DNS entry %q dropped: unexpected format", clip(id)))
			continue
		}
		res = append(res, id)
	}
	s.Resolvers = res
	if s.Tun6 != nil {
		if n := s.Tun6.Sanitize(); n > 0 {
			warnings = append(warnings, fmt.Sprintf("journal: %d unexpected IPv6 tunnel setting(s) dropped", n))
		}
		if s.Tun6.Empty() {
			s.Tun6 = nil
		}
	}
	if len(s.Sig) > 1024 || hasControl(s.Sig) {
		s.Sig = ""
	}
	if len(s.DNSSig) > 4096 || hasControl(s.DNSSig) {
		s.DNSSig = ""
	}
	if s.Mode != ModeSession && s.Mode != ModePersistent {
		s.Mode = ""
	}
	if o := s.Owner; o != nil {
		if o.PID <= 0 || o.Start < 0 {
			s.Owner = nil
		} else if len(o.Boot) > 64 || clip(o.Boot) != o.Boot {
			o.Boot = ""
		}
	}
	return warnings
}

// decodeText turns the bytes of a text file into UTF-8: a byte order mark is
// dropped, and UTF-16 (with or without the mark; what PowerShell's Out-File and
// Notepad write) is converted.
func decodeText(b []byte) []byte {
	switch {
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return b[3:]
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return utf16Bytes(b[2:], false)
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		return utf16Bytes(b[2:], true)
	case len(b) >= 4 && b[0] != 0 && b[1] == 0 && b[2] != 0 && b[3] == 0: // "{" 0 and the like
		return utf16Bytes(b, false)
	case len(b) >= 4 && b[0] == 0 && b[1] != 0 && b[2] == 0 && b[3] != 0:
		return utf16Bytes(b, true)
	}
	return b
}

func utf16Bytes(b []byte, bigEndian bool) []byte {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			u = append(u, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return []byte(string(utf16.Decode(u)))
}

func parseState(b []byte) (*State, []string, error) {
	b = decodeText(b)
	s := &State{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, nil, err
	}
	return s, s.Sanitize(), nil
}

// merge adds the entries of o that s does not have yet.
func (s *State) merge(o *State) {
	have := map[Route]bool{}
	for _, r := range s.Routes {
		have[r] = true
	}
	for _, r := range o.Routes {
		if !have[r] {
			s.Routes = append(s.Routes, r)
		}
	}
	haveRule := map[Rule]bool{}
	for _, r := range s.Rules {
		haveRule[r] = true
	}
	for _, r := range o.Rules {
		if !haveRule[r] {
			s.Rules = append(s.Rules, r)
		}
	}
	for _, id := range o.Resolvers {
		s.Resolvers = AddUnique(s.Resolvers, id)
	}
	if s.Sig == "" {
		s.Sig = o.Sig
	}
	if s.Tun6.Empty() && !o.Tun6.Empty() {
		c := *o.Tun6
		s.Tun6 = &c
	}
}
