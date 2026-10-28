package router

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// pendingSig is the Sig of a journal whose apply has not finished: it never
// equals a real one, so a watching process applies again if the first one died.
const pendingSig = "pending"

// diff is the difference between the desired state and the journal and the
// OS table.
type diff struct {
	keep   []config.Route // in the journal, wanted, and in the table (or the table is unknown)
	readd  []config.Route // in the journal and wanted, but missing from the table (or the apply was cut short and the table is unknown)
	add    []config.Route // wanted, not in the journal
	del    []config.Route // in the journal (or ours in the table) and not wanted
	adopt  []config.Route // ours in the table, wanted, not in the journal
	dropJ  int            // duplicates and invalid entries removed from the journal
	keepR  []config.Rule
	readdR []config.Rule
	addR   []config.Rule
	delR   []config.Rule
}

// makeDiff compares what is wanted with what the journal and the table say.
// A table that cannot be read (tbl.known == false) is taken to agree with the
// journal, unless the journal says the last apply was cut short (pendingSig):
// its entries may never have been created, so they are created again. On OSes
// that tag routes, routes of ours that nobody wants and the journal has lost
// are removed as well.
func makeDiff(st *config.State, p *plan, tbl *table, rs *ruleSet, partial bool) *diff {
	d := &diff{}
	want := make(map[rkey]config.Route, len(p.routes))
	for _, r := range p.routes {
		want[keyOf(r)] = r
	}
	inJ := make(map[rkey]bool, len(st.Routes))
	for _, jr := range st.Routes {
		k := keyOf(jr)
		if config.ValidateRoute(jr) != nil || inJ[k] {
			d.dropJ++
			continue
		}
		inJ[k] = true
		switch _, wanted := want[k]; {
		case !wanted && partial:
			d.keep = append(d.keep, jr)
		case !wanted:
			d.del = append(d.del, jr)
		case !tbl.known && st.Sig == pendingSig:
			d.readd = append(d.readd, jr)
		case !tbl.known || tbl.has(jr):
			d.keep = append(d.keep, jr)
		default:
			d.readd = append(d.readd, jr)
		}
	}
	for _, r := range p.routes {
		k := keyOf(r)
		if inJ[k] {
			continue
		}
		if o, ok := tbl.byKey[k]; ok && tbl.known && routesTagged && o.Ours {
			d.adopt = append(d.adopt, r)
			continue
		}
		d.add = append(d.add, r)
	}
	for _, o := range tbl.ours() {
		if partial {
			break
		}
		k := o.key()
		if _, wanted := want[k]; wanted || inJ[k] || o.Iface == "" {
			continue
		}
		d.del = append(d.del, o.toRoute()) // ours, and nobody asked for it: left by a lost journal
	}

	wantR := make(map[ruleKey]config.Rule, len(p.rules))
	for _, r := range p.rules {
		wantR[ruleKeyOf(r)] = r
	}
	inJR := map[ruleKey]bool{}
	for _, jr := range st.Rules {
		k := ruleKeyOf(jr)
		if config.ValidateRule(jr) != nil || inJR[k] {
			d.dropJ++
			continue
		}
		inJR[k] = true
		switch _, wanted := wantR[k]; {
		case !wanted && partial:
			d.keepR = append(d.keepR, jr)
		case !wanted:
			d.delR = append(d.delR, jr)
		case !rs.known && st.Sig == pendingSig:
			d.readdR = append(d.readdR, jr)
		case !rs.known || rs.has(jr):
			d.keepR = append(d.keepR, jr)
		default:
			d.readdR = append(d.readdR, jr)
		}
	}
	for _, r := range p.rules {
		if !inJR[ruleKeyOf(r)] {
			d.addR = append(d.addR, r)
		}
	}
	if rs.known && !partial {
		for _, o := range rs.all {
			k, shape := o.isOurShape()
			if !shape {
				continue
			}
			if _, wanted := wantR[k]; wanted || inJR[k] {
				continue
			}
			d.delR = append(d.delR, config.Rule{Table: k.table, Pref: k.pref})
		}
	}
	return d
}

// planned is the journal to write before anything is changed: everything
// that may exist when this run is over, so that a crash at any point leaves
// nothing unrecorded. Entries that turn out not to be created are harmless:
// removal ignores what is not there.
func (d *diff) planned(st *config.State, newIDs []string) *config.State {
	n := &config.State{Sig: pendingSig, DNSSig: st.DNSSig}
	seen := map[rkey]bool{}
	for _, list := range [][]config.Route{d.keep, d.readd, d.adopt, d.add, d.del} {
		for _, r := range list {
			if k := keyOf(r); !seen[k] {
				seen[k] = true
				n.Routes = append(n.Routes, r)
			}
		}
	}
	seenR := map[ruleKey]bool{}
	for _, list := range [][]config.Rule{d.keepR, d.readdR, d.addR, d.delR} {
		for _, r := range list {
			if k := ruleKeyOf(r); !seenR[k] {
				seenR[k] = true
				n.Rules = append(n.Rules, r)
			}
		}
	}
	n.Resolvers = append([]string(nil), st.Resolvers...)
	for _, id := range newIDs {
		n.Resolvers = config.AddUnique(n.Resolvers, id)
	}
	return n
}

func (d *diff) empty() bool {
	return len(d.readd)+len(d.add)+len(d.del)+len(d.adopt)+len(d.readdR)+len(d.addR)+len(d.delR) == 0 && d.dropJ == 0
}

// summary counts what reconcile did.
type summary struct{ added, kept, unchanged, removed, failed int }

// slot is what the OS allows one route to occupy: a destination in a table.
// A route that takes the place of another one of ours has the same slot.
type slot struct {
	dest  netip.Prefix
	table int
}

func slotOf(r config.Route) slot {
	k := keyOf(r)
	return slot{k.dest, k.table}
}

// replacer is a Backend that can put a route in the place of another route of
// ours in one step (Linux: NLM_F_REPLACE).
type replacer interface {
	ReplaceRoute(old, next config.Route) error
}

// resolverChecker is a Backend that can tell which DNS entries are missing.
type resolverChecker interface {
	MissingResolvers(ids []string) ([]string, error)
}

// missingResolvers lists the entries that are not in the OS; nothing is
// reported (and no error) where the backend cannot tell.
func missingResolvers(b Backend, ids []string) ([]string, error) {
	if c, ok := b.(resolverChecker); ok {
		return c.MissingResolvers(ids)
	}
	return nil, nil
}

// replaceRoute makes next exist and old go away, in this order. added tells
// whether next exists afterwards. err is why it does not (added false) or why
// old could not be removed (added true).
func (m *Manager) replaceRoute(old, next config.Route) (added bool, err error) {
	if r, ok := m.b.(replacer); ok {
		if err := r.ReplaceRoute(old, next); err != nil {
			return false, err
		}
		return true, nil
	}
	err = m.b.AddRoute(next)
	if err == nil {
		return true, ignoreNotOurs(m.b.DelRoute(old))
	}
	if !errors.Is(err, errExists) {
		return false, err
	}
	// The OS keeps one route per slot, and ours is in the way: it goes first
	// and comes back if the new one still cannot be created.
	if derr := ignoreNotOurs(m.b.DelRoute(old)); derr != nil {
		return false, err
	}
	if aerr := m.b.AddRoute(next); aerr != nil {
		// the old route is put back; if that fails too, the journal still lists it
		if rerr := m.b.AddRoute(old); rerr != nil && !errors.Is(rerr, errExists) {
			return false, fmt.Errorf("%w (and the old route could not be restored: %v)", aerr, rerr)
		}
		return false, aerr
	}
	return true, nil
}

// reconcile brings the OS to p without tearing everything down first: what is
// in place stays, what is missing is added, what is ours and not wanted any
// more is removed. The journal is written twice, whatever the number of routes:
// before the first change (everything that may come to exist) and after the
// last (what does exist). The order is: routes added (a route that takes the
// place of one of ours replaces it, and the old one is not touched if the new
// one cannot be created); rules added; rules removed; routes removed; DNS
// entries added, then the ones nobody wants any more removed. A rule never
// outlives the routes it was for, no route is removed while the rule that finds
// it is still the only way to it, and a DNS entry that is wanted and in place is
// never taken away to be made again (only the missing ones are made).
func (m *Manager) reconcile(st *config.State, p *plan, tbl *table, rs *ruleSet, sig string, partial bool, w io.Writer) error {
	defer m.flushNotes() // what was found in place and left alone (noteKept) is written once
	d := makeDiff(st, p, tbl, rs, partial)
	var dnsSig string
	var newIDs []string
	if p.dns != nil {
		dnsSig = p.dns.sig()
		newIDs = p.dns.ids
	}
	// the entries in place stay while they point where the plan wants them to (the
	// adapter and the servers); a plan that changes only the zones adds the new
	// ones and removes the old ones, and leaves the rest alone
	retarget := dnsTarget(dnsSig) != dnsTarget(st.DNSSig)
	sigChanged := dnsSig != st.DNSSig
	dnsChange := !partial && (sigChanged || (p.dns == nil && len(st.Resolvers) > 0) || !sameSet(st.Resolvers, newIDs))
	var missingIDs map[string]bool // entries removed behind our back
	if !partial && !dnsChange && p.dns != nil && len(st.Resolvers) > 0 {
		if missing, err := missingResolvers(m.b, st.Resolvers); err == nil && len(missing) > 0 {
			dnsChange = true // an entry was removed behind our back: those are made again
			missingIDs = make(map[string]bool, len(missing))
			for _, id := range missing {
				missingIDs[id] = true
			}
			fmt.Fprintf(w, "  ! DNS entries missing: %d, restoring\n", len(missing))
		}
	}

	changes := !d.empty() || dnsChange
	if changes {
		if err := m.save(d.planned(st, newIDs)); err != nil {
			return err
		}
	}
	var sum summary

	out := &config.State{Sig: sig, DNSSig: dnsSig}
	out.Routes = append(out.Routes, d.keep...)
	out.Routes = append(out.Routes, d.adopt...)
	sum.unchanged = len(d.keep) + len(d.adopt)

	adds := append(append([]config.Route(nil), d.readd...), d.add...)
	journaled := make(map[rkey]bool, len(d.readd))
	for _, r := range d.readd {
		journaled[keyOf(r)] = true
	}

	// stale routes whose place is taken by an addition are replaced by it; the
	// others are removed after the rules
	addSlot := map[slot]bool{}
	for _, r := range adds {
		addSlot[slotOf(r)] = true
	}
	stale := map[slot]config.Route{}
	var delLater []config.Route
	for _, r := range d.del {
		sl := slotOf(r)
		if _, taken := stale[sl]; !taken && addSlot[sl] {
			stale[sl] = r
		} else {
			delLater = append(delLater, r)
		}
	}
	var failedDel []config.Route // still in the OS: the journal keeps them for the next try
	var ownTbl *table            // the table as it is after our own additions, read when needed
	var ownRules *ruleSet
	var readOnce sync.Once
	reread := func() {
		readOnce.Do(func() { ownTbl, ownRules = m.readTables() })
	}

	for _, r := range adds {
		if m.ctx.Err() != nil {
			break // the program is exiting: Cleanup removes what the journal lists
		}
		if err := config.ValidateRoute(r); err != nil {
			sum.failed++
			fmt.Fprintf(w, "  ! %s: %v\n", r.Dest, err)
			continue
		}
		s, paired := stale[slotOf(r)]
		if paired {
			delete(stale, slotOf(r))
		}
		var added bool
		var err error
		if paired {
			added, err = m.replaceRoute(s, r)
		} else {
			err = m.b.AddRoute(r)
			added = err == nil
		}
		switch {
		case added:
			sum.added++
			out.Routes = append(out.Routes, r)
			fmt.Fprintf(w, "  + %-18s -> %-6s %s\n", r.Dest, r.Via, r.Iface)
			if paired && err != nil {
				fmt.Fprintf(w, "  ! remove %s -> %s: %v\n", s.Dest, s.Iface, err)
				failedDel = append(failedDel, s)
				sum.failed++
			} else if paired {
				sum.removed++
				fmt.Fprintf(w, "  - %-18s -> %-6s %s (replaced)\n", s.Dest, s.Via, s.Iface)
			}
		case errors.Is(err, errExists):
			if journaled[keyOf(r)] {
				// ours, from the apply that was cut short: stays in the journal so that it is removed
				reread()
				if ownTbl.known && !ownTbl.has(r) {
					sum.kept++
					m.noteKept(r)
					fmt.Fprintf(w, "  = %-18s already routed by the system or a VPN client, left as is\n", r.Dest)
				} else {
					sum.unchanged++
					out.Routes = append(out.Routes, r)
					fmt.Fprintf(w, "  = %-18s already in place\n", r.Dest)
				}
			} else {
				sum.kept++
				m.noteKept(r)
				fmt.Fprintf(w, "  = %-18s already routed by the system or a VPN client, left as is\n", r.Dest)
			}
			if paired {
				failedDel = append(failedDel, s)
			}
		default:
			sum.failed++
			fmt.Fprintf(w, "  ! %s via %s: %v\n", r.Dest, r.Iface, err)
			if paired {
				failedDel = append(failedDel, s)
			}
		}
	}
	for _, s := range stale { // not reached: the program is exiting, or the addition was invalid
		if m.ctx.Err() != nil {
			failedDel = append(failedDel, s)
		} else {
			delLater = append(delLater, s)
		}
	}

	out.Rules = append(out.Rules, d.keepR...)
	journaledR := map[ruleKey]bool{}
	for _, r := range d.readdR {
		journaledR[ruleKeyOf(r)] = true
	}
	for _, r := range append(append([]config.Rule(nil), d.readdR...), d.addR...) {
		if m.ctx.Err() != nil {
			break
		}
		err := m.b.AddRule(r)
		switch {
		case err == nil:
			sum.added++
			out.Rules = append(out.Rules, r)
			fmt.Fprintf(w, "  + rule lookup %d pref %d\n", r.Table, r.Pref)
		case errors.Is(err, errExists):
			sum.kept++
			if journaledR[ruleKeyOf(r)] {
				// ours from the apply that was cut short: stays in the journal so that it is removed
				reread()
				if !ownRules.known || ownRules.has(r) {
					out.Rules = append(out.Rules, r)
				}
			}
			fmt.Fprintf(w, "  = rule lookup %d pref %d is there already, left as is\n", r.Table, r.Pref)
		default:
			sum.failed++
			fmt.Fprintf(w, "  ! rule lookup %d: %v\n", r.Table, err)
		}
	}

	// rules go before the routes they were for
	for _, r := range d.delR {
		if m.ctx.Err() != nil {
			out.Rules = append(out.Rules, r)
			continue
		}
		if err := m.b.DelRule(r); err != nil {
			fmt.Fprintf(w, "  ! remove rule lookup %d: %v\n", r.Table, err)
			out.Rules = append(out.Rules, r)
			sum.failed++
			continue
		}
		sum.removed++
		fmt.Fprintf(w, "  - rule lookup %d pref %d\n", r.Table, r.Pref)
	}
	for _, r := range delLater {
		if m.ctx.Err() != nil {
			failedDel = append(failedDel, r)
			continue
		}
		if err := ignoreNotOurs(m.b.DelRoute(r)); err != nil {
			fmt.Fprintf(w, "  ! remove %s: %v\n", r.Dest, err)
			failedDel = append(failedDel, r)
			sum.failed++
			continue
		}
		sum.removed++
		fmt.Fprintf(w, "  - %-18s -> %-6s %s\n", r.Dest, r.Via, r.Iface)
	}
	out.Routes = append(out.Routes, failedDel...)

	// DNS entries last: the new and the missing are made first, then the ones
	// nobody wants any more go. An entry that is wanted and in place stays.
	out.Resolvers = append([]string(nil), st.Resolvers...)
	inJournal := make(map[string]bool, len(st.Resolvers))
	for _, id := range st.Resolvers {
		inJournal[id] = true
	}
	if dnsChange && p.dns != nil && m.ctx.Err() == nil {
		for _, id := range p.dns.ids {
			if m.ctx.Err() != nil {
				break
			}
			if inJournal[id] && !retarget && !missingIDs[id] {
				continue
			}
			err := m.b.AddResolver(id, p.dns.servers)
			if errors.Is(err, errResolverExists) {
				fmt.Fprintf(w, "  = %s: %v\n", id, err)
				continue
			}
			if err != nil {
				sum.failed++
				fmt.Fprintf(w, "  ! %s: %v\n", id, err)
				continue
			}
			out.Resolvers = config.AddUnique(out.Resolvers, id)
			sum.added++
			fmt.Fprintf(w, "  + %-18s -> corp DNS\n", id)
		}
	}
	if dnsChange {
		wanted := make(map[string]bool, len(newIDs))
		for _, id := range newIDs {
			wanted[id] = true
		}
		var left []string
		for _, id := range out.Resolvers {
			if wanted[id] {
				left = append(left, id)
				continue
			}
			if m.ctx.Err() != nil {
				left = append(left, id)
				continue
			}
			if err := m.b.DelResolver(id); err != nil {
				fmt.Fprintf(w, "  ! DNS %s: %v\n", id, err)
				left = append(left, id)
				continue
			}
			sum.removed++
		}
		out.Resolvers = left
		if len(st.Resolvers) > 0 || len(out.Resolvers) > 0 || sum.added > 0 {
			m.b.FlushDNS()
		}
	}
	switch {
	case partial:
		out.DNSSig = st.DNSSig
	case p.dns == nil || m.ctx.Err() != nil || len(out.Resolvers) != len(p.dns.ids):
		out.DNSSig = "" // not complete: the next apply redoes the DNS entries
	}
	if m.ctx.Err() != nil {
		out.Sig = pendingSig // do not claim the job is done: a watching process tries again
	}

	if partial {
		out.Sig = st.Sig
		if changes {
			out.Sig = pendingSig // the full plan follows and sets the real one
		}
	}
	if changes || out.Sig != st.Sig {
		if err := m.save(out); err != nil {
			fmt.Fprintf(w, "  ! journal: %v\n", err)
			return fmt.Errorf("journal not updated after applying: %w", err)
		}
	}
	if partial {
		return nil
	}
	fmt.Fprintf(w, "done: %d added, %d already in place, %d unchanged, %d removed, %d failed. Undo anytime with: vpnsplit reset\n",
		sum.added, sum.kept, sum.unchanged, sum.removed, sum.failed)
	return nil
}

// dnsTarget is the part of a DNS signature that says where the entries point:
// the adapter and the servers ("iface|servers|zones").
func dnsTarget(sig string) string {
	parts := strings.SplitN(sig, "|", 3)
	if len(parts) < 3 {
		return sig
	}
	return parts[0] + "|" + parts[1]
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool, len(a))
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}

// dnsCheckEvery is how often Drifted looks at the DNS entries: that can mean
// starting a tool, which is too much for every cycle of a watching process.
const dnsCheckEvery = 30 * time.Second

// dnsCheck remembers when Drifted last looked at the DNS entries.
var dnsCheck struct {
	mu   sync.Mutex
	last time.Time
}

func dnsCheckDue(now time.Time) bool {
	dnsCheck.mu.Lock()
	defer dnsCheck.mu.Unlock()
	if now.Sub(dnsCheck.last) < dnsCheckEvery {
		return false
	}
	dnsCheck.last = now
	return true
}

// Drifted reports whether something the journal lists is missing from the OS:
// a VPN reconnected and its routes went with the old adapter, or somebody
// removed them. It only reads the tables, which is cheap enough for every
// cycle of a watching process; the DNS entries are looked at every
// dnsCheckEvery only. A table that cannot be read is no drift.
func Drifted(st *config.State) bool { return drifted(osBackend{}, st) }

func drifted(b Backend, st *config.State) bool {
	if len(st.Routes) == 0 && len(st.Rules) == 0 && len(st.Resolvers) == 0 {
		return false
	}
	if len(st.Routes) > 0 {
		rs, err := b.Routes()
		if err != nil {
			return false
		}
		t := newTable(rs)
		for _, r := range st.Routes {
			if !t.has(r) {
				return true
			}
		}
	}
	if len(st.Rules) > 0 {
		rules, err := b.Rules()
		if err != nil {
			return false
		}
		s := newRuleSet(rules)
		for _, r := range st.Rules {
			if !s.has(r) {
				return true
			}
		}
	}
	if len(st.Resolvers) > 0 && dnsCheckDue(time.Now()) {
		if missing, err := missingResolvers(b, st.Resolvers); err == nil && len(missing) > 0 {
			return true
		}
	}
	return false
}
