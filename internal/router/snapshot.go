package router

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// How long the comparison with the snapshot may take where it must not hold
// the start up (Acquire), the time below which a cleanup is a shutdown of the
// OS, and how little time is worth starting a comparison with.
const (
	acquireCompareBudget = 10 * time.Second
	abruptBelow          = 10 * time.Second
	minCompareTime       = 1500 * time.Millisecond
)

// maxSnapRoutes is config.MaxSnapRoutes; tests lower it.
var maxSnapRoutes = config.MaxSnapRoutes

// providersByName maps the adapters to the VPN client behind them (netif). The
// result is nil (not empty) when the adapters could not be listed.
func providersByName() map[string]string {
	ifs, err := netif.List()
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, i := range ifs {
		if i.Provider != "" {
			m[i.Name] = i.Provider
		}
	}
	return m
}

// takeSnapshot records the system as it is now, leaving out what the journal
// lists and, where the table marks routes (Linux), what carries our mark: that
// is vpnsplit's, not the baseline. On Windows a route with the shape of ours
// (metric 3, NETMGMT, Manual) is not left out unless the journal lists it: it may
// be a client's or the user's, and by being in the baseline it is never removed.
func (m *Manager) takeSnapshot(ctx context.Context, st *config.State, self config.Owner) *config.Snapshot {
	cur := m.readOS(ctx, true)
	sn := &config.Snapshot{Version: 1, Owner: &self, Taken: time.Now().UTC().Format(time.RFC3339), Approx: !st.Empty(),
		RoutesKnown: cur.routesKnown, RulesKnown: cur.rulesKnown, ResolversKnown: cur.resolversKnown}
	jid := map[routeID]bool{}
	for _, r := range st.Routes {
		if p, err := netip.ParsePrefix(r.Dest); err == nil {
			jid[routeID{table: r.Table, dest: p.Masked(), gw: addrOrZero(r.Gateway), iface: r.Iface, metric: r.EffMetric()}] = true
		}
	}
	for _, o := range cur.routes {
		if jid[idOf(o)] || (m.goos != "windows" && routeMark(m.goos, o) == markOurs) {
			continue
		}
		sn.Routes = append(sn.Routes, snapRouteOf(o))
	}
	if len(sn.Routes) > maxSnapRoutes {
		n := len(sn.Routes)
		sn.Routes, sn.RoutesKnown = nil, false
		sn.ReportOnly, sn.Why = true, fmt.Sprintf("%s (%d routes)", reasonTooLarge, n)
	}
	jr := map[ruleKey]bool{}
	for _, r := range st.Rules {
		jr[ruleKeyOf(r)] = true
	}
	for _, o := range cur.rules {
		if k, ours := o.isOurShape(); ours && (jr[k] || o.Ours) {
			continue
		}
		sn.Rules = append(sn.Rules, snapRuleOf(o))
	}
	jres := map[string]bool{}
	for _, id := range st.Resolvers {
		jres[id] = true
	}
	for _, o := range cur.resolvers {
		if o.Ours || jres[o.ID] {
			continue
		}
		sn.Resolvers = append(sn.Resolvers, config.SnapResolver{ID: o.ID, Detail: o.Detail})
	}
	return sn
}

// snapState is what is known about whether sn describes the system of this boot.
func (m *Manager) snapState(sn *config.Snapshot) config.SnapState {
	return sn.Validity(m.procs.Self(), m.procs.SameBoot, time.Now())
}

// acquireSnapshot is the part of Acquire that deals with the baseline. The
// journal is as recover left it. An earlier run's snapshot of this boot is
// kept while the journal still lists entries (they are not the baseline); if
// the journal is empty, the earlier run did not get to compare (it ran out of
// time, or was killed), and that is done now, within a budget of its own
// (it must not hold the start up for as long as the recovery may). Then a new
// snapshot is taken, unless the old one is still needed. A snapshot that
// cannot be tied to this boot of the computer is compared for the report only.
func (m *Manager) acquireSnapshot(ctx context.Context, st *config.State, self config.Owner, w io.Writer) *Baseline {
	ss, ok := m.store.(snapshotStore)
	if !ok {
		return nil
	}
	var res *Baseline
	old, err := ss.LoadSnapshot()
	if err != nil {
		fmt.Fprintln(w, "warning: the snapshot of the state before the earlier run is unreadable, ignored:", err)
		old = nil
	}
	state := config.SnapInvalid
	if old != nil {
		if state = m.snapState(old); state == config.SnapInvalid {
			old = nil // the computer was restarted: the table it describes is gone
		}
	}
	left := !st.Empty()
	if old != nil {
		m.loadPlanned(ss, old) // the sweep tells the routes of our plans by them
	}
	if old != nil && !left {
		cctx, cancel := context.WithTimeout(ctx, acquireCompareBudget)
		o := sweepOpts{dns: true, fix: state == config.SnapProven}
		if state != config.SnapProven {
			o.why = reasonUnproven
		}
		b := m.sweep(cctx, old, st, o)
		cancel()
		res = &b
		if b.Cut {
			return res // the next start tries again; this run's baseline is that one
		}
		old = nil
	}
	if old != nil {
		return res
	}
	tctx, cancel := context.WithTimeout(ctx, acquireCompareBudget)
	sn := m.takeSnapshot(tctx, st, self)
	cancel()
	if err := ss.SaveSnapshot(sn); err != nil {
		fmt.Fprintln(w, "warning: the snapshot of the state before the start was not saved, the end of the session cannot compare with it:", err)
	}
	m.mu.Lock()
	m.planned, m.kept, m.planTaken, m.planDirty = map[string]bool{}, map[string]bool{}, sn.Taken, false
	m.mu.Unlock()
	_ = ss.SavePlanNotes(&config.PlanNotes{Taken: sn.Taken}) // best effort: it empties the notes of the snapshot before
	return res
}

// loadPlanned takes over the notes of the plans that were made since sn.
func (m *Manager) loadPlanned(ss snapshotStore, sn *config.Snapshot) {
	n, _ := ss.LoadPlanNotes(sn.Taken) // best effort: without it only the routes of our plan go unrecognized
	m.mu.Lock()
	defer m.mu.Unlock()
	m.planTaken = sn.Taken
	if n == nil {
		return
	}
	for _, d := range n.Planned {
		m.planned[d] = true
	}
	for _, d := range n.Kept {
		m.kept[d] = true
	}
}

// notePlanned records the routes of a plan before they are applied: a route
// that carries our mark is told from a client's by it. The notes are written to
// a file of their own, once per call.
func (m *Manager) notePlanned(routes []config.Route) {
	m.noteRoutes(routes, false)
	m.flushNotes()
}

// noteKept records a route that was found in place and left as somebody
// else's: it is never taken for a route of ours. It is written by flushNotes,
// which the caller runs after a batch.
func (m *Manager) noteKept(r config.Route) { m.noteRoutes([]config.Route{r}, true) }

func (m *Manager) noteRoutes(routes []config.Route, kept bool) {
	if m.closed.Load() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.planned // chosen under the lock: the maps are replaced by Acquire
	if kept {
		set = m.kept
	}
	for _, r := range routes {
		if k := routeKey(r); k != "" && !set[k] {
			set[k] = true
			m.planDirty = true
		}
	}
}

// flushNotes writes the notes if they grew.
func (m *Manager) flushNotes() {
	ss, ok := m.store.(snapshotStore)
	if !ok || m.closed.Load() {
		return
	}
	m.mu.Lock()
	if !m.planDirty || m.planTaken == "" {
		m.mu.Unlock()
		return
	}
	n := &config.PlanNotes{Taken: m.planTaken, Planned: keysOf(m.planned), Kept: keysOf(m.kept)}
	m.planDirty = false
	m.mu.Unlock()
	if err := ss.SavePlanNotes(n); err != nil { // best effort: without it only routes of our plan go unrecognized
		m.mu.Lock()
		m.planDirty = true
		m.mu.Unlock()
	}
}

func keysOf(set map[string]bool) []string {
	list := make([]string, 0, len(set))
	for d := range set {
		list = append(list, d)
	}
	sort.Strings(list)
	return list
}

// settle compares the system with the snapshot after the journal's entries are
// removed, removes what is ours, and drops the snapshot when that is complete.
// abrupt is a cleanup in a hurry (the OS is shutting the program down): the DNS
// entries are not read, and with too little time left nothing is compared; the
// snapshot stays and the next start finishes the job.
func (m *Manager) settle(ctx context.Context, abrupt bool) *Baseline {
	ss, ok := m.store.(snapshotStore)
	if !ok {
		return nil
	}
	if dl, has := ctx.Deadline(); abrupt && has && time.Until(dl) < minCompareTime {
		return &Baseline{Cut: true}
	}
	sn, err := ss.LoadSnapshot()
	if err != nil {
		return &Baseline{Note: err.Error()}
	}
	if sn == nil {
		return &Baseline{Note: "no snapshot"}
	}
	state := m.snapState(sn)
	if state == config.SnapInvalid {
		_ = ss.RemoveSnapshot()
		return &Baseline{Note: "the snapshot is from before a restart of the computer"}
	}
	st, _, _ := m.store.Load()
	m.loadPlanned(ss, sn)
	o := sweepOpts{dns: !abrupt, fix: state == config.SnapProven}
	if !o.fix {
		o.why = reasonUnproven
	}
	b := m.sweep(ctx, sn, st, o)
	if b.Checked && !b.Cut && o.fix {
		if err := ss.RemoveSnapshot(); err != nil {
			b.Note = "the snapshot was not deleted: " + err.Error()
		}
	}
	return &b
}

// Settle is the comparison with the state before the start, for a command that
// ends without Cleanup removing anything (`reset`): everything the journal
// listed is removed, now whatever else of ours is. It does nothing while the
// journal still lists entries.
func (s *Session) Settle(deadline time.Time) *Baseline {
	if err := s.m.requireOwner(); err != nil {
		return nil
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := s.m.lockSem(ctx); err != nil {
		return nil
	}
	defer s.m.unlockSem()
	if st, _, status := s.m.store.Load(); statusErr(status) != nil || !st.Empty() {
		return nil
	}
	return s.m.settle(ctx, false)
}

// Diff compares the system with the snapshot of the state before the start,
// without changing anything. withDNS also reads the per-domain DNS entries
// (on Windows that starts PowerShell). The snapshot is in the protected
// directory: without administrator rights the result says so.
func Diff(ctx context.Context, withDNS bool) Baseline {
	return NewManager().diff(ctx, withDNS)
}

func (m *Manager) diff(ctx context.Context, withDNS bool) Baseline {
	ss, ok := m.store.(snapshotStore)
	if !ok {
		return Baseline{Note: "no snapshot"}
	}
	sn, err := ss.LoadSnapshot()
	if err != nil {
		return Baseline{Note: err.Error()}
	}
	if sn == nil {
		return Baseline{Note: "no snapshot"}
	}
	state := m.snapState(sn)
	if state == config.SnapInvalid {
		return Baseline{Note: "the snapshot is from before a restart of the computer"}
	}
	st, _, _ := m.store.Load()
	m.loadPlanned(ss, sn)
	o := sweepOpts{dns: withDNS}
	if state == config.SnapUnproven {
		o.why = reasonUnproven
	}
	return m.sweep(ctx, sn, st, o)
}
