package router

import (
	"fmt"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// A DNS entry that somebody else has made is not in the journal at any moment:
// the journal written before the entries are made lists everything that may come
// to exist, and an entry that turned out to be there already is taken out of it
// at once. The state at the time of the flush is what a kill between the
// entries and the final journal would leave.
func TestForeignDNSEntryIsNotInTheJournalMidway(t *testing.T) {
	needDNS(t)
	a, cfg := splitDNSRig(t)
	fb := &foreignBackend{memBackend: a.mb, foreignIDs: map[string]bool{}}
	a.m.b = fb
	tbl, rs := a.m.readTables()
	pl := a.m.buildPlan(cfg, *a.env, &config.State{}, tbl, rs, &discard{})
	if pl.rest == nil {
		t.Fatal("no rule for the rest")
	}
	for _, id := range pl.rest.ids {
		fb.foreignIDs[id] = true
	}
	var midway []string
	called := false
	fb.onFlush = func() {
		called = true
		midway = append([]string(nil), a.store.state().Resolvers...)
	}
	a.apply(t, cfg)
	if !called {
		t.Fatal("the cache was not flushed, so nothing was checked")
	}
	if !hasID(midway, "corp.example") {
		t.Errorf("the corp zone, made by us, is not in the journal midway: %v", midway)
	}
	for _, id := range pl.rest.ids {
		if hasID(midway, id) {
			t.Errorf("the entry %q of somebody else was in the journal midway: %v", id, midway)
		}
	}
}

// lostBackend is an OS where the DNS settings are gone after a restart.
type lostBackend struct{ *fakeBackend }

func (lostBackend) resolversLostOnReboot() bool { return true }

// The DNS settings that do not survive a restart are forgotten with the routes,
// not removed: what is there now under the same name is somebody else's.
func TestRecoverAfterRebootForgetsResolvedSettings(t *testing.T) {
	j := sessionJournal(4242, config.ModePersistent)
	j.Owner.Boot = "boot-1"
	r := newRig(j)
	r.m.b = lostBackend{r.b}
	_, info := acquire(t, r, config.ModePersistent)
	for _, l := range r.b.calls() {
		if strings.HasPrefix(l, "dns ") || strings.HasPrefix(l, "route ") {
			t.Errorf("removed after a restart: %v", r.b.calls())
		}
	}
	if info.Recovered.Resolvers != 0 || info.Recovered.Forgotten != 4 {
		t.Errorf("%+v", info.Recovered)
	}
	if st := r.store.state(); len(st.Routes) != 0 || len(st.Resolvers) != 0 {
		t.Errorf("%+v", st)
	}
}

// notOursBackend is an OS that finds the DNS entries of the journal changed.
type notOursBackend struct{ *fakeBackend }

func (b notOursBackend) DelResolver(id string) error {
	b.record("dns " + id)
	return fmt.Errorf("%w: the link was made again", errNotOurs)
}

// An entry that is not ours any more stays as it is, is reported as left and
// leaves the journal.
func TestResolverNotOursIsLeftAndDropped(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModeSession))
	r.m.b = notOursBackend{r.b}
	_, info := acquire(t, r, config.ModeSession)
	if info.Recovered.Resolvers != 0 || len(info.Recovered.Left) != 1 || !strings.Contains(info.Recovered.Left[0], "DNS ") {
		t.Errorf("%+v", info.Recovered)
	}
	if st := r.store.state(); len(st.Resolvers) != 0 {
		t.Errorf("the entry stays in the journal: %v", st.Resolvers)
	}
}

// The same in a cycle that retires an entry of the plan.
type notOursMem struct{ *foreignBackend }

func (b notOursMem) DelResolver(id string) error {
	b.memBackend.dnsLog = append(b.memBackend.dnsLog, "del "+id)
	return fmt.Errorf("%w: the servers were changed", errNotOurs)
}

func TestReconcileDropsResolverThatIsNotOurs(t *testing.T) {
	needDNS(t)
	a, cfg := splitDNSRig(t)
	a.apply(t, cfg)
	if len(a.store.state().Resolvers) == 0 {
		t.Fatal("no DNS entries")
	}
	a.m.b = notOursMem{&foreignBackend{memBackend: a.mb, foreignIDs: map[string]bool{}}}
	cfg.SplitDNS = false
	out := a.apply(t, cfg)
	if strings.Contains(out, "! DNS") {
		t.Errorf("a failure is reported:\n%s", out)
	}
	if st := a.store.state(); len(st.Resolvers) != 0 {
		t.Errorf("entries that are not ours stay in the journal: %v", st.Resolvers)
	}
}
