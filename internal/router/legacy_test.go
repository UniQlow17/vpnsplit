package router

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// A route the backend says is not ours is not counted as removed, is reported
// as left, and leaves the journal (it would be found "not ours" at every start).
func TestResetNotOursIsLeftAndForgotten(t *testing.T) {
	r := newRig(nil)
	acquire(t, r, config.ModeSession)
	r.b.failRoute["10.0.0.0/8"] = fmt.Errorf("%w: another metric", errNotOurs)
	if err := r.m.save(&config.State{Routes: []config.Route{
		{Dest: "10.0.0.0/8", Iface: "eth0", Metric: 3},
		{Dest: "10.1.0.0/16", Iface: "eth0", Metric: 3},
	}}); err != nil {
		t.Fatal(err)
	}
	rep, errs := r.m.ResetReport()
	if len(errs) != 0 {
		t.Fatalf("%v", errs)
	}
	if rep.Routes != 1 || len(rep.Left) != 1 || !strings.Contains(rep.Left[0], "10.0.0.0/8") {
		t.Fatalf("%+v", rep)
	}
	if st := r.store.state(); len(st.Routes) != 0 {
		t.Errorf("the entry stays in the journal: %+v", st.Routes)
	}
	if d := rep.Describe(false); !strings.Contains(d, "left") {
		t.Errorf("%q", d)
	}
	if d := rep.Describe(true); !strings.Contains(d, "оставлено") {
		t.Errorf("%q", d)
	}
}

// Routes taken over from the untrusted old journal keep the exceptions of the
// routes that are not in the journal: a VPN client's adapter and /1 or shorter
// stay, and the report says so. The same prefixes from the protected journal
// are removed as before.
func TestRemoveEntriesLegacyExceptions(t *testing.T) {
	r := newRig(nil)
	r.m.providerOf = func() map[string]string { return map[string]string{"clientvpn": "SomeVPN"} }
	acquire(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: []config.Route{
		{Dest: "10.0.0.0/8", Iface: "clientvpn", FromLegacy: true},
		{Dest: "0.0.0.0/1", Iface: "eth0", FromLegacy: true},
		{Dest: "192.168.50.0/24", Iface: "eth0", FromLegacy: true},
		{Dest: "172.16.0.0/12", Iface: "clientvpn", Metric: 3}, // the protected journal: removed
	}}); err != nil {
		t.Fatal(err)
	}
	rep, errs := r.m.ResetReport()
	if len(errs) != 0 {
		t.Fatalf("%v", errs)
	}
	calls := strings.Join(r.b.calls(), " ")
	if strings.Contains(calls, "route 10.0.0.0/8") || strings.Contains(calls, "route 0.0.0.0/1") {
		t.Errorf("a route that must stay was removed: %s", calls)
	}
	if !strings.Contains(calls, "route 192.168.50.0/24") || !strings.Contains(calls, "route 172.16.0.0/12") {
		t.Errorf("a route that is ours stayed: %s", calls)
	}
	if rep.Routes != 2 || len(rep.Left) != 2 {
		t.Errorf("%+v", rep)
	}
	if joined := strings.Join(rep.Left, "|"); !strings.Contains(joined, "SomeVPN") || !strings.Contains(joined, "full tunnel") {
		t.Errorf("the reasons: %q", joined)
	}
	if st := r.store.state(); len(st.Routes) != 0 {
		t.Errorf("%+v", st.Routes)
	}
}

// bulkBackend removes the DNS entries in one call, as the Windows backend does.
type bulkBackend struct {
	*fakeBackend
}

func (b bulkBackend) DelResolvers(ids []string) error {
	b.record("dns-all " + strings.Join(ids, ","))
	return nil
}

func TestRemoveEntriesBulkDNS(t *testing.T) {
	r := newRig(nil)
	r.m.b = bulkBackend{r.b}
	acquire(t, r, config.ModeSession)
	if err := r.m.save(&config.State{
		Resolvers: []string{testResolver("a.example"), testResolver("b.example")},
		Routes:    []config.Route{{Dest: "10.0.0.0/8", Iface: "eth0", Metric: 3}},
	}); err != nil {
		t.Fatal(err)
	}
	rep, errs := r.m.ResetReport()
	if len(errs) != 0 || rep.Resolvers != 2 || rep.Routes != 1 {
		t.Fatalf("%+v %v", rep, errs)
	}
	var all, single int
	for _, c := range r.b.calls() {
		switch {
		case strings.HasPrefix(c, "dns-all"):
			all++
		case strings.HasPrefix(c, "dns "):
			single++
		}
	}
	if all != 1 || single != 0 {
		t.Errorf("%v", r.b.calls())
	}
	if !before(r.b.calls(), "dns-all", "route ") {
		t.Errorf("order %v", r.b.calls())
	}
}

// slowDNS never finishes removing DNS entries.
type slowDNS struct {
	*fakeBackend
	release chan struct{}
}

func (b slowDNS) DelResolver(id string) error {
	<-b.release
	return nil
}

// The DNS entries get a share of the time only: the routes start in time
// even if DNS hangs, and the entry that was not removed stays in the journal.
func TestDNSCeilingLeavesTimeForRoutes(t *testing.T) {
	r := newRig(nil)
	slow := slowDNS{r.b, make(chan struct{})}
	defer close(slow.release)
	r.m.b = slow
	s, _ := acquire(t, r, config.ModeSession)
	if err := r.m.save(&config.State{
		Resolvers: []string{testResolver("a.example")},
		Routes:    []config.Route{{Dest: "10.0.0.0/8", Iface: "eth0", Metric: 3}},
	}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := s.CleanupUntil(start.Add(3*time.Second), nil)
	if err == nil {
		t.Error("the DNS entry was not removed: an error expected")
	}
	if !strings.Contains(strings.Join(r.b.calls(), " "), "route 10.0.0.0/8") {
		t.Errorf("the route was not removed: %v", r.b.calls())
	}
	if el := time.Since(start); el > 2500*time.Millisecond {
		t.Errorf("DNS took the whole budget: %v", el)
	}
	if st := r.store.state(); len(st.Resolvers) != 1 || len(st.Routes) != 0 {
		t.Errorf("%+v", st)
	}
}

// migratingStore tells which way the journal was read.
type migratingStore struct {
	*memStore
	migrate, plain int
}

func (s *migratingStore) Load() (*config.State, []string, config.JournalStatus) {
	s.plain++
	return s.memStore.Load()
}

func (s *migratingStore) LoadMigrate() (*config.State, []string, config.JournalStatus) {
	s.migrate++
	return s.memStore.Load()
}

// The old journal is taken over by Acquire and reset (the lock is held), never
// by the plain reads.
func TestMigrationOnlyUnderTheLock(t *testing.T) {
	r := newRig(nil)
	ms := &migratingStore{memStore: r.store}
	r.m.store = ms
	if _, _, err := r.m.Acquire(context.Background(), config.ModeSession, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if ms.migrate != 1 {
		t.Errorf("Acquire read with migration %d times", ms.migrate)
	}
	before := ms.migrate
	r.m.ResetReport()
	if ms.migrate != before+1 {
		t.Errorf("reset: %d", ms.migrate-before)
	}
	pl := ms.plain
	r.m.busy()
	if ms.migrate != before+1 || ms.plain != pl+1 {
		t.Errorf("the busy check must only read: migrate %d plain %d", ms.migrate, ms.plain-pl)
	}
}
