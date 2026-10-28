package router

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

func acquireAs(t *testing.T, r *rig, mode string) (*Session, AcquireInfo) {
	t.Helper()
	s, info, err := r.m.Acquire(context.Background(), mode, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("Acquire(%s): %v", mode, err)
	}
	return s, info
}

// The lock proves that the owner is dead: a running process with the same PID
// and start time only earns a warning.
func TestRecoverLiveOwnerOnlyWarns(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModeSession))
	r.procs.alive[4242] = 4000 // exactly the owner of the journal (start 4000)
	var out bytes.Buffer
	_, info, err := r.m.Acquire(context.Background(), config.ModeSession, &out)
	if err != nil {
		t.Fatalf("a live PID must not block: %v", err)
	}
	if info.Recovered.Routes != 3 {
		t.Errorf("the routes must be removed: %+v", info)
	}
	if !strings.Contains(out.String(), "warning") || !strings.Contains(out.String(), "4242") {
		t.Errorf("no warning: %q", out.String())
	}
}

// A process that cannot be looked into (Alive says yes, the start time is
// unknown) neither blocks nor warns.
func TestRecoverUnknownStartNeitherBlocksNorWarns(t *testing.T) {
	j := sessionJournal(4242, config.ModeSession)
	j.Owner.Start = 0
	r := newRig(j)
	r.procs.alive[4242] = 4000
	var out bytes.Buffer
	if _, info, err := r.m.Acquire(context.Background(), config.ModeSession, &out); err != nil || info.Recovered.Routes != 3 {
		t.Fatalf("%v %+v", err, info)
	}
	if strings.Contains(out.String(), "warning") {
		t.Errorf("%q", out.String())
	}
}

func TestRecoverEmptyBootIDWarns(t *testing.T) {
	j := sessionJournal(4242, config.ModeSession)
	j.Owner.Boot = ""
	r := newRig(j)
	var out bytes.Buffer
	if _, _, err := r.m.Acquire(context.Background(), config.ModeSession, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "boot id is unknown") {
		t.Errorf("%q", out.String())
	}
}

// A signal during the start cancels the recovery: what was not reached stays
// in the journal, the lock is released, the error says why.
func TestAcquireCancelledDuringRecover(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModeSession))
	r.b.block = make(chan struct{})
	defer close(r.b.block)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	_, _, err := r.m.Acquire(ctx, config.ModeSession, &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) || time.Since(start) > 3*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	if r.lock.held {
		t.Error("the lock must be released")
	}
	st := r.store.state()
	if len(st.Routes) != 3 || st.Mode != config.ModeSession || st.Owner == nil || st.Owner.PID != 4242 {
		t.Errorf("the rest must stay with the dead owner's header: %+v", st)
	}
	// already cancelled: nothing is even tried
	if _, _, err := r.m.Acquire(ctx, config.ModeSession, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Errorf("%v", err)
	}
}

// A signal during Apply/Reset: Abort stops them and later ones are refused,
// even though nothing holds the semaphore.
func TestAbortRefusesOperations(t *testing.T) {
	r := newRig(nil)
	s, _ := acquireAs(t, r, config.ModeSession)
	s.Abort()
	if err := r.m.Apply(config.New(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("Apply after Abort: %v", err)
	}
	if _, errs := r.m.Reset(); len(errs) != 1 || !strings.Contains(errs[0].Error(), "interrupted") {
		t.Errorf("Reset after Abort: %v", errs)
	}
	if len(r.b.calls()) != 0 {
		t.Error("the OS was touched")
	}
}

// An operation in flight when the session ends: Cleanup waits for it within
// the deadline.
func TestCleanupWaitsForTheOperationInFlight(t *testing.T) {
	r := newRig(nil)
	s, _ := acquireAs(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: homeRoutes(), Sig: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := r.m.begin(); err != nil { // an Apply that is busy
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() { time.Sleep(100 * time.Millisecond); r.m.unlockSem(); close(released) }()
	rep, err := s.CleanupUntil(time.Now().Add(3*time.Second), nil)
	<-released
	if err != nil || rep.Routes != 2 {
		t.Errorf("an operation that ends in time must not spoil the cleanup: %+v %v", rep, err)
	}
	if r.lock.held {
		t.Error("lock not released")
	}
}

func TestCleanupPanicBecomesError(t *testing.T) {
	r := newRig(nil)
	s, _ := acquireAs(t, r, config.ModeSession)
	r.store.panicOnLoad = true
	_, err := s.Cleanup(time.Second)
	if err == nil || !strings.Contains(err.Error(), "internal error") || !strings.Contains(err.Error(), "journal exploded") {
		t.Fatalf("%v", err)
	}
	if r.lock.held {
		t.Error("the lock must be released after a panic: nothing else is running")
	}
	if _, err2 := s.Cleanup(time.Second); err2 == nil {
		t.Error("later calls return the first result")
	}
}

// The deadline is absolute: one that has passed leaves everything in the journal.
func TestCleanupUntilPastDeadlineKeepsEverything(t *testing.T) {
	r := newRig(nil)
	s, _ := acquireAs(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: homeRoutes(), Sig: "x"}); err != nil {
		t.Fatal(err)
	}
	r.b.block = make(chan struct{})
	defer close(r.b.block)
	start := time.Now()
	_, err := s.CleanupUntil(time.Now().Add(-time.Second), nil)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("%v after %v", err, time.Since(start))
	}
	if st := r.store.state(); len(st.Routes) != 2 || st.Mode != config.ModeSession {
		t.Errorf("%+v", st)
	}
}

func TestCleanupReportsProgress(t *testing.T) {
	r := newRig(nil)
	s, _ := acquireAs(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: homeRoutes(), Resolvers: []string{testResolver("a.example")}, Sig: "x"}); err != nil {
		t.Fatal(err)
	}
	var last, total atomic.Int32
	if _, err := s.CleanupUntil(time.Now().Add(5*time.Second), func(done, n int) { last.Store(int32(done)); total.Store(int32(n)) }); err != nil {
		t.Fatal(err)
	}
	if last.Load() != 3 || total.Load() != 3 {
		t.Errorf("progress %d of %d", last.Load(), total.Load())
	}
}

// A call that finished is not reported as "not removed" when the deadline
// comes at the same moment.
func TestRunAllCountsFinishedCallsAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	errs := runAll(ctx, []int{1, 2, 3}, 1, func(i int) error {
		if i == 2 {
			cancel()
		}
		return nil
	})
	if errs[0] != nil || errs[1] != nil {
		t.Errorf("finished calls: %v", errs)
	}
}

// ModeSessionAsk over a persistent journal (applied by apply/watch): nothing
// is taken over and nothing removed at exit until TakeOver.
func TestSessionAskLeavesPersistentUntilConfirmed(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModePersistent))
	s, info := acquireAs(t, r, ModeSessionAsk)
	if !info.Foreign || info.TookOver || !s.Foreign() || s.Mode() != config.ModePersistent {
		t.Fatalf("%+v foreign=%v mode=%s", info, s.Foreign(), s.Mode())
	}
	if st := r.store.state(); st.Mode != config.ModePersistent || len(st.Routes) != 3 {
		t.Errorf("%+v", st)
	}
	rep, err := s.Cleanup(time.Second) // quit without confirming
	if err != nil || rep.Total() != 0 || len(r.b.calls()) != 0 {
		t.Errorf("%+v %v %v", rep, err, r.b.calls())
	}
	if st := r.store.state(); st.Mode != config.ModePersistent || len(st.Routes) != 3 {
		t.Errorf("the routes must stay persistent: %+v", st)
	}
}

func TestSessionAskTakeOverThenCleanupRemoves(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModePersistent))
	s, _ := acquireAs(t, r, ModeSessionAsk)
	if err := s.TakeOver(); err != nil {
		t.Fatal(err)
	}
	if s.Foreign() || s.Mode() != config.ModeSession {
		t.Errorf("foreign=%v mode=%s", s.Foreign(), s.Mode())
	}
	if st := r.store.state(); st.Mode != config.ModeSession || st.Owner.PID != 100 || len(st.Routes) != 3 {
		t.Errorf("%+v", st)
	}
	rep, err := s.Cleanup(time.Second)
	if err != nil || rep.Routes != 3 || !rep.FullTunnel {
		t.Errorf("%+v %v", rep, err)
	}
	if st := r.store.state(); !st.Empty() {
		t.Errorf("%+v", st)
	}
}

// Without persistent entries the menu is a plain session; a dead session's
// leftovers are removed first, as before.
func TestSessionAskOnEmptyOrDeadSessionIsSession(t *testing.T) {
	r := newRig(nil)
	s, info := acquireAs(t, r, ModeSessionAsk)
	if info.Foreign || s.Mode() != config.ModeSession || s.Foreign() {
		t.Errorf("%+v %s", info, s.Mode())
	}
	r = newRig(sessionJournal(4242, config.ModeSession))
	s, info = acquireAs(t, r, ModeSessionAsk)
	if info.Foreign || s.Mode() != config.ModeSession || info.Recovered.Routes != 3 {
		t.Errorf("%+v %s", info, s.Mode())
	}
}

// Reset from the menu empties the journal: nothing is left to confirm, and
// what is applied afterwards is the session's.
func TestSessionAskResetEndsTheForeignState(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModePersistent))
	s, _ := acquireAs(t, r, ModeSessionAsk)
	if n, errs := r.m.Reset(); n != 4 || len(errs) != 0 {
		t.Fatalf("%d %v", n, errs)
	}
	if s.Foreign() || s.Mode() != config.ModeSession {
		t.Errorf("foreign=%v mode=%s", s.Foreign(), s.Mode())
	}
	if err := r.m.save(&config.State{Routes: homeRoutes()}); err != nil {
		t.Fatal(err)
	}
	if st := r.store.state(); st.Mode != config.ModeSession {
		t.Errorf("%+v", st)
	}
}

// After a reboot a session's routes are gone: they are forgotten, not
// removed (the table may hold a VPN client's route to the same place), and
// its DNS entries are removed.
func TestRecoverSessionAfterRebootForgetsRoutes(t *testing.T) {
	j := sessionJournal(4242, config.ModeSession)
	j.Owner.Boot = "boot-1"
	r := newRig(j)
	_, info := acquireAs(t, r, config.ModeSession)
	for _, l := range r.b.calls() {
		if strings.HasPrefix(l, "route ") {
			t.Errorf("a route was removed after a reboot: %v", r.b.calls())
		}
	}
	if info.Recovered.Resolvers != 1 || info.Recovered.Forgotten != 3 {
		t.Errorf("%+v", info.Recovered)
	}
	if st := r.store.state(); len(st.Routes) != 0 || len(st.Resolvers) != 0 {
		t.Errorf("%+v", st)
	}
}

// --force: the boot id is not believed, everything listed is removed.
func TestForceRemovesAfterRebootVerdict(t *testing.T) {
	j := sessionJournal(4242, config.ModePersistent)
	j.Owner.Boot = "boot-1"
	r := newRig(j)
	r.m.SetForce(true)
	acquireAs(t, r, config.ModePersistent)
	if st := r.store.state(); len(st.Routes) != 3 {
		t.Fatalf("the routes must stay for Reset: %+v", st)
	}
	n, errs := r.m.Reset()
	if n != 4 || len(errs) != 0 {
		t.Errorf("%d %v", n, errs)
	}
}

// Leftovers of a dead session stay the session's even if the new run is
// persistent: they must not become permanent.
func TestLeftoversOfDeadSessionStayAsSession(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModeSession))
	r.b.failRoute["10.10.0.0/16"] = errors.New("busy")
	s, info := acquireAs(t, r, config.ModePersistent)
	if len(info.Errors) != 1 {
		t.Fatalf("%+v", info)
	}
	st := r.store.state()
	if len(st.Routes) != 1 || st.Mode != config.ModeSession || st.Owner.PID != 100 {
		t.Errorf("%+v", st)
	}
	// the persistent run ends: the header still says session, the next start removes it
	if _, err := s.Cleanup(time.Second); err != nil {
		t.Fatal(err)
	}
	if st := r.store.state(); st.Mode != config.ModeSession || len(st.Routes) != 1 {
		t.Errorf("%+v", st)
	}
	delete(r.b.failRoute, "10.10.0.0/16")
	next := r.another(300)
	if _, info, err := next.m.Acquire(context.Background(), config.ModeSession, &bytes.Buffer{}); err != nil || info.Recovered.Routes != 1 {
		t.Errorf("%+v %v", info, err)
	}
}

func TestReportNotice(t *testing.T) {
	if (Report{Routes: 2}).Notice(true) != "" {
		t.Error("no notice without the full tunnel")
	}
	n := (Report{FullTunnel: true}).Notice(true)
	if !strings.Contains(n, "Весь трафик теперь идёт напрямую через провайдера (мимо домашнего VPN), пока VPN-клиент сам не направит его в туннель") {
		t.Error(n)
	}
	if !strings.Contains((Report{FullTunnel: true}).Notice(false), "ISP") {
		t.Error("English notice")
	}
}
