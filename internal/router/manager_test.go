package router

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

func acquire(t *testing.T, r *rig, mode string) (*Session, AcquireInfo) {
	t.Helper()
	var w bytes.Buffer
	s, info, err := r.m.Acquire(context.Background(), mode, &w)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	return s, info
}

// A session journal whose owner is gone is removed at the next start, DNS first.
func TestRecoverDeadSessionRemovesAll(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModeSession)) // 4242 is not alive
	_, info := acquire(t, r, config.ModeSession)
	log := r.b.calls()
	if info.Recovered.Routes != 3 || info.Recovered.Resolvers != 1 || !info.Recovered.FullTunnel || len(info.Errors) != 0 {
		t.Errorf("%+v", info)
	}
	if !before(log, "dns ", "route ") {
		t.Errorf("DNS must be removed before routes: %v", log)
	}
	st := r.store.state()
	if len(st.Routes) != 0 || len(st.Resolvers) != 0 || st.Owner == nil || st.Owner.PID != 100 || st.Mode != config.ModeSession {
		t.Errorf("journal after Acquire: %+v", st)
	}
}

// The PID of the owner is used by another process now: it is not the owner.
func TestRecoverPidReused(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModeSession))
	r.procs.alive[4242] = 999999 // another start time
	acquire(t, r, config.ModeSession)
	if len(r.b.calls()) == 0 {
		t.Error("a reused PID is not a live owner: the journal must be cleaned")
	}
}

func TestRecoverPersistentIsKept(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModePersistent))
	_, info := acquire(t, r, config.ModePersistent)
	if len(r.b.calls()) != 0 || info.TookOver {
		t.Errorf("persistent journal touched: %v %+v", r.b.calls(), info)
	}
	if len(r.store.state().Routes) != 3 {
		t.Error("routes lost")
	}
}

// A session started over a persistent journal takes it over: it becomes a
// session's, so it is removed when the session ends.
func TestSessionTakesOverPersistent(t *testing.T) {
	r := newRig(sessionJournal(4242, config.ModePersistent))
	s, info := acquire(t, r, config.ModeSession)
	if !info.TookOver || len(r.b.calls()) != 0 {
		t.Fatalf("%+v %v", info, r.b.calls())
	}
	if st := r.store.state(); st.Mode != config.ModeSession || st.Owner.PID != 100 || len(st.Routes) != 3 {
		t.Errorf("%+v", st)
	}
	rep, err := s.Cleanup(time.Second)
	if err != nil || rep.Routes != 3 {
		t.Errorf("%+v %v", rep, err)
	}
}

func TestRecoverPersistentAfterReboot(t *testing.T) {
	j := sessionJournal(4242, config.ModePersistent)
	j.Owner.Boot = "boot-1"
	r := newRig(j)
	_, info := acquire(t, r, config.ModePersistent)
	log := r.b.calls()
	for _, l := range log {
		if strings.HasPrefix(l, "route ") {
			t.Errorf("routes are gone with the reboot, not removed: %v", log)
		}
	}
	if info.Recovered.Resolvers != 1 || info.Recovered.Forgotten != 3 {
		t.Errorf("%+v", info.Recovered)
	}
	if st := r.store.state(); len(st.Routes) != 0 || len(st.Resolvers) != 0 || st.Sig != "" {
		t.Errorf("%+v", st)
	}
}

// The journal of an older version has no owner: treated as persistent.
func TestRecoverLegacyJournalIsKept(t *testing.T) {
	r := newRig(&config.State{Routes: homeRoutes(), Sig: "s"})
	_, info := acquire(t, r, config.ModeSession)
	if len(r.b.calls()) != 0 || !info.TookOver {
		t.Errorf("%v %+v", r.b.calls(), info)
	}
}

func TestSecondCopyIsRefused(t *testing.T) {
	first := newRig(nil)
	s, _ := acquire(t, first, config.ModeSession)
	second := first.another(200)
	_, _, err := second.m.Acquire(context.Background(), config.ModeSession, &bytes.Buffer{})
	var busy *BusyError
	if !errors.As(err, &busy) || !errors.Is(err, config.ErrLocked) {
		t.Fatalf("err %v", err)
	}
	if busy.Owner == nil || busy.Owner.PID != 100 || !strings.Contains(busy.Error(), "PID 100") {
		t.Errorf("the message must name the running copy: %v", busy)
	}
	if err := second.m.Apply(config.New(), &bytes.Buffer{}); !errors.Is(err, errNotOwner) {
		t.Errorf("Apply by a copy that does not own the journal: %v", err)
	}
	if n, errs := second.m.Reset(); n != 0 || len(errs) != 1 {
		t.Errorf("Reset by a copy that does not own the journal: %d %v", n, errs)
	}
	if len(second.b.calls()) != 0 {
		t.Error("the second copy changed something")
	}
	if _, err := s.Cleanup(time.Second); err != nil {
		t.Fatal(err)
	}
	// the first is gone: now the second may start
	if _, _, err := second.m.Acquire(context.Background(), config.ModeSession, &bytes.Buffer{}); err != nil {
		t.Errorf("after the first copy ended: %v", err)
	}
}

func TestAcquireRefusesUnreadableJournal(t *testing.T) {
	r := newRig(nil)
	r.store.status = config.JournalUnreadable
	if _, _, err := r.m.Acquire(context.Background(), config.ModeSession, &bytes.Buffer{}); err == nil {
		t.Fatal("must fail")
	}
	if r.lock.held {
		t.Error("lock leaked")
	}
}

func TestCleanupRemovesDNSThenRoutes(t *testing.T) {
	r := newRig(nil)
	s, _ := acquire(t, r, config.ModeSession)
	st := sessionJournal(100, config.ModeSession)
	st.Owner = &config.Owner{PID: 100, Start: 5000, Boot: "boot-2"}
	st.Resolvers = append(st.Resolvers, testResolver("other.example"))
	if err := r.m.save(st); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Cleanup(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	log := r.b.calls()
	if !before(log, "dns ", "route ") {
		t.Errorf("order: %v", log)
	}
	if rep.Routes != 3 || rep.Resolvers != 2 || !rep.FullTunnel {
		t.Errorf("%+v", rep)
	}
	if d := rep.Describe(false); !strings.Contains(d, "full tunnel 0/1+128/1 removed") {
		t.Error(d)
	}
	if d := rep.Describe(true); !strings.Contains(d, "полный туннель 0/1+128/1 снят") {
		t.Error(d)
	}
	if got := r.store.state(); !got.Empty() || got.Owner != nil {
		t.Errorf("journal must be empty and ownerless: %+v", got)
	}
	if r.lock.held {
		t.Error("lock not released")
	}
}

func TestCleanupIsIdempotentAndSafeFromManyGoroutines(t *testing.T) {
	r := newRig(nil)
	s, _ := acquire(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: homeRoutes(), Sig: "x"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	reps := make([]Report, 8)
	for i := range reps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reps[i], _ = s.Cleanup(time.Second)
		}()
	}
	wg.Wait()
	for _, rep := range reps {
		if rep.Routes != 2 {
			t.Errorf("every caller gets the first result: %+v", rep)
		}
	}
	n := 0
	for _, l := range r.b.calls() {
		if strings.HasPrefix(l, "route ") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("routes were removed %d times: %v", n, r.b.calls())
	}
}

func TestCleanupKeepsFailedEntriesInJournal(t *testing.T) {
	r := newRig(nil)
	s, _ := acquire(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: append([]config.Route{corpRoute()}, homeRoutes()...), Sig: "x"}); err != nil {
		t.Fatal(err)
	}
	r.b.failRoute["10.10.0.0/16"] = errors.New("busy")
	rep, err := s.Cleanup(time.Second)
	if err == nil || !strings.Contains(err.Error(), "busy") || !strings.Contains(err.Error(), "next start") {
		t.Fatalf("err %v", err)
	}
	if rep.Routes != 2 {
		t.Errorf("%+v", rep)
	}
	st := r.store.state()
	if len(st.Routes) != 1 || st.Routes[0].Dest != "10.10.0.0/16" || st.Owner == nil || st.Mode != config.ModeSession {
		t.Errorf("the failed route must stay with its owner header: %+v", st)
	}
	if r.lock.held {
		t.Error("the lock must be released so that the next start can recover")
	}
	// the next start finishes the job
	delete(r.b.failRoute, "10.10.0.0/16")
	next := newRig(nil)
	next.store, next.lock = r.store, r.lock
	next.m = newManager(next.b, r.store, &fakeProcs{self: config.Owner{PID: 300, Boot: "boot-2"}, alive: map[int]int64{}}, r.lock.take)
	_, info, err := next.m.Acquire(context.Background(), config.ModeSession, &bytes.Buffer{})
	if err != nil || info.Recovered.Routes != 1 {
		t.Errorf("%+v %v", info, err)
	}
}

func TestCleanupRespectsDeadline(t *testing.T) {
	r := newRig(nil)
	s, _ := acquire(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: homeRoutes(), Sig: "x"}); err != nil {
		t.Fatal(err)
	}
	r.b.block = make(chan struct{})
	defer close(r.b.block)
	start := time.Now()
	rep, err := s.Cleanup(150 * time.Millisecond)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
	if err == nil || rep.Routes != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if st := r.store.state(); len(st.Routes) != 2 {
		t.Errorf("entries not reached must stay in the journal: %+v", st)
	}
}

// Cleanup does not wait forever for an Apply that is stuck: it ends within its budget.
func TestCleanupWaitsForOperationOnlyWithinBudget(t *testing.T) {
	r := newRig(nil)
	s, _ := acquire(t, r, config.ModeSession)
	if err := r.m.lockSem(r.m.ctx); err != nil { // an operation that never ends
		t.Fatal(err)
	}
	start := time.Now()
	_, err := s.Cleanup(100 * time.Millisecond)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("%v after %v", err, time.Since(start))
	}
	if !r.lock.held {
		t.Error("the lock must stay while an operation may still write: the OS drops it at exit")
	}
	if err := r.m.save(&config.State{Routes: homeRoutes()}); !errors.Is(err, errClosed) {
		t.Errorf("the abandoned operation must not write the journal: %v", err)
	}
}

func TestPersistentSessionLeavesEverything(t *testing.T) {
	r := newRig(nil)
	s, _ := acquire(t, r, config.ModePersistent)
	if err := r.m.save(&config.State{Routes: homeRoutes(), Sig: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Cleanup(time.Second); err != nil {
		t.Fatal(err)
	}
	st := r.store.state()
	if len(r.b.calls()) != 0 || len(st.Routes) != 2 || st.Mode != config.ModePersistent || st.Owner.PID != 100 {
		t.Errorf("%v %+v", r.b.calls(), st)
	}
	if r.lock.held {
		t.Error("lock not released")
	}
}

func TestResetRemovesAllAndClearsOwner(t *testing.T) {
	r := newRig(nil)
	acquire(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: homeRoutes(), Resolvers: []string{testResolver("corp.example")}, Sig: "x"}); err != nil {
		t.Fatal(err)
	}
	n, errs := r.m.Reset()
	if n != 3 || len(errs) != 0 {
		t.Fatalf("%d %v", n, errs)
	}
	if st := r.store.state(); !st.Empty() {
		t.Errorf("%+v", st)
	}
	if !before(r.b.calls(), "dns ", "route ") {
		t.Errorf("order %v", r.b.calls())
	}
}

// Invalid entries among valid ones never reach the OS and are reported;
// failed ones stay in the journal.
func TestResetWithInvalidAndFailingEntries(t *testing.T) {
	r := newRig(nil)
	acquire(t, r, config.ModeSession)
	st := &config.State{
		Routes: []config.Route{
			routeFor(""),
			{Dest: "10.0.0.0/8'; calc; '", Iface: "tun0"},
			{Dest: "172.16.0.0/12", Iface: "-D"},
			{Dest: "192.168.0.0/16", Iface: "Ethernet", Via: ViaCorp},
		},
		Resolvers: []string{"has space", "not-a-valid-entry\n"},
	}
	if err := r.m.save(st); err != nil {
		t.Fatal(err)
	}
	r.b.failRoute["192.168.0.0/16"] = errors.New("busy")
	// the memStore does not sanitize like the file does: these entries reach Reset as written
	n, errs := r.m.Reset()
	if n != 1 || len(errs) != 5 {
		t.Errorf("removed %d, errors: %v", n, errs)
	}
	for _, l := range r.b.calls() {
		if strings.Contains(l, "calc") || strings.Contains(l, "-D") || strings.Contains(l, "space") {
			t.Errorf("invalid entry reached the OS: %v", r.b.calls())
		}
	}
	if got := r.store.state(); len(got.Routes) != 3 || len(got.Resolvers) != 2 || got.Owner == nil {
		t.Errorf("kept in the journal: %+v", got)
	}
}

func TestResetReportsJournalSaveError(t *testing.T) {
	r := newRig(nil)
	acquire(t, r, config.ModeSession)
	if err := r.m.save(&config.State{Routes: []config.Route{routeFor("")}}); err != nil {
		t.Fatal(err)
	}
	r.store.saveErr = errors.New("disk full")
	n, errs := r.m.Reset()
	if n != 1 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "disk full") {
		t.Errorf("%d %v", n, errs)
	}
}

func TestResetEmptyJournalDropsHeaderOnly(t *testing.T) {
	r := newRig(nil)
	acquire(t, r, config.ModeSession)
	if n, errs := r.m.Reset(); n != 0 || len(errs) != 0 {
		t.Errorf("%d %v", n, errs)
	}
	if st := r.store.state(); st.Owner != nil || !st.Empty() {
		t.Errorf("the header of nothing must go: %+v", st)
	}
}
