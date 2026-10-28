package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// How long Recover may take, and how many OS calls run at once while entries
// are removed (the system tools are slow to start, PowerShell especially).
const (
	recoverBudget = 60 * time.Second
	removeWorkers = 4
)

// ModeSessionAsk is a mode for Acquire (never written to the journal) for the
// interactive menu: a session, except that a persistent journal with entries
// (applied by apply/watch) is not taken over silently. The session then starts
// persistent for those entries (nothing is removed at exit) and Foreign says
// so, until TakeOver is called or the entries are gone.
const ModeSessionAsk = "session-ask"

var errNotOwner = errors.New("this copy of vpnsplit does not own the routes (see Acquire)")

var errClosed = errors.New("the session has ended: the journal is not written any more")

// BusyError means another running vpnsplit owns the routes. This copy may
// only look: it must neither apply nor remove anything.
type BusyError struct {
	Owner *config.Owner // from the journal, nil if unknown
	Mode  string
}

func (e *BusyError) Error() string {
	who := "another copy of vpnsplit"
	if e.Owner != nil {
		who = fmt.Sprintf("another copy of vpnsplit (PID %d)", e.Owner.PID)
	}
	return who + " is running and owns the routes: this copy can only view, close the other one first"
}

func (e *BusyError) Unwrap() error { return config.ErrLocked }

// Manager applies and removes routes and DNS entries and keeps the journal.
// Exactly one running process owns the journal (Acquire); the lock for it is
// held by the OS for as long as the process lives.
type Manager struct {
	b     Backend
	store Store
	procs Procs
	lock  LockFunc

	sem    chan struct{} // one operation at a time; unlike a mutex, can be waited for with a deadline
	ctx    context.Context
	cancel context.CancelFunc
	stamp  atomic.Pointer[config.State] // header written to every saved journal; nil until Acquire
	closed atomic.Bool                  // the session ended: nothing writes the journal any more
	force  bool                         // see SetForce

	mu      sync.Mutex
	mode    string // what Cleanup does: config.ModeSession or config.ModePersistent
	foreign bool   // persistent entries of apply/watch are waiting for TakeOver
}

// NewManager returns the Manager that works on this OS.
func NewManager() *Manager {
	return newManager(osBackend{}, fileStore{}, osProcs{}, osLock)
}

// NewManagerFor returns a Manager on the given parts (for tests of the
// callers; NewManager is the real one).
func NewManagerFor(b Backend, s Store, p Procs, l LockFunc) *Manager {
	return newManager(b, s, p, l)
}

func newManager(b Backend, s Store, p Procs, l LockFunc) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{b: b, store: s, procs: p, lock: l, sem: make(chan struct{}, 1), ctx: ctx, cancel: cancel}
}

// SetForce makes the recovery in Acquire distrust the "computer was restarted"
// verdict: routes of an earlier run are then removed instead of forgotten.
// For `reset --force`, when the boot id lied (a clock jump) and routes that
// should be gone are still in the table. Call it before Acquire.
func (m *Manager) SetForce(on bool) { m.force = on }

func (m *Manager) lockSem(ctx context.Context) error {
	select {
	case m.sem <- struct{}{}:
		return nil
	default:
	}
	select {
	case m.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) unlockSem() { <-m.sem }

// begin takes the right to run one operation; it fails once the session is
// being ended, even if the semaphore happens to be free.
func (m *Manager) begin() error {
	if err := m.lockSem(m.ctx); err != nil {
		return fmt.Errorf("interrupted: %w", err)
	}
	if err := m.ctx.Err(); err != nil {
		m.unlockSem()
		return fmt.Errorf("interrupted: %w", err)
	}
	return nil
}

func (m *Manager) requireOwner() error {
	if m.stamp.Load() == nil {
		return errNotOwner
	}
	return nil
}

// save writes the journal with the owner's header.
func (m *Manager) save(st *config.State) error {
	if m.closed.Load() {
		return errClosed
	}
	if h := m.stamp.Load(); h != nil {
		o := *h.Owner
		st.Version, st.Owner, st.Mode = h.Version, &o, h.Mode
	}
	return m.store.Save(st)
}

// saveBare writes the journal as it is (an empty one has no owner).
func (m *Manager) saveBare(st *config.State) error {
	if m.closed.Load() {
		return errClosed
	}
	return m.store.Save(st)
}

// Report says what was removed.
type Report struct {
	Routes, Resolvers int
	Forgotten         int  // journal routes dropped without removal: gone with a reboot
	FullTunnel        bool // 0.0.0.0/1 and 128.0.0.0/1 of the home VPN were removed
}

// Total is the number of entries removed.
func (r Report) Total() int { return r.Routes + r.Resolvers }

// Describe tells what was removed, in English or Russian.
func (r Report) Describe(ru bool) string {
	if r.Total() == 0 && r.Forgotten == 0 {
		if ru {
			return "ничего снимать не пришлось"
		}
		return "nothing to remove"
	}
	var s string
	if ru {
		s = fmt.Sprintf("снято: маршрутов %d, DNS-записей %d", r.Routes, r.Resolvers)
		if r.FullTunnel {
			s += "; полный туннель 0/1+128/1 снят"
		}
		if r.Forgotten > 0 {
			s += fmt.Sprintf("; после перезагрузки забыто маршрутов: %d", r.Forgotten)
		}
		return s
	}
	s = fmt.Sprintf("removed: %d routes, %d DNS entries", r.Routes, r.Resolvers)
	if r.FullTunnel {
		s += "; full tunnel 0/1+128/1 removed"
	}
	if r.Forgotten > 0 {
		s += fmt.Sprintf("; routes forgotten after a reboot: %d", r.Forgotten)
	}
	return s
}

// Notice is what the user must know after the full tunnel of the home VPN was
// removed, or "" when it was not.
func (r Report) Notice(ru bool) string {
	if !r.FullTunnel {
		return ""
	}
	if ru {
		return "Весь трафик теперь идёт напрямую через провайдера (мимо домашнего VPN), пока VPN-клиент сам не направит его в туннель."
	}
	return "All traffic now goes straight through your ISP (past the home VPN) until the VPN client routes it into the tunnel itself."
}

func (r *Report) add(o Report) {
	r.Routes += o.Routes
	r.Resolvers += o.Resolvers
	r.Forgotten += o.Forgotten
	r.FullTunnel = r.FullTunnel || o.FullTunnel
}

// AcquireInfo is what happened while the journal was taken over.
type AcquireInfo struct {
	Recovered Report
	Errors    []error  // entries of a dead owner that could not be removed; they stay in the journal
	Warns     []string // problems found while reading the journal
	TookOver  bool     // a persistent (apply/watch) journal with entries became a session's
	Foreign   bool     // ModeSessionAsk: such a journal was found and left alone, see TakeOver
}

// Acquire makes this process the owner of the journal, or fails. It takes
// the lock (a *BusyError if another copy runs), recovers what a dead owner
// left (see recover) and writes the header of this process. mode is
// config.ModeSession, config.ModePersistent or ModeSessionAsk.
//
// ctx ends the recovery early (a signal during the start): what was not
// removed stays in the journal, the lock is released and the error wraps
// ctx's. The recovery has a time limit of its own as well.
func (m *Manager) Acquire(ctx context.Context, mode string, w io.Writer) (*Session, AcquireInfo, error) {
	var info AcquireInfo
	if err := ctx.Err(); err != nil {
		return nil, info, fmt.Errorf("interrupted: %w", err)
	}
	release, err := m.lock()
	if err != nil {
		if errors.Is(err, config.ErrLocked) {
			return nil, info, m.busy()
		}
		return nil, info, fmt.Errorf("lock the journal: %w", err)
	}
	fail := func(err error) (*Session, AcquireInfo, error) {
		if rerr := release(); rerr != nil {
			err = fmt.Errorf("%w (and the lock was not released: %v)", err, rerr)
		}
		return nil, info, err
	}
	st, warns, status := m.store.Load()
	info.Warns = warns
	if err := statusErr(status); err != nil {
		return fail(err)
	}
	rctx, cancel := context.WithTimeout(ctx, recoverBudget)
	defer cancel()
	self := m.procs.Self()
	rep, errs := m.recover(rctx, st, self, w)
	info.Recovered, info.Errors = rep, errs
	if err := ctx.Err(); err != nil {
		// recover has saved what it managed to do
		return fail(fmt.Errorf("interrupted while finishing the previous run, the rest stays in the journal: %w", err))
	}

	leftover := !st.Empty() && (st.Mode == config.ModePersistent || st.Owner == nil)
	eff := mode
	switch mode {
	case config.ModeSession:
		info.TookOver = leftover
	case ModeSessionAsk:
		eff = config.ModeSession
		if leftover {
			eff, info.Foreign = config.ModePersistent, true
		}
	}
	// whatever a dead session could not remove stays a session's: the next
	// start removes it, whatever this run is
	hdrMode := eff
	if !st.Empty() && st.Mode == config.ModeSession {
		hdrMode = config.ModeSession
	}
	m.stamp.Store(&config.State{Version: config.JournalVersion, Owner: &self, Mode: hdrMode})
	m.mu.Lock()
	m.mode, m.foreign = eff, info.Foreign
	m.mu.Unlock()
	if err := m.save(st); err != nil {
		m.stamp.Store(nil)
		return fail(err)
	}
	return &Session{m: m, release: release}, info, nil
}

// busy builds the error for a lock held by somebody else.
func (m *Manager) busy() error {
	e := &BusyError{}
	if st, _, status := m.store.Load(); status == config.JournalOK {
		e.Owner, e.Mode = st.Owner, st.Mode
	}
	return e
}

func statusErr(s config.JournalStatus) error {
	switch s {
	case config.JournalDenied:
		return fmt.Errorf("the journal of routes is available to administrators only: %s", PrivHint)
	case config.JournalUnreadable:
		return errors.New("the journal of routes cannot be read, nothing was changed (see the warnings of `vpnsplit status`)")
	}
	return nil
}

// Mode is what Cleanup does with what was applied: config.ModeSession
// removes it, config.ModePersistent leaves it.
func (m *Manager) Mode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// Foreign reports whether persistent entries of apply/watch wait for TakeOver
// (see ModeSessionAsk). Nothing of them is removed at exit until then.
func (m *Manager) Foreign() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.foreign
}

// setMode changes what Cleanup does and the mode the next saved journal
// carries. A dead session's leftovers (see Acquire) keep their session
// header, so it is called only when the journal holds nothing of the kind.
func (m *Manager) setMode(mode string, stamp bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mode, m.foreign = mode, false
	if h := m.stamp.Load(); h != nil && stamp {
		c := *h
		c.Mode = mode
		m.stamp.Store(&c)
	}
}

// journalCleared is called after the journal was emptied: whatever it said
// before is gone, so the header follows the mode of this run. Entries of
// apply/watch that waited for TakeOver are gone too, and what is applied from
// now on is the session's.
func (m *Manager) journalCleared() {
	m.mu.Lock()
	mode := m.mode
	if m.foreign {
		mode = config.ModeSession
	}
	m.mu.Unlock()
	m.setMode(mode, true)
}

// TakeOver makes the persistent entries that were left alone the session's:
// they are removed when the session ends. It does nothing if there are none.
func (m *Manager) TakeOver() error {
	if err := m.requireOwner(); err != nil {
		return err
	}
	if err := m.begin(); err != nil {
		return err
	}
	defer m.unlockSem()
	if !m.Foreign() {
		return nil
	}
	st, _, status := m.store.Load()
	if err := statusErr(status); err != nil {
		return err
	}
	prevStamp, prevMode := m.stamp.Load(), m.Mode()
	m.setMode(config.ModeSession, true)
	if err := m.save(st); err != nil {
		m.stamp.Store(prevStamp)
		m.mu.Lock()
		m.mode, m.foreign = prevMode, true
		m.mu.Unlock()
		return fmt.Errorf("journal not updated: %w", err)
	}
	return nil
}

// recover deals with what an earlier owner left in the journal. It is called
// with the lock held, and the OS drops the lock when its holder dies, so that
// owner is dead whatever the process table says (a reused PID, a process we
// cannot look into). st is updated in place and saved when it changes.
//
//   - computer restarted since (boot id differs): routes are gone with the
//     reboot and are forgotten, never removed (the table may hold a route of a
//     VPN client to the same place); DNS entries survive a reboot and are
//     removed. With SetForce everything is removed instead;
//   - session journal: everything is removed, DNS first;
//   - persistent journal (and one written by an older version): left alone.
//
// Entries that could not be removed stay in the journal with their owner's
// header, which Acquire keeps for sessions.
func (m *Manager) recover(ctx context.Context, st *config.State, self config.Owner, w io.Writer) (Report, []error) {
	var rep Report
	if st.Empty() {
		return rep, nil
	}
	o := st.Owner
	if o != nil && !(o.PID == self.PID && o.Start == self.Start) && m.procs.AliveExact(*o) {
		fmt.Fprintf(w, "warning: a process with PID %d, the one named in the journal, is running, but the lock is free, so it does not own the routes (the PID was reused?): continuing\n", o.PID)
	}
	if o != nil && (o.Boot == "" || self.Boot == "") {
		fmt.Fprintln(w, "warning: the boot id is unknown, so it cannot be told whether the computer was restarted since the routes were applied: assuming it was not")
	}
	rebooted := o != nil && !m.force && !m.procs.SameBoot(o.Boot, self.Boot)
	switch {
	case rebooted:
		fmt.Fprintln(w, "the computer was restarted since the routes were applied: removing DNS entries, forgetting routes")
		dns := &config.State{Resolvers: st.Resolvers}
		r, keep, errs := m.removeEntries(ctx, dns, nil)
		rep.add(r)
		rep.Forgotten = len(st.Routes)
		st.Resolvers, st.Routes, st.Sig = keep.Resolvers, nil, ""
		if err := m.saveBare(st); err != nil {
			errs = append(errs, fmt.Errorf("journal not updated: %w", err))
		}
		return rep, errs
	case st.Mode == config.ModeSession:
		fmt.Fprintln(w, "the previous vpnsplit session did not clean up after itself, removing its routes and DNS entries")
		r, keep, errs := m.removeEntries(ctx, st, nil)
		rep.add(r)
		keep.Version, keep.Owner, keep.Mode = st.Version, st.Owner, st.Mode
		*st = *keep
		if len(errs) == 0 {
			*st = config.State{}
		}
		if err := m.saveBare(st); err != nil {
			errs = append(errs, fmt.Errorf("journal not updated: %w", err))
		}
		return rep, errs
	}
	return rep, nil
}

// removeEntries removes the DNS entries of st, then its routes, up to four
// calls at a time, and returns what stays in the journal: the entries that
// could not be removed or were not reached before ctx ended. Nothing is
// written. progress, if set, is told after every entry how many are done.
func (m *Manager) removeEntries(ctx context.Context, st *config.State, progress func(done, total int)) (Report, *config.State, []error) {
	var (
		rep   Report
		errs  []error
		keep  = &config.State{}
		pmu   sync.Mutex
		done  int
		total = len(st.Resolvers) + len(st.Routes)
	)
	step := func() {
		if progress == nil {
			return
		}
		pmu.Lock()
		defer pmu.Unlock()
		done++
		progress(done, total)
	}
	dnsErrs := runAll(ctx, st.Resolvers, removeWorkers, func(id string) error {
		defer step()
		if !config.ValidResolverEntry(id) {
			return fmt.Errorf("invalid DNS entry %q", id)
		}
		return m.b.DelResolver(id)
	})
	for i, id := range st.Resolvers {
		if err := dnsErrs[i]; err != nil {
			errs = append(errs, entryErr("DNS "+id, err))
			keep.Resolvers = append(keep.Resolvers, id)
			continue
		}
		rep.Resolvers++
	}
	routeErrs := runAll(ctx, st.Routes, removeWorkers, func(r config.Route) error {
		defer step()
		if err := config.ValidateRoute(r); err != nil {
			return err
		}
		return m.b.DelRoute(r)
	})
	gone := map[string]bool{}
	for i, r := range st.Routes {
		if err := routeErrs[i]; err != nil {
			errs = append(errs, entryErr("route "+r.Dest, err))
			keep.Routes = append(keep.Routes, r)
			continue
		}
		rep.Routes++
		if r.Via == ViaHome {
			gone[r.Dest] = true
		}
	}
	rep.FullTunnel = gone["0.0.0.0/1"] && gone["128.0.0.0/1"]
	if len(st.Resolvers) > 0 && ctx.Err() == nil {
		runAll(ctx, []struct{}{{}}, 1, func(struct{}) error { m.b.FlushDNS(); return nil })
	}
	return rep, keep, errs
}

// entryErr names the entry when the error says only that time ran out.
func entryErr(what string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: not removed in time: %w", what, err)
	}
	return err
}

// runAll calls fn for every item, up to workers at a time, and returns the
// error of each. When ctx ends, calls still running are abandoned (they may
// finish later; their result is dropped) and items not started get ctx's
// error: the caller then treats them as not removed. A call that has finished
// by then counts as done. A panic in fn is an error.
func runAll[T any](ctx context.Context, items []T, workers int, fn func(T) error) []error {
	errs := make([]error, len(items))
	if len(items) == 0 {
		return errs
	}
	started := make([]bool, len(items))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(workers, len(items)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				started[i] = true
				done := make(chan error, 1)
				go func() {
					defer func() {
						if r := recover(); r != nil {
							done <- fmt.Errorf("internal error: %v", r)
						}
					}()
					done <- fn(items[i])
				}()
				select {
				case errs[i] = <-done:
				case <-ctx.Done():
					select { // both may be ready: a finished call is not "not removed"
					case errs[i] = <-done:
					default:
						errs[i] = ctx.Err()
					}
				}
			}
		}()
	}
feed:
	for i := range items {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	for i := range items {
		if !started[i] && errs[i] == nil {
			errs[i] = ctx.Err()
		}
	}
	return errs
}

// Reset removes every route and DNS entry recorded in the journal. Entries
// that could not be removed stay in the journal for the next try. It needs no
// config, so it works even if config.json is broken or missing.
func (m *Manager) Reset() (removed int, errs []error) {
	rep, errs := m.ResetReport()
	return rep.Total(), errs
}

// ResetReport is Reset that says what was removed.
func (m *Manager) ResetReport() (Report, []error) {
	if err := m.requireOwner(); err != nil {
		return Report{}, []error{err}
	}
	if err := m.begin(); err != nil {
		return Report{}, []error{err}
	}
	defer m.unlockSem()
	return m.resetLocked(m.ctx)
}

func (m *Manager) resetLocked(ctx context.Context) (Report, []error) {
	st, _, status := m.store.Load()
	if err := statusErr(status); err != nil {
		return Report{}, []error{err}
	}
	if st.Empty() {
		if st.Owner != nil { // only the header of a finished run: nobody owns anything now
			if err := m.saveBare(&config.State{}); err != nil {
				return Report{}, []error{fmt.Errorf("journal not updated: %w", err)}
			}
		}
		m.journalCleared()
		return Report{}, nil
	}
	rep, keep, errs := m.removeEntries(ctx, st, nil)
	var err error
	if len(errs) == 0 {
		err = m.saveBare(&config.State{}) // nothing is applied: no owner to record
		if err == nil {
			m.journalCleared()
		}
	} else {
		err = m.save(keep)
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("journal not updated, entries removed above may be listed again: %w", err))
	}
	return rep, errs
}

// Session is the ownership of the journal by this process.
type Session struct {
	m       *Manager
	release func() error

	once sync.Once
	rep  Report
	err  error
}

// Abort stops an Apply in flight (it returns an "interrupted" error) and
// makes later ones fail; used when the program is told to exit.
func (s *Session) Abort() { s.m.cancel() }

// OwnerRunning reports whether the process that wrote the journal header is
// still running (for display; the lock is what decides).
func OwnerRunning(o config.Owner) bool { return osProcs{}.Alive(o) }

// Mode is config.ModeSession or config.ModePersistent: what Cleanup does.
func (s *Session) Mode() string { return s.m.Mode() }

// Foreign reports whether persistent entries of apply/watch are waiting for
// TakeOver (see ModeSessionAsk).
func (s *Session) Foreign() bool { return s.m.Foreign() }

// TakeOver makes them the session's: removed when it ends.
func (s *Session) TakeOver() error { return s.m.TakeOver() }

// Cleanup is CleanupUntil with a time limit counted from now.
func (s *Session) Cleanup(budget time.Duration) (Report, error) {
	return s.CleanupUntil(time.Now().Add(budget), nil)
}

// CleanupUntil ends the session, once, however often and from wherever it is
// called (later calls return the first result). For a session journal it
// removes everything applied, DNS first and then routes, before deadline;
// whatever is not removed stays in the journal and the next start removes it
// (see Acquire), which the returned error says. progress, if set, is told
// after every removed entry. A persistent session leaves what it applied.
// The lock is released, except when an operation did not stop before the
// deadline: it may still be writing the journal, so nothing is written and
// the lock stays until the OS drops it at the exit of the process. A panic
// becomes the error.
func (s *Session) CleanupUntil(deadline time.Time, progress func(done, total int)) (Report, error) {
	s.once.Do(func() {
		abandoned := false
		defer func() {
			if r := recover(); r != nil {
				s.err = errors.Join(s.err, fmt.Errorf("internal error during the cleanup: %v\n%s", r, debug.Stack()))
			}
			s.m.closed.Store(true)
			if abandoned {
				return
			}
			if err := s.release(); err != nil {
				s.err = errors.Join(s.err, fmt.Errorf("release the lock: %w", err))
			}
		}()
		s.m.cancel() // stops an Apply in flight
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		if err := s.m.lockSem(ctx); err != nil {
			abandoned = true
			s.m.closed.Store(true)
			s.err = fmt.Errorf("an operation did not stop in time, the journal is left for the next start: %w", err)
			return
		}
		defer s.m.unlockSem()
		if s.m.Mode() != config.ModeSession {
			return
		}
		s.rep, s.err = s.m.cleanupLocked(ctx, progress)
	})
	return s.rep, s.err
}

func (m *Manager) cleanupLocked(ctx context.Context, progress func(done, total int)) (Report, error) {
	st, _, status := m.store.Load()
	if err := statusErr(status); err != nil {
		return Report{}, err
	}
	if st.Empty() && st.Owner == nil {
		return Report{}, nil
	}
	rep, keep, errs := m.removeEntries(ctx, st, progress)
	var serr error
	if len(errs) == 0 {
		serr = m.saveBare(&config.State{})
	} else {
		serr = m.save(keep)
	}
	if serr != nil {
		errs = append(errs, fmt.Errorf("journal not updated: %w", serr))
	}
	if len(errs) > 0 {
		return rep, fmt.Errorf("%d entries were not removed, the journal keeps them for the next start: %w", len(errs), errors.Join(errs...))
	}
	return rep, nil
}
