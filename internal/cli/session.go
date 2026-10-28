package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/lifecycle"
	"github.com/UniQlow17/vpnsplit/internal/router"
)

// acquire makes this process the owner of the journal: the previous owner's
// leftovers are dealt with first (ctx ends that early). The Session must be
// ended with end.
func acquire(ctx context.Context, mgr *router.Manager, mode string, out io.Writer) (*router.Session, error) {
	sess, info, err := mgr.Acquire(ctx, mode, out)
	printWarningsTo(out, info.Warns)
	// an old-format journal that is still where it was: say that and why
	if n := config.LegacyNote(false); n != "" {
		printWarningsTo(out, []string{n})
	}
	if err != nil {
		return nil, err
	}
	if info.Recovered.Total()+info.Recovered.Forgotten > 0 {
		fmt.Fprintln(out, "recovered after an earlier run:", info.Recovered.Describe(false))
	}
	if n := info.Recovered.Notice(false); n != "" {
		fmt.Fprintln(out, n)
	}
	for _, e := range info.Errors {
		fmt.Fprintln(os.Stderr, "  !", e)
	}
	if info.Baseline != nil {
		if s := info.Baseline.Describe(false); s != "" {
			fmt.Fprintln(out, "state before the earlier run:", s)
		}
	}
	if info.TookOver {
		fmt.Fprintln(out, "took over the routes of the journal that had no owner (apply/watch or an older version): they are removed when this run ends")
	}
	return sess, nil
}

func printWarningsTo(w io.Writer, warns []string) {
	for _, s := range warns {
		fmt.Fprintln(w, "warning:", s)
	}
}

// endInfo says until when the cleanup may take and what is written down.
type endInfo struct {
	deadline time.Time
	reason   string
	saveLast func(string) error // may be nil
}

// endFor is how a session that was told to stop by n (nil: no signals are
// watched, the command ended by itself) is ended: a user who stopped it with
// Ctrl+C gets a minute; a closed window or SIGTERM gets what is left of
// ~4.5 s after the signal.
func endFor(n *lifecycle.Notifier) endInfo {
	if n == nil {
		return endInfo{deadline: lifecycle.CleanupDeadline(nil, time.Time{}, time.Now()), reason: "finished", saveLast: config.WriteLastSession}
	}
	sig, at, ok := n.Signal()
	if !ok {
		return endInfo{deadline: lifecycle.CleanupDeadline(nil, time.Time{}, time.Now()), reason: "finished", saveLast: config.WriteLastSession}
	}
	return endInfo{deadline: lifecycle.CleanupDeadline(sig, at, time.Now()), reason: "signal " + sig.String(), saveLast: config.WriteLastSession}
}

// end ends the session (removing everything for a session journal) and
// reports it; a failure is loud, because routes are left behind. It sets
// *errp when there was no error yet. info is called when the session ends (the
// deadline depends on when the signal came). It must be deferred directly (it
// recovers a panic of the command, still cleaning up).
func end(sess *router.Session, info func() endInfo, errp *error, out io.Writer) {
	if r := recover(); r != nil {
		if *errp == nil {
			*errp = fmt.Errorf("internal error: %v\n%s", r, debug.Stack())
		}
	}
	endWith(sess, info(), errp, out)
}

func endWith(sess *router.Session, ei endInfo, errp *error, out io.Writer) {
	progress := func(done, total int) { fmt.Fprintf(out, "removing: %d of %d\n", done, total) }
	rep, err := sess.CleanupUntil(ei.deadline, progress)
	session := sess.Mode() == config.ModeSession
	var summary string
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n!!! vpnsplit could not remove everything it applied: %v\n!!! The journal keeps the rest: the next start of vpnsplit with admin rights (or `vpnsplit reset`) removes it.\n", err)
		summary = "NOT everything was removed, the rest is in the journal (the next start finishes it)"
		if *errp == nil {
			*errp = errors.New("cleanup incomplete")
		}
	} else if session {
		summary = rep.Describe(false)
		fmt.Fprintln(out, "session ended,", summary)
		if rep.Base != nil {
			if s := rep.Base.Describe(false); s != "" {
				fmt.Fprintln(out, s)
				summary += ". " + s
			}
		}
	}
	if n := rep.Notice(false); n != "" {
		fmt.Fprintln(out, n)
	}
	if session && ei.saveLast != nil {
		text := time.Now().Format("2006-01-02 15:04:05") + " (" + ei.reason + "): " + summary
		if rep.FullTunnel {
			text += ". All traffic went straight through the ISP, past the home VPN, until the VPN client routed it into the tunnel itself"
		}
		if werr := ei.saveLast(text); werr != nil {
			fmt.Fprintln(os.Stderr, "warning: the outcome of the session was not recorded:", werr)
		}
	}
}

// noSignal is the end of a command that does not watch signals.
func noSignal() endInfo { return endFor(nil) }

func cmdApply() (err error) {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	mgr := router.NewManager()
	sess, err := acquire(context.Background(), mgr, config.ModePersistent, os.Stdout)
	if err != nil {
		return err
	}
	defer end(sess, noSignal, &err, os.Stdout)
	mgr.SetOneShot() // nothing watches what apply leaves: no DNS rule for everything else
	return mgr.Apply(cfg, os.Stdout)
}

// resetOpts are the flags of `reset`.
type resetOpts struct {
	purge bool // also delete the user's config.json
	force bool // do not assume that routes vanished with a reboot: remove everything listed
	// removeConfig deletes config.json; config.Remove if nil
	removeConfig func() error
}

func cmdReset(mgr *router.Manager, o resetOpts, out io.Writer) (err error) {
	mgr.SetForce(o.force)
	mgr.NoSnapshot() // reset takes nothing new on; it compares with the snapshot of the run it undoes
	sess, err := acquire(context.Background(), mgr, config.ModePersistent, out)
	if err != nil {
		return err
	}
	defer end(sess, noSignal, &err, out)
	rep, errs := mgr.ResetReport()
	fmt.Fprintf(out, "removed %d routes and DNS entries\n", rep.Total())
	if n := rep.Notice(false); n != "" {
		fmt.Fprintln(out, n)
	}
	for _, e := range errs {
		fmt.Fprintln(out, "  !", e)
	}
	if o.purge {
		remove := o.removeConfig
		if remove == nil {
			remove = config.Remove
		}
		switch rerr := remove(); {
		case rerr == nil:
			fmt.Fprintln(out, "config deleted")
		case !errors.Is(rerr, os.ErrNotExist):
			fmt.Fprintln(out, "  ! config not deleted:", rerr)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d entries could not be removed; journal kept, run reset again (`reset --force` if the routes should be gone with a reboot but are still in the table)", len(errs))
	}
	if b := sess.Settle(time.Now().Add(resetCompareBudget)); b != nil {
		if b.Checked && !b.Restored() {
			for _, l := range b.Lines(false) {
				fmt.Fprintln(out, " ", l)
			}
		}
		if s := b.Describe(false); s != "" {
			fmt.Fprintln(out, s)
		}
	}
	fmt.Fprintln(out, "routing is back to what your VPN clients and OS set up. Reconnect the VPNs if something still looks off.")
	return nil
}

// How often cmdSync looks at the adapters and the routing table, and how soon
// after a restoration of missing routes it may try that again.
const (
	syncInterval = 2 * time.Second
	driftRetry   = 10 * time.Second
)

// cmdSync keeps routes in line with what is connected, until a signal. In
// the persistent mode (watch) they stay afterwards; in the session mode
// (run) everything is removed.
func cmdSync(mode string) (err error) {
	if _, err := loadConfig(); err != nil {
		return err
	}
	// listening starts before the (possibly slow) recovery of an earlier
	// run, so that a signal during it is not lost
	n := lifecycle.Notify()
	defer n.Stop()
	n.OnRepeat(func(os.Signal) {
		lifecycle.ForceExit("\nsecond signal: exiting without waiting. The journal keeps what is not removed yet: the next start of vpnsplit with admin rights (or `vpnsplit reset`) finishes it.")
	})
	mgr := router.NewManager()
	sess, err := acquire(n.Context(), mgr, mode, os.Stdout)
	if err != nil {
		if n.Context().Err() != nil {
			fmt.Println("interrupted while starting; what was not removed after the earlier run stays in the journal and is removed by the next start")
			return nil
		}
		return err
	}
	defer end(sess, func() endInfo { return endFor(n) }, &err, os.Stdout)

	ctx := n.Context()
	finished := make(chan struct{})
	defer close(finished)
	lifecycle.SafeGo(func() {
		select {
		case <-ctx.Done():
			sess.Abort() // an apply in flight stops
		case <-finished:
		}
	}, func(e error) { fmt.Fprintln(os.Stderr, e); sess.Abort() })
	if mode == config.ModeSession {
		fmt.Println("session started (Ctrl+C or SIGTERM to stop: everything applied is removed)...")
	} else {
		fmt.Println("watching (Ctrl+C to stop; run `vpnsplit reset` to clean up)...")
	}
	stopping := func() error {
		sig, _, _ := n.Signal()
		fmt.Println("\n"+time.Now().Format("15:04:05"), "got", sig, "- stopping")
		return nil
	}
	var lastDrift time.Time
	for {
		if ctx.Err() != nil {
			return stopping()
		}
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		e := router.Detect(cfg)
		st := config.LoadState()
		apply, reset := router.Sync(cfg, e, st)
		drift := false
		// a VPN that reconnected took its routes along: they are missing from the
		// table although nothing in the configuration changed. Reading the table
		// is cheap; a retry is not made more often than every driftRetry.
		if !apply && !reset && time.Since(lastDrift) >= driftRetry && router.Drifted(st) {
			apply, drift, lastDrift = true, true, time.Now()
		}
		switch {
		case apply:
			if drift {
				fmt.Println(time.Now().Format("15:04:05"), "routes are missing from the table, restoring")
			} else {
				fmt.Println(time.Now().Format("15:04:05"), "VPNs or rules changed, applying")
			}
			if err := mgr.Apply(cfg, os.Stdout); err != nil && ctx.Err() == nil {
				fmt.Println("  !", err)
			}
		case reset:
			fmt.Println(time.Now().Format("15:04:05"), "no VPN connected, removing routes")
			mgr.Reset()
		}
		select {
		case <-ctx.Done():
			return stopping()
		case <-time.After(syncInterval):
		}
	}
}

// resetCompareBudget is how long `reset` may take to compare the system with the
// state before the start, after it has removed what the journal listed.
const resetCompareBudget = 30 * time.Second

// cmdDiff shows how the system differs from the state before vpnsplit started:
// what is new (and whose it is: ours is removed at the end of a session,
// everything else belongs to a VPN client or the OS and stays) and what is gone.
func cmdDiff(out io.Writer) error {
	b := router.Diff(context.Background(), true)
	if !b.Checked {
		fmt.Fprintln(out, "no comparison:", b.Note)
		if !router.IsPrivileged() {
			fmt.Fprintf(out, "the snapshot is kept in the protected directory: %s\n", router.PrivHint)
		}
		return nil
	}
	for _, l := range b.Lines(false) {
		fmt.Fprintln(out, l)
	}
	fmt.Fprintln(out, b.Describe(false))
	return nil
}

// printOwner tells who applied what the journal lists and what happens to it.
func printOwner(w io.Writer, st *config.State) {
	if st.Empty() {
		return
	}
	o := st.Owner
	switch {
	case o == nil:
		fmt.Fprintln(w, "applied by: an older version of vpnsplit; stays until `vpnsplit reset`")
	case st.Mode == config.ModeSession && router.OwnerRunning(*o):
		fmt.Fprintf(w, "applied by: a running vpnsplit session (PID %d); removed when it ends\n", o.PID)
	case st.Mode == config.ModeSession:
		fmt.Fprintf(w, "applied by: a vpnsplit session (PID %d) that is not running any more; it did not clean up, the next start of vpnsplit with admin rights removes it (or `vpnsplit reset`)\n", o.PID)
		if len(st.Resolvers) > 0 {
			fmt.Fprintln(w, "WARNING: DNS rules of the previous session are still in place (they survive a reboot and redirect the DNS queries of their domains): start vpnsplit with administrator rights to clean them up")
		}
	case router.OwnerRunning(*o):
		fmt.Fprintf(w, "applied by: vpnsplit apply/watch (PID %d, running); stays until `vpnsplit reset`\n", o.PID)
	default:
		fmt.Fprintln(w, "applied by: vpnsplit apply/watch; stays until `vpnsplit reset`")
	}
}

// printLastSession shows how the last session ended, if it was recorded.
func printLastSession(w io.Writer) {
	if s := config.ReadLastSession(); s != "" {
		fmt.Fprintln(w, "last session:", s)
	}
}
