package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/autorecover"
	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/lifecycle"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/tui"
)

// cmdRecover finishes what a run that did not clean up after itself left: it
// takes the journal (so it fails while another copy is running), removes what a
// dead session of vpnsplit applied (DNS entries, rules, routes, settings of the
// IPv6 tunnels), compares the system with the state before that run and exits.
// It applies nothing. Routes of apply/watch are not a dead session's and stay
// (`vpnsplit reset` removes them). It is what the job installed by
// `install-recover` runs at the start of the computer.
func cmdRecover(out io.Writer) (err error) {
	n := lifecycle.Notify()
	defer n.Stop()
	n.OnRepeat(func(os.Signal) {
		lifecycle.ForceExit("\nsecond signal: exiting without waiting. The journal keeps what is not removed yet: the next start of vpnsplit with admin rights (or `vpnsplit recover`) finishes it.")
	})
	return recoverWith(n.Context(), router.NewManager(), out)
}

// recoverWith is cmdRecover on a given manager and context.
func recoverWith(ctx context.Context, mgr *router.Manager, out io.Writer) (err error) {
	mgr.NoSnapshot() // nothing new is taken on; the snapshot of the run being recovered is compared with
	sess, info, err := acquireInfo(ctx, mgr, config.ModePersistent, out)
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(out, "interrupted while recovering; what was not removed stays in the journal and is removed by the next start or `vpnsplit recover`")
			return nil
		}
		return err
	}
	defer end(sess, noSignal, &err, out)

	failed := len(info.Errors)
	// the entries are gone: now whatever else of ours changed since that run started
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
	st, status, jerr := sess.Journal()
	if jerr != nil {
		fmt.Fprintln(out, "the journal is busy, its state is not shown; run `vpnsplit recover` again to check")
		if failed > 0 {
			return fmt.Errorf("%d entries of the earlier run could not be removed", failed)
		}
		return jerr
	}
	if r := info.Recovered; r.Total()+r.Forgotten == 0 && failed == 0 && status == config.JournalOK && st.Empty() {
		fmt.Fprintln(out, "nothing to recover: no earlier run left routes or DNS entries")
	}
	if status == config.JournalOK && !st.Empty() {
		if failed > 0 {
			fmt.Fprintf(out, "%d entries could not be removed and stay in the journal: run `vpnsplit recover` again, or `vpnsplit reset`\n", len(st.Routes)+len(st.Rules)+len(st.Resolvers))
		} else {
			fmt.Fprintf(out, "left in place: %d routes and DNS entries of `vpnsplit apply`/`watch` (not a crashed session's); `vpnsplit reset` removes them\n", len(st.Routes)+len(st.Resolvers))
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d entries of the earlier run could not be removed", failed)
	}
	return nil
}

// cmdInstallRecover installs (or with --remove deletes) the job that runs
// `vpnsplit recover` at the start of the computer. It is never done by anything
// else.
func cmdInstallRecover(args []string, out io.Writer) error {
	remove := false
	for _, a := range args {
		switch a {
		case "--remove":
			remove = true
		default:
			return fmt.Errorf("usage: vpnsplit install-recover [--remove] (unknown argument %q)", a)
		}
	}
	if remove {
		return autorecover.Remove(out)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot tell where vpnsplit is: %w", err)
	}
	if err := autorecover.Install(exe, out); err != nil {
		if errors.Is(err, autorecover.ErrNotOurs) {
			return fmt.Errorf("%w (remove it by hand first)", err)
		}
		return err
	}
	return nil
}

// parseMenu reads the flags of the menu.
func parseMenu(args []string) (tui.Options, error) {
	var o tui.Options
	for _, a := range args {
		switch a {
		case "--no-tray":
			o.NoTray = true
		case "--no-resize":
			o.NoResize = true
		default:
			return o, fmt.Errorf("usage: vpnsplit [menu] [--no-resize] [--no-tray] (unknown argument %q)", a)
		}
	}
	return o, nil
}
