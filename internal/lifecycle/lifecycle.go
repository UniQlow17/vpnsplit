// Package lifecycle holds what a long-running vpnsplit needs to end cleanly:
// the termination signals and goroutines that cannot take the process down.
package lifecycle

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
)

// How long removing everything applied may take when the program ends.
const (
	// GracefulBudget: the user quit on purpose (q, the Ctrl+C key, SIGINT in
	// a terminal). Nobody is forcing the process, so it may take its time,
	// with progress shown.
	GracefulBudget = 60 * time.Second
	// AbruptBudget: the OS is closing the program (a closed console window,
	// logoff, shutdown: SIGTERM/SIGHUP). Counted from the moment of the
	// signal, not from the start of the cleanup: Windows kills the process
	// about five seconds after it, and the menu needs its 500 ms grace and
	// the terminal restored first.
	AbruptBudget = 4500 * time.Millisecond
)

// CleanupDeadline is when the cleanup must be over. sig is the first signal
// the program got (nil: none, the user quit from the menu), at is the moment
// it arrived.
func CleanupDeadline(sig os.Signal, at, now time.Time) time.Time {
	if sig == nil || sig == os.Interrupt {
		return now.Add(GracefulBudget)
	}
	return at.Add(AbruptBudget)
}

// Notifier listens for SIGINT, SIGTERM and SIGHUP. It must be started before
// anything slow (taking over the journal after a crash, for one) so that a
// signal during it is not lost: the first signal cancels Context.
//
// On Windows the Go runtime turns closing the console window, logoff and
// shutdown into SIGTERM and holds the OS back until the process has handled
// it (or about five seconds have passed), so a program that listens for
// SIGTERM gets a short time to clean up and one that does not is killed at
// once. SIGHUP is never delivered there.
type Notifier struct {
	ctx    context.Context
	cancel context.CancelFunc
	stop   func()
	done   chan struct{}
	once   sync.Once

	mu       sync.Mutex
	sig      os.Signal
	at       time.Time
	onRepeat func(os.Signal)
}

// Notify starts listening for the termination signals.
func Notify() *Notifier {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	return newNotifier(ch, func() { signal.Stop(ch) })
}

func newNotifier(ch <-chan os.Signal, stop func()) *Notifier {
	ctx, cancel := context.WithCancel(context.Background())
	n := &Notifier{ctx: ctx, cancel: cancel, stop: stop, done: make(chan struct{})}
	go n.loop(ch)
	return n
}

func (n *Notifier) loop(ch <-chan os.Signal) {
	for {
		select {
		case s := <-ch:
			n.mu.Lock()
			first := n.sig == nil
			if first {
				n.sig, n.at = s, time.Now()
			}
			f := n.onRepeat
			n.mu.Unlock()
			if first {
				n.cancel()
			} else if f != nil {
				f(s)
			}
		case <-n.done:
			return
		}
	}
}

// Context ends with the first signal.
func (n *Notifier) Context() context.Context { return n.ctx }

// Signal is the first signal and when it arrived; ok is false if none has.
func (n *Notifier) Signal() (sig os.Signal, at time.Time, ok bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sig, n.at, n.sig != nil
}

// OnRepeat sets what happens on every signal after the first (a second
// Ctrl+C while the cleanup runs). f runs on the notifier's goroutine.
func (n *Notifier) OnRepeat(f func(os.Signal)) {
	n.mu.Lock()
	n.onRepeat = f
	n.mu.Unlock()
}

// Stop gives the signals back to the default handling. Context is left as it
// is: it ends by a signal only.
func (n *Notifier) Stop() {
	n.once.Do(func() {
		n.stop()
		close(n.done)
	})
}

// ForceExit ends the process at once with msg on stderr: for a second signal
// while the program is cleaning up and the user insists.
func ForceExit(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(130)
}

// SafeGo runs f in a goroutine. A panic in f does not crash the process
// before the program has cleaned up: it is passed to onPanic (with the stack
// in the message), or printed to stderr if onPanic is nil.
func SafeGo(f func(), onPanic func(error)) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				err := fmt.Errorf("panic in a goroutine: %v\n%s", r, debug.Stack())
				if onPanic != nil {
					onPanic(err)
					return
				}
				fmt.Fprintln(os.Stderr, err)
			}
		}()
		f()
	}()
}
