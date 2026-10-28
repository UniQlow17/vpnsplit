package lifecycle

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSafeGoReportsPanic(t *testing.T) {
	got := make(chan error, 1)
	SafeGo(func() { panic("boom") }, func(err error) { got <- err })
	select {
	case err := <-got:
		if !strings.Contains(err.Error(), "boom") {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("panic not reported")
	}
}

func TestSafeGoRunsFunction(t *testing.T) {
	done := make(chan struct{})
	SafeGo(func() { close(done) }, nil)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not run")
	}
}

func TestCleanupDeadlineByReason(t *testing.T) {
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	now := at.Add(700 * time.Millisecond)
	if d := CleanupDeadline(nil, time.Time{}, now); d != now.Add(GracefulBudget) {
		t.Errorf("quit from the menu: %v", d)
	}
	if d := CleanupDeadline(os.Interrupt, at, now); d != now.Add(GracefulBudget) {
		t.Errorf("SIGINT: %v", d)
	}
	for _, s := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		if d := CleanupDeadline(s, at, now); d != at.Add(AbruptBudget) {
			t.Errorf("%v must count from the signal: %v", s, d)
		}
	}
	if AbruptBudget >= 5*time.Second {
		t.Error("the abrupt budget must fit the ~5 s Windows gives a closed window")
	}
}

func TestNotifierFirstSignalCancelsSecondRepeats(t *testing.T) {
	ch := make(chan os.Signal, 4)
	n := newNotifier(ch, func() {})
	defer n.Stop()
	if _, _, ok := n.Signal(); ok {
		t.Fatal("no signal yet")
	}
	repeat := make(chan os.Signal, 1)
	n.OnRepeat(func(s os.Signal) { repeat <- s })
	ch <- syscall.SIGTERM
	select {
	case <-n.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the first signal must cancel the context")
	}
	sig, at, ok := n.Signal()
	if !ok || sig != syscall.SIGTERM || time.Since(at) > 5*time.Second {
		t.Errorf("%v %v %v", sig, at, ok)
	}
	select {
	case <-repeat:
		t.Fatal("the first signal is not a repeat")
	default:
	}
	ch <- os.Interrupt
	select {
	case s := <-repeat:
		if s != os.Interrupt {
			t.Errorf("%v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second signal must reach OnRepeat")
	}
	if s, _, _ := n.Signal(); s != syscall.SIGTERM {
		t.Error("the first signal stays the reason")
	}
}
