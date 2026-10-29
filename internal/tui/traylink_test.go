package tui

import (
	"syscall"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/UniQlow17/vpnsplit/internal/lifecycle"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/tray"
)

// fakeTray records what the icon is told; it never touches the desktop.
type fakeTray struct {
	states []tray.State
	closed int
}

func (f *fakeTray) Update(s tray.State) { f.states = append(f.states, s) }
func (f *fakeTray) Close()              { f.closed++ }

func TestTrayStateFollowsModel(t *testing.T) {
	m := testModel()
	if s := m.trayState(false); s.On || s.Danger {
		t.Errorf("%+v", s)
	}
	m.on = true
	m.diags = []router.Diag{{Code: "PROXY_ON", Level: router.DiagWarn}}
	if s := m.trayState(true); !s.On || s.Danger || !s.CanHide {
		t.Errorf("a warning is not danger: %+v", s)
	}
	m.diags = append(m.diags, router.Diag{Code: "GPO_NRPT", Level: router.DiagDanger})
	if s := m.trayState(false); !s.Danger || s.Code != "GPO_NRPT" || s.Icon() != tray.IconDanger {
		t.Errorf("%+v", s)
	}
}

// The icon is told only when the state changes, and a model without an icon works as before.
func TestTrayPushOnlyOnChange(t *testing.T) {
	f := &fakeTray{}
	l := &trayLink{t: f}
	m := testModel()
	l.push(m)
	l.push(m)
	m.on = true
	l.push(m)
	if len(f.states) != 2 || !f.states[1].On {
		t.Errorf("%+v", f.states)
	}
	var none *trayLink
	none.push(m)
	(&trayLink{}).push(m)
	if none.canHideNow() || (&trayLink{canHide: true}).canHideNow() {
		t.Error("no icon, no hiding")
	}
}

// Update pushes the state the step leaves behind.
func TestUpdateFeedsTheIcon(t *testing.T) {
	f := &fakeTray{}
	m := testModel()
	m.tr = &trayLink{t: f}
	m.on = true
	next, _ := m.Update(tickMsg(time.Now()))
	_ = next
	if len(f.states) != 1 || !f.states[0].On {
		t.Errorf("%+v", f.states)
	}
}

// "Разделение" from the icon is the same switch as the menu item, and it waits
// while the user is typing or answering.
func TestTrayToggleMessage(t *testing.T) {
	m := testModel() // no rights: toggleSplit refuses with a note, as the key does
	next, _ := m.Update(trayToggleMsg{})
	if got := next.(model).flash; got == "" {
		t.Error("the same refusal as the key must show")
	}
	m = testModel()
	m.inputting = true
	next, _ = m.Update(trayToggleMsg{})
	m2 := next.(model)
	if m2.on || m2.flash == "" {
		t.Errorf("typing: on=%v flash=%q", m2.on, m2.flash)
	}
	for sc, want := range map[screen]bool{scMenu: true, scAdvanced: true, scHelp: true, scDiag: true, scResult: true, scBusy: false, scConfirm: false, scPick: false, scRules: false} {
		m := testModel()
		m.sc = sc
		if m.trayToggleOK() != want {
			t.Errorf("screen %d: %v", sc, !want)
		}
	}
}

func TestKeyMHidesOnlyWithIcon(t *testing.T) {
	m := testModel()
	if m.keysHint() != menuHint {
		t.Error("no icon: the hint is as before")
	}
	m.tr = &trayLink{t: &fakeTray{}, canHide: true}
	if m.keysHint() == menuHint {
		t.Error("the key m must be in the hint")
	}
	// without the console to hide (tests, other systems) the key does nothing
	m2 := testModel()
	next, cmd := m2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	if cmd != nil || next.(model).sc != scMenu {
		t.Error("m is not a key without the icon")
	}
}

func TestTrayNoteIsFlashed(t *testing.T) {
	next, _ := testModel().Update(trayNoteMsg{text: "нет значка"})
	if next.(model).flash != "нет значка" {
		t.Errorf("%q", next.(model).flash)
	}
}

// The end of the session takes the road of the signal and waits for the
// cleanup, but never longer than the budget counted from the signal.
func TestEndSessionWaitsForCleanup(t *testing.T) {
	n := lifecycle.Notify()
	defer n.Stop()
	cleaned := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(cleaned)
	}()
	start := time.Now()
	endSession(n, cleaned, start)
	if d := time.Since(start); d < 90*time.Millisecond || d > 3*time.Second {
		t.Errorf("waited %v", d)
	}
	if s, _, ok := n.Signal(); !ok || s != syscall.SIGTERM {
		t.Error("the end of the session is a SIGTERM for the program")
	}
	select {
	case <-n.Context().Done():
	default:
		t.Error("the context must be cancelled")
	}
}

func TestEndSessionBudgetIsFromTheFirstSignal(t *testing.T) {
	n := lifecycle.Notify()
	defer n.Stop()
	n.Inject(syscall.SIGTERM)
	_, at, _ := n.Signal()
	late := at.Add(lifecycle.AbruptBudget + time.Second) // the budget is spent already
	start := time.Now()
	endSession(n, make(chan struct{}), late)
	if time.Since(start) > time.Second {
		t.Error("a spent budget must not be waited for")
	}
}

func TestTrayHandleStopIsIdempotent(t *testing.T) {
	f := &fakeTray{}
	h := &trayHandle{link: &trayLink{t: f}, done: make(chan struct{})}
	h.stop()
	h.stop()
	h.wait(time.Second)
	if f.closed != 1 {
		t.Errorf("closed %d times", f.closed)
	}
	var none *trayHandle
	none.stop()
	none.wait(time.Millisecond)
}
