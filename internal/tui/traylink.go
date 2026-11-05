package tui

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/UniQlow17/vpnsplit/internal/lifecycle"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/tray"
)

// The icon in the notification area is a view of the menu and a second place
// to press its keys: it keeps no state of its own, and what it asks for goes
// to the program as a message that the keys also lead to (the switch ->
// toggleSplit, the exit -> tea.QuitMsg, which "q" and Ctrl+C produce too). The
// exit is the one path of Run: finish, then the icon is removed.

// trayToggleMsg is "Разделение ВКЛ/ВЫКЛ" chosen in the menu of the icon.
type trayToggleMsg struct{}

// trayLink joins the model to the icon. The model is copied at every step, so
// the link is a pointer; it is filled in before the program starts running and
// stays as it is. A nil link is no tray.
type trayLink struct {
	t       tray.Tray
	canHide bool // the console window can be hidden into the tray (key "m")

	mu   sync.Mutex
	last tray.State
	have bool
}

// ready: there is an icon.
func (l *trayLink) ready() bool { return l != nil && l.t != nil }

// canHideNow: the key "m" may hide the window.
func (l *trayLink) canHideNow() bool { return l.ready() && l.canHide }

// push shows the state of the model on the icon when it differs from the last one.
func (l *trayLink) push(m model) {
	if !l.ready() {
		return
	}
	s := m.trayState(l.canHide)
	l.mu.Lock()
	same := l.have && l.last == s
	l.last, l.have = s, true
	l.mu.Unlock()
	if !same {
		l.t.Update(s)
	}
}

// trayState is what the icon shows for the model.
func (m model) trayState(canHide bool) tray.State {
	s := tray.State{On: m.on, CanHide: canHide, Hidden: tray.ConsoleHidden()}
	for _, d := range m.diags {
		if d.Level == router.DiagDanger {
			s.Danger, s.Code = true, d.Code
			break
		}
	}
	return s
}

// trayToggleOK: a menu of the icon may flip the switch now. Not while the user
// types, answers a question or a step runs: the same screens the key works on.
func (m model) trayToggleOK() bool {
	if m.inputting {
		return false
	}
	switch m.sc {
	case scMenu, scAdvanced, scHelp, scDiag, scResult:
		return true
	}
	return false
}

// keysHint is the line of keys under the menu.
func (m model) keysHint() string {
	if m.tr.canHideNow() {
		return menuHint + " · m — в трей"
	}
	return menuHint
}

// trayHandle is what Run keeps of the icon.
type trayHandle struct {
	link *trayLink
	once sync.Once
	done chan struct{}
}

// stop removes the icon in the background (it must not eat the time of the
// cleanup) and brings the console window back. Safe to call more than once.
func (h *trayHandle) stop() {
	if h == nil || !h.link.ready() {
		return
	}
	h.once.Do(func() {
		if tray.ConsoleHidden() {
			tray.ConsoleShow()
		}
		closeDone := sync.OnceFunc(func() { close(h.done) })
		lifecycle.SafeGo(func() {
			defer closeDone()
			h.link.t.Close()
		}, func(error) { closeDone() })
	})
}

// wait gives the removal a moment to end (it is quick unless the desktop hangs).
func (h *trayHandle) wait(d time.Duration) {
	if h == nil || !h.link.ready() {
		return
	}
	select {
	case <-h.done:
	case <-time.After(d):
	}
}

// startTray puts the icon in the notification area, unless it is switched off
// (--no-tray, VPNSPLIT_NO_TRAY, ssh, no rights or another copy owns the
// routes) or the system has none. A failure is not fatal: the menu works as it
// did. It returns the handle to stop it with, and a note for the menu (empty
// when there is nothing to say).
//
// n is the notifier of the signals: the end of the Windows session joins it as
// a SIGTERM, and cleaned is closed when the cleanup is over, so that the
// handler of WM_ENDSESSION can wait for it.
func startTray(opts Options, m model, link *trayLink, p *tea.Program, n *lifecycle.Notifier, cleaned <-chan struct{}) (*trayHandle, string) {
	if m.readOnly != "" || !m.admin {
		return nil, ""
	}
	if tray.Disabled(tray.Settings{NoTray: opts.NoTray}, os.Getenv) != "" {
		return nil, ""
	}
	t, err := tray.Start(tray.Commands{
		Toggle: func() { p.Send(trayToggleMsg{}) },
		Show: func() {
			tray.ConsoleShow()
			p.Send(trayRefreshMsg{}) // the icon shows "hidden" or not: the step pushes the state
		},
		Quit: func() { p.Send(tea.QuitMsg{}) },
		EndSession: func() {
			endSession(n, cleaned, time.Now())
		},
	})
	if err != nil {
		if errors.Is(err, tray.ErrUnsupported) {
			return nil, ""
		}
		return nil, fmt.Sprintf("Значок в области уведомлений не создан: %v", err)
	}
	link.t, link.canHide = t, tray.ConsoleCanHide()
	h := &trayHandle{link: link, done: make(chan struct{})}
	// ForceExit and the last recover of main end the process without the way out of Run
	lifecycle.AtExit(func() {
		h.stop()
		h.wait(650 * time.Millisecond) // the icon is gone before the process is
	})
	link.push(m)
	return h, ""
}

// endSession is what Windows asks at the end of the session (logoff, shutdown):
// the same road as CTRL_SHUTDOWN. The signal is injected into the notifier
// (once: a second notice of the same event is not a repeat), and the call
// returns when the cleanup is over or its budget (counted from the first
// signal) is spent: the process can be killed right after.
func endSession(n *lifecycle.Notifier, cleaned <-chan struct{}, now time.Time) {
	n.Inject(syscall.SIGTERM)
	_, at, ok := n.Signal()
	if !ok {
		at = now
	}
	wait := at.Add(lifecycle.AbruptBudget).Sub(now)
	if wait <= 0 {
		return
	}
	select {
	case <-cleaned:
	case <-time.After(wait):
	}
}

// trayRefreshMsg changes nothing in the model: it makes the step run, and the
// step pushes the state to the icon (the console window was shown or hidden
// from outside the keys).
type trayRefreshMsg struct{}

// trayNoteMsg is a remark about the icon for the line of notes of the menu.
type trayNoteMsg struct{ text string }
