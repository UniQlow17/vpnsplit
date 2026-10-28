package tui

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/lifecycle"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/router/routertest"
)

type fakeEnder struct {
	rep      router.Report
	err      error
	calls    int
	mode     string
	foreign  bool
	deadline time.Time
}

func (f *fakeEnder) CleanupUntil(d time.Time, progress func(int, int)) (router.Report, error) {
	f.calls++
	f.deadline = d
	if progress != nil {
		progress(1, 2)
	}
	return f.rep, f.err
}

func (f *fakeEnder) Mode() string {
	if f.mode == "" {
		return config.ModeSession
	}
	return f.mode
}

func (f *fakeEnder) Foreign() bool { return f.foreign }

func finishFor(f ender, runErr error, out, errOut *bytes.Buffer, last *[]string) error {
	return finish(f, finishInfo{reason: "тест", deadline: time.Now().Add(time.Second),
		saveLast: func(s string) error { *last = append(*last, s); return nil }}, runErr, out, errOut)
}

func TestFinishReportsWhatWasRemoved(t *testing.T) {
	f := &fakeEnder{rep: router.Report{Routes: 3, Resolvers: 1, FullTunnel: true}}
	var out, errOut bytes.Buffer
	var last []string
	if err := finishFor(f, nil, &out, &errOut, &last); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "полный туннель 0/1+128/1 снят") {
		t.Errorf("out %q", out.String())
	}
	if !strings.Contains(out.String(), "Весь трафик теперь идёт напрямую через провайдера (мимо домашнего VPN)") {
		t.Errorf("the consequence of removing the full tunnel is not said: %q", out.String())
	}
	if len(last) != 1 || !strings.Contains(last[0], "(тест)") || !strings.Contains(last[0], "снято: маршрутов 3") {
		t.Errorf("the outcome must be remembered for the next start: %q", last)
	}
}

// A failed cleanup is loud and turns into a non-zero exit, even after a clean run.
func TestFinishFailureIsLoud(t *testing.T) {
	f := &fakeEnder{err: errors.New("2 entries were not removed")}
	var out, errOut bytes.Buffer
	var last []string
	err := finishFor(f, nil, &out, &errOut, &last)
	if err == nil {
		t.Fatal("exit code must be non-zero")
	}
	if !strings.Contains(errOut.String(), "НЕ УБРАЛ") || !strings.Contains(errOut.String(), "доделает") {
		t.Errorf("stderr: %q", errOut.String())
	}
	if len(last) != 1 || !strings.Contains(last[0], "НЕ ВСЁ СНЯТО") {
		t.Errorf("%q", last)
	}
}

func TestFinishKeepsTheRunError(t *testing.T) {
	run := errors.New("program panic")
	f := &fakeEnder{}
	var last []string
	if err := finishFor(f, run, &bytes.Buffer{}, &bytes.Buffer{}, &last); !errors.Is(err, run) {
		t.Errorf("%v", err)
	}
	if f.calls != 1 {
		t.Error("cleanup must run even when the program failed")
	}
}

// The routes of apply/watch that the user did not take over are left, and
// the exit says so; no "last session" is recorded for a session that did nothing.
func TestFinishForeignLeavesRoutes(t *testing.T) {
	f := &fakeEnder{mode: config.ModePersistent, foreign: true}
	var out bytes.Buffer
	var last []string
	if err := finishFor(f, nil, &out, &bytes.Buffer{}, &last); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "оставлены") || len(last) != 0 {
		t.Errorf("%q %q", out.String(), last)
	}
}

func TestFinishShowsProgress(t *testing.T) {
	f := &fakeEnder{}
	var errOut bytes.Buffer
	var last []string
	if err := finishFor(f, nil, &bytes.Buffer{}, &errOut, &last); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "1 из 2") {
		t.Errorf("no progress: %q", errOut.String())
	}
}

// The time given to the cleanup depends on why the program ends.
func TestExitInfoBudgetByReason(t *testing.T) {
	at := time.Now().Add(-700 * time.Millisecond) // the signal came 0.7 s ago: menu grace, terminal restore
	quit := exitInfo(nil, time.Time{}, false)
	if d := time.Until(quit.deadline); d < 55*time.Second || d > 61*time.Second {
		t.Errorf("quit from the menu: %v", d)
	}
	if d := time.Until(exitInfo(os.Interrupt, at, true).deadline); d < 55*time.Second {
		t.Errorf("SIGINT in a terminal is a normal exit: %v", d)
	}
	for _, s := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		got := exitInfo(s, at, true).deadline
		want := at.Add(lifecycle.AbruptBudget)
		if got.Sub(want) > 50*time.Millisecond || want.Sub(got) > 50*time.Millisecond {
			t.Errorf("%v: the deadline counts from the signal: %v, want %v", s, got, want)
		}
		if time.Until(got) > 4*time.Second {
			t.Errorf("%v: what the menu grace and the restore took must be deducted: %v left", s, time.Until(got))
		}
	}
}

func TestWatchSignalsQuitsThenKills(t *testing.T) {
	sig := make(chan struct{})
	done := make(chan struct{})
	var quit, kill atomic.Int32
	ended := make(chan struct{})
	go func() {
		watchSignals(sig, done, 50*time.Millisecond, func() { quit.Add(1) }, func() { kill.Add(1) })
		close(ended)
	}()
	close(sig)
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("no kill after the grace period")
	}
	time.Sleep(20 * time.Millisecond)
	if quit.Load() != 1 || kill.Load() != 1 {
		t.Errorf("quit %d kill %d", quit.Load(), kill.Load())
	}
}

// p.Send blocks until the program takes the message: that must not delay the kill.
func TestWatchSignalsBlockedQuitDoesNotDelayKill(t *testing.T) {
	sig := make(chan struct{})
	close(sig)
	block := make(chan struct{})
	defer close(block)
	killed := make(chan struct{})
	start := time.Now()
	go watchSignals(sig, make(chan struct{}), 100*time.Millisecond, func() { <-block }, func() { close(killed) })
	select {
	case <-killed:
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("killed after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked quit held the kill back")
	}
}

func TestWatchSignalsNoKillWhenMenuEnds(t *testing.T) {
	sig := make(chan struct{})
	done := make(chan struct{})
	var kill atomic.Int32
	ended := make(chan struct{})
	go func() {
		watchSignals(sig, done, time.Second, func() { close(done) }, func() { kill.Add(1) })
		close(ended)
	}()
	close(sig)
	<-ended
	if kill.Load() != 0 {
		t.Error("killed a menu that had quit")
	}
}

func TestWatchSignalsReturnsWhenMenuEndsFirst(t *testing.T) {
	done := make(chan struct{})
	ended := make(chan struct{})
	go func() {
		watchSignals(make(chan struct{}), done, time.Second, func() { t.Error("quit") }, func() { t.Error("kill") })
		close(ended)
	}()
	close(done)
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("goroutine leaked")
	}
}

func TestStartupNotes(t *testing.T) {
	ro, note := startupNotes(router.AcquireInfo{}, &router.BusyError{})
	if ro == "" || note != ro {
		t.Errorf("a second copy is read-only: %q %q", ro, note)
	}
	ro, note = startupNotes(router.AcquireInfo{Recovered: router.Report{Routes: 2}}, nil)
	if ro != "" || !strings.Contains(note, "прошлого запуска") {
		t.Errorf("%q %q", ro, note)
	}
	ro, note = startupNotes(router.AcquireInfo{Foreign: true}, nil)
	if ro != "" || !strings.Contains(note, "[t] Забрать в сессию — будут сняты при выходе") || !strings.Contains(note, "apply/watch") {
		t.Errorf("%q %q", ro, note)
	}
	if ro, note = startupNotes(router.AcquireInfo{}, nil); ro != "" || note != "" {
		t.Errorf("a quiet start has no notes: %q %q", ro, note)
	}
}

func TestNoAdminNoteSaysWhatToDo(t *testing.T) {
	n := noAdminNote()
	if !strings.Contains(n, "администратор") {
		t.Errorf("%q", n)
	}
	m := model{readOnly: n, cfg: config.New()}
	if cmd := m.startApply(false); cmd != nil || m.flash != n {
		t.Errorf("without rights nothing is applied: cmd %v flash %q", cmd, m.flash)
	}
}

// A copy that does not own the routes cannot apply or reset from the menu.
func TestReadOnlyModelDoesNotChangeTheNetwork(t *testing.T) {
	m := model{readOnly: "Другая копия управляет маршрутами", cfg: config.New()}
	if cmd := m.startApply(false); cmd != nil || m.flash != m.readOnly {
		t.Errorf("apply: cmd %v flash %q", cmd, m.flash)
	}
	m.flash = ""
	if cmd := m.startReset(false); cmd != nil || m.flash != m.readOnly {
		t.Errorf("reset: cmd %v flash %q", cmd, m.flash)
	}
}

func TestViewWithStartupNoteDoesNotHang(t *testing.T) {
	ro, note := startupNotes(router.AcquireInfo{}, &router.BusyError{Owner: &config.Owner{PID: 123}})
	sp := spinner.New()
	m := model{admin: true, readOnly: ro, flash: note, flashAt: 100, input: newInput(), spin: sp, now: time.Now, width: 120, height: 40}
	done := make(chan string, 1)
	go func() { done <- m.View() }()
	select {
	case v := <-done:
		if !strings.Contains(v, "Другая копия") {
			t.Errorf("the note is not shown:\n%s", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("View hangs")
	}
}

// foreignModel is the menu started over routes that apply/watch left.
func foreignModel(t *testing.T) (model, *routertest.Rig, *router.Session) {
	t.Helper()
	r := routertest.New(routertest.Journal(config.ModePersistent))
	sess, info, err := r.M.Acquire(t.Context(), router.ModeSessionAsk, &bytes.Buffer{})
	if err != nil || !info.Foreign {
		t.Fatalf("%+v %v", info, err)
	}
	m := model{admin: true, mgr: r.M, input: newInput(), spin: spinner.New(), now: time.Now, width: 130, height: 50}
	return m, r, sess
}

// The routes of apply/watch are not taken silently: a notice with the action
// is shown, and quitting without confirming removes nothing.
func TestForeignRoutesNoticeAndQuitLeavesThem(t *testing.T) {
	m, r, sess := foreignModel(t)
	v := m.View()
	for _, want := range []string{"apply/watch", "постоянные", "[t]", "Забрать в сессию", "будут сняты при выходе"} {
		if !strings.Contains(v, want) {
			t.Errorf("the notice lacks %q:\n%s", want, v)
		}
	}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatal("q must quit")
	}
	var out bytes.Buffer
	var last []string
	if err := finish(sess, finishInfo{deadline: time.Now().Add(time.Second), saveLast: func(s string) error { last = append(last, s); return nil }}, nil, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(r.Calls()) != 0 || len(r.State().Routes) != 3 || r.State().Mode != config.ModePersistent {
		t.Errorf("nothing may be removed without the confirmation: %v %+v", r.Calls(), r.State())
	}
	if r.Held() {
		t.Error("lock not released")
	}
	if len(last) != 0 {
		t.Errorf("nothing happened to remember: %q", last)
	}
}

func TestForeignAutoModeWaits(t *testing.T) {
	m, r, _ := foreignModel(t)
	m.auto = true
	next, cmd := m.Update(statusMsg{cfg: config.New(), st: &config.State{}, apply: true})
	if cmd != nil || len(r.Calls()) != 0 || next.(model).busy != "" {
		t.Errorf("auto mode must not touch the routes of apply/watch before the confirmation: cmd %v", cmd)
	}
}

// t takes them over: the notice goes, and quitting then removes them.
func TestForeignTakeOverThenQuitRemoves(t *testing.T) {
	m, r, sess := foreignModel(t)
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	if cmd == nil {
		t.Fatal("t must start the take-over")
	}
	msg := cmd()
	if to, ok := msg.(tookOver); !ok || to.err != nil {
		t.Fatalf("%#v", msg)
	}
	next, _ = next.(model).Update(msg)
	m = next.(model)
	if m.foreign() || !m.auto {
		t.Errorf("foreign %v auto %v", m.foreign(), m.auto)
	}
	if v := m.View(); strings.Contains(v, "Забрать в сессию") {
		t.Errorf("the notice must go:\n%s", v)
	}
	var out bytes.Buffer
	if err := finish(sess, finishInfo{deadline: time.Now().Add(5 * time.Second)}, nil, &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(r.State().Routes) != 0 || routertest.Count(r.Calls(), "route ") != 3 {
		t.Errorf("%v %+v", r.Calls(), r.State())
	}
	if !strings.Contains(out.String(), "Весь трафик теперь идёт напрямую") {
		t.Errorf("%q", out.String())
	}
}

// t does nothing when there is nothing to take.
func TestTKeyWithoutForeignRoutesIsIdle(t *testing.T) {
	r := routertest.New(nil)
	if _, _, err := r.M.Acquire(t.Context(), router.ModeSessionAsk, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	m := model{admin: true, mgr: r.M, input: newInput(), spin: spinner.New(), now: time.Now}
	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}}); cmd != nil {
		t.Error("t must do nothing")
	}
}

func TestDeadSessionDNSWarning(t *testing.T) {
	const gone = 2147483000 // no such process
	st := &config.State{Mode: config.ModeSession, Owner: &config.Owner{PID: gone, Start: 1}, Resolvers: []string{routertest.Resolver("corp.example")}}
	if w := deadSessionDNSWarning(st); !strings.Contains(w, "DNS-правила прошлого сеанса") || !strings.Contains(w, "с правами администратора") {
		t.Errorf("%q", w)
	}
	st.Resolvers = nil
	if deadSessionDNSWarning(st) != "" {
		t.Error("no DNS entries, no warning")
	}
	st.Resolvers, st.Mode = []string{routertest.Resolver("corp.example")}, config.ModePersistent
	if deadSessionDNSWarning(st) != "" {
		t.Error("persistent entries stay on purpose")
	}
}

func TestStatusScreenShowsLastSession(t *testing.T) {
	m := model{cfg: config.New(), lastSession: "2026-01-01 12:00:00 (сигнал terminated): снято: маршрутов 3", width: 120, height: 40}
	if v := strings.Join(m.statusLines(), "\n"); !strings.Contains(v, "Последний сеанс") || !strings.Contains(v, "маршрутов 3") {
		t.Errorf("%s", v)
	}
}
