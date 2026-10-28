package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/lifecycle"
	"github.com/UniQlow17/vpnsplit/internal/router"
)

// killAfter is how long the menu gets to quit on a signal before it is torn
// down. It is part of the time the cleanup is given after a signal (see
// lifecycle.AbruptBudget), not added to it.
const killAfter = 500 * time.Millisecond

// foreignNote is shown while the persistent routes of apply/watch wait for
// the user's decision.
const foreignNote = "Маршруты применены командой apply/watch (постоянные). [t] Забрать в сессию — будут сняты при выходе"

// ender is the session of the router, narrowed for tests.
type ender interface {
	CleanupUntil(deadline time.Time, progress func(done, total int)) (router.Report, error)
	Mode() string
	Foreign() bool
}

// noAdminNote is why the menu cannot change anything without rights.
func noAdminNote() string {
	how := "запустите vpnsplit через sudo"
	if runtime.GOOS == "windows" {
		how = "запустите терминал от имени администратора"
	}
	return "Нет прав администратора: меню только показывает состояние, маршруты менять нельзя. Чтобы применять и сбрасывать, " + how
}

// Run starts the interactive menu as a session: with administrator rights it
// first deals with what an earlier run left behind (router.Manager.Acquire),
// and whenever the menu ends, however (quit, Ctrl+C, closed window, signal,
// panic), everything it applied is removed. A failure to remove it is
// reported loudly and makes the exit code non-zero; the next start finishes.
// Routes left by apply/watch are not removed without the user's say (the [t]
// key of the menu).
func Run() (err error) {
	sp := spinner.New(spinner.WithSpinner(spinner.Dot))
	sp.Style = lipgloss.NewStyle().Foreground(cCyan)
	admin := router.IsPrivileged()
	m := model{admin: admin, input: newInput(), spin: sp, streamPaste: streamPasteDefault, now: time.Now}

	// signals are listened for before anything slow starts: one that arrives
	// while the previous run is being cleaned up ends the start, cleanly
	n := lifecycle.Notify()
	defer n.Stop()

	var sess *router.Session
	if admin {
		mgr := router.NewManager()
		m.mgr = mgr
		var info router.AcquireInfo
		var aerr error
		sess, info, aerr = mgr.Acquire(n.Context(), router.ModeSessionAsk, os.Stderr)
		if sess == nil && n.Context().Err() != nil {
			fmt.Fprintln(os.Stderr, "vpnsplit: прервано сигналом при запуске; то, что не успели убрать после прошлого запуска, осталось в журнале: следующий запуск доделает")
			return nil
		}
		m.readOnly, m.flash = startupNotes(info, aerr)
		m.flashAt = 100
		// with rights, keep routes in sync from the start: nothing to think
		// about, unless there are routes of apply/watch to decide about
		m.auto = aerr == nil && !info.Foreign
		m.lastSession = config.ReadLastSession()
		if m.lastSession != "" && aerr == nil {
			m.flash = joinNotes(m.flash, "Последний сеанс: "+m.lastSession)
		}
	} else {
		m.readOnly = noAdminNote()
		m.flash, m.flashAt = m.readOnly, 100
	}
	if sess != nil {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("internal error: %v\n%s", r, debug.Stack())
			}
			// a second signal while the cleanup runs: the user insists
			n.OnRepeat(func(os.Signal) {
				lifecycle.ForceExit("\nvpnsplit: повторный сигнал, выход без ожидания. Журнал сохранён: следующий запуск vpnsplit с правами администратора доделает (или `vpnsplit reset`).")
			})
			err = finish(sess, exitInfo(n.Signal()), err, os.Stdout, os.Stderr)
		}()
		if n.Context().Err() != nil { // a signal came as the start was ending
			return nil
		}
	}

	// the program does not handle signals itself: a signal asks the menu to
	// quit, and Cleanup runs after the menu is gone, never next to it
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithoutSignalHandler())
	done := make(chan struct{})
	lifecycle.SafeGo(func() {
		watchSignals(n.Context().Done(), done, killAfter,
			func() { p.Send(tea.QuitMsg{}) }, p.Kill)
	}, func(e error) { fmt.Fprintln(os.Stderr, e); p.Kill() })

	_, err = p.Run()
	close(done)
	if _, _, signaled := n.Signal(); signaled && errors.Is(err, tea.ErrProgramKilled) {
		err = nil // torn down after a signal, on purpose
	}
	return err
}

// exitInfo is why and until when the session ends.
func exitInfo(sig os.Signal, at time.Time, ok bool) finishInfo {
	if !ok {
		return finishInfo{reason: "выход из меню", deadline: lifecycle.CleanupDeadline(nil, time.Time{}, time.Now()), saveLast: saveLast}
	}
	return finishInfo{reason: "сигнал " + sig.String(), deadline: lifecycle.CleanupDeadline(sig, at, time.Now()), saveLast: saveLast}
}

func saveLast(text string) error { return config.WriteLastSession(text) }

// watchSignals asks the program to quit on the first signal (sig closes) and
// tears it down if it has not ended (done closed) within grace. The timer
// starts before the quit request, which is made on its own goroutine: it
// blocks until the program takes it, and that must not delay the kill.
func watchSignals(sig <-chan struct{}, done <-chan struct{}, grace time.Duration, quit, kill func()) {
	select {
	case <-sig:
	case <-done:
		return
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	lifecycle.SafeGo(quit, nil)
	select {
	case <-done:
	case <-timer.C:
		kill()
	}
}

func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + ". " + b
}

// startupNotes turns the result of Acquire into the note shown in the menu
// and, when this copy may not change anything, the reason.
func startupNotes(info router.AcquireInfo, err error) (readOnly, note string) {
	if err != nil {
		var busy *router.BusyError
		if errors.As(err, &busy) {
			who := "Другая копия vpnsplit"
			if busy.Owner != nil {
				who = fmt.Sprintf("Другая копия vpnsplit (PID %d)", busy.Owner.PID)
			}
			readOnly = who + " уже управляет маршрутами: эта копия только показывает состояние. Закройте другую копию"
		} else {
			readOnly = "Нельзя начать работу с маршрутами: " + err.Error()
		}
		return readOnly, readOnly
	}
	var parts []string
	if r := info.Recovered; r.Total()+r.Forgotten > 0 {
		parts = append(parts, "Убрано после прошлого запуска: "+r.Describe(true))
	}
	if len(info.Errors) > 0 {
		parts = append(parts, fmt.Sprintf("Не всё убрано после прошлого запуска (%d), будет повтор", len(info.Errors)))
	}
	if info.Foreign {
		parts = append(parts, foreignNote)
	}
	return "", strings.Join(parts, ". ")
}

// finishInfo is how the session ends.
type finishInfo struct {
	reason   string                // for the note about the last session
	deadline time.Time             // the cleanup must be over by then
	saveLast func(string) error    // remembers the outcome for the next start; may be nil
	progress func(done, total int) // nil: lines on stderr
}

// finish ends the session and reports the result. It is the one path every
// exit takes. A failure to remove everything is loud and becomes the error,
// which makes the exit code non-zero. The outcome of a session is also
// written down (saveLast): when the console window was closed nobody saw it.
func finish(sess ender, fi finishInfo, runErr error, stdout, stderr io.Writer) error {
	progress := fi.progress
	if progress == nil {
		progress = func(done, total int) {
			fmt.Fprintf(stderr, "vpnsplit: снимаю маршруты и DNS: %d из %d\n", done, total)
		}
	}
	rep, cerr := sess.CleanupUntil(fi.deadline, progress)
	persistent := sess.Mode() != config.ModeSession
	var summary string
	switch {
	case cerr != nil:
		fmt.Fprintf(stderr, "\n!!! vpnsplit НЕ УБРАЛ всё, что применил: %v\n"+
			"!!! Остальное осталось в журнале: следующий запуск vpnsplit с правами администратора доделает (или `vpnsplit reset`).\n", cerr)
		summary = "НЕ ВСЁ СНЯТО, остаток в журнале (следующий запуск доделает): " + headLine(cerr.Error())
		if runErr == nil {
			runErr = errors.New("очистка не завершена")
		}
	case persistent && sess.Foreign():
		fmt.Fprintln(stdout, "vpnsplit: маршруты apply/watch оставлены (постоянные); убрать: `vpnsplit reset`")
		return runErr
	case persistent:
		return runErr
	default:
		summary = rep.Describe(true)
		fmt.Fprintln(stdout, "vpnsplit:", summary)
	}
	if n := rep.Notice(true); n != "" {
		fmt.Fprintln(stdout, "vpnsplit:", n)
	}
	if fi.saveLast != nil {
		text := time.Now().Format("2006-01-02 15:04:05") + " (" + fi.reason + "): " + summary
		if rep.FullTunnel {
			text += ". Весь трафик шёл напрямую, мимо домашнего VPN, пока VPN-клиент сам не направил его в туннель"
		}
		if err := fi.saveLast(text); err != nil {
			fmt.Fprintln(stderr, "vpnsplit: не удалось записать итог сеанса:", err)
		}
	}
	return runErr
}

func headLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
