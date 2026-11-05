// Package termsize makes the terminal window big enough for the menu, where the
// terminal allows it, and puts the size back at the end.
//
// How the size is changed depends on the terminal and is told from its
// environment (see Detect): the classic Windows console through the console API,
// xterm, iTerm2 and Terminal.app through the escape sequence CSI 8;rows;cols t.
// Everywhere else (Windows Terminal, tmux, VTE, Konsole, unknown terminals) the
// window cannot be resized by a program, or it is not known whether it can: the
// caller only learns the size it wants and tells the user.
package termsize

import (
	"fmt"
	"os"
)

// Size is a window size in character cells.
type Size struct{ Cols, Rows int }

// Fits reports whether a window of size s holds a window of size want.
func (s Size) Fits(want Size) bool { return s.Cols >= want.Cols && s.Rows >= want.Rows }

func (s Size) String() string { return fmt.Sprintf("%d×%d", s.Cols, s.Rows) }

// Method is the way the size of the window can be changed.
type Method int

const (
	// Hint: the program does not resize the window; the user is asked to.
	Hint Method = iota
	// Console: the classic Windows console (conhost), through the console API.
	Console
	// CSI: xterm, iTerm2, Terminal.app, through CSI 8;rows;cols t.
	CSI
)

func (m Method) String() string {
	switch m {
	case Console:
		return "console"
	case CSI:
		return "csi"
	}
	return "hint"
}

// Detect tells the way to resize the window from the environment (getenv) of
// the process on the system goos. Terminals that may sit in front of any other
// (tmux, screen, Windows Terminal) or that do not allow it (VTE, Konsole) are
// checked first: they are asked, not resized.
func Detect(goos string, getenv func(string) string) Method {
	for _, k := range []string{"TMUX", "STY", "WT_SESSION", "VTE_VERSION", "KONSOLE_VERSION"} {
		if getenv(k) != "" {
			return Hint
		}
	}
	if goos == "windows" {
		// The classic console sets none of these. A terminal that runs on top of the
		// console API (ConPTY: VS Code, mintty and Git Bash, ConEmu, WezTerm, Alacritty)
		// has its own window, which the console API does not resize.
		for _, k := range []string{"TERM_PROGRAM", "TERM", "ConEmuPID", "WEZTERM_PANE", "ALACRITTY_SOCKET"} {
			if getenv(k) != "" {
				return Hint
			}
		}
		return Console // the console API answers an error where this is not a console
	}
	if getenv("XTERM_VERSION") != "" {
		return CSI
	}
	switch getenv("TERM_PROGRAM") {
	case "iTerm.app", "Apple_Terminal":
		return CSI
	}
	return Hint
}

// resizeSeq is the sequence that asks the terminal for a window of s cells.
func resizeSeq(s Size) string { return fmt.Sprintf("\x1b[8;%d;%dt", s.Rows, s.Cols) }

// Result is what Fit did.
type Result struct {
	Method  Method
	Resized bool   // the window was asked to change (or changed)
	Restore func() // puts the size back; safe to call more than once and from any goroutine
}

// Fit grows the window to want, when it is smaller and the terminal can be
// resized, and returns the way to put the size back. It never shrinks a window.
// Restore is never nil. The terminal is out (normally os.Stdout).
func Fit(want Size, out *os.File) Result {
	return fit(want, out, Detect(goos(), os.Getenv))
}

func fit(want Size, out *os.File, m Method) Result {
	res := Result{Method: m, Restore: func() {}}
	switch m {
	case Console:
		if !isConsole(out) {
			res.Method = Hint
			break
		}
		if restore, ok := consoleFit(want, out); ok {
			res.Resized, res.Restore = true, once(restore)
		}
	case CSI:
		cur, ok := ttySize(out)
		if !ok {
			res.Method = Hint
			break
		}
		if cur.Fits(want) {
			break
		}
		to := Size{max(cur.Cols, want.Cols), max(cur.Rows, want.Rows)}
		if _, err := out.WriteString(resizeSeq(to)); err != nil {
			res.Method = Hint
			break
		}
		res.Resized = true
		res.Restore = once(func() { _, _ = out.WriteString(resizeSeq(cur)) })
	}
	return res
}

// once makes f run at most once, however often and from wherever it is called.
func once(f func()) func() {
	ch := make(chan struct{}, 1)
	ch <- struct{}{}
	return func() {
		select {
		case <-ch:
			f()
		default:
		}
	}
}
