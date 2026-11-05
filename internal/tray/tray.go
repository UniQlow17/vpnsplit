// Package tray is the icon in the notification area: a state-coloured icon, a
// tooltip and a menu ("Разделение ВКЛ/ВЫКЛ", "Показать окно", "Выход").
//
// This file is platform-independent: the states, the texts, the items of the
// menu, the rules that switch the tray off and the mapping of the menu events
// to commands. The icon itself exists on Windows only (tray_windows.go). On
// macOS the status item needs Objective-C (cgo) or a dependency such as purego,
// and on Linux the StatusNotifierItem needs D-Bus (godbus): neither is in
// go.mod and neither is worth a new dependency in a tool that touches the
// routing table, so both return ErrUnsupported and the program works as before.
//
// The tray never acts by itself: every event becomes a command that the menu
// (bubbletea) runs by the same path as the key does (toggle -> toggleSplit,
// quit -> the "q" key -> finish). There is no second way out of the program.
package tray

import (
	"errors"
	"strings"
)

// ErrUnsupported: there is no tray on this system (or none in this build).
var ErrUnsupported = errors.New("tray is not supported here")

// Icon is the picture in the notification area.
type Icon int

const (
	IconOff    Icon = iota // the split is off
	IconOn                 // the split is on
	IconDanger             // a finding of the level danger in the environment
)

// State is what the icon shows.
type State struct {
	On      bool   // the split switch is on
	Danger  bool   // there is a finding of the level danger (router.DiagDanger)
	Code    string // the code of the worst finding, for the tooltip
	CanHide bool   // the console window can be hidden and shown (see Console)
	Hidden  bool   // the console window is hidden now
}

// Icon is the picture for the state: danger wins over the switch.
func (s State) Icon() Icon {
	switch {
	case s.Danger:
		return IconDanger
	case s.On:
		return IconOn
	}
	return IconOff
}

// maxTip is the room for the tooltip of the icon (NOTIFYICONDATAW.szTip, with
// the terminating zero).
const maxTip = 127

// Tooltip is the text under the pointer.
func (s State) Tooltip() string {
	t := "vpnsplit: разделение выключено"
	if s.On {
		t = "vpnsplit: разделение включено"
	}
	if s.Danger {
		t += ". Внимание: проблема в окружении"
		if s.Code != "" {
			t += " (" + s.Code + ")"
		}
	}
	t = strings.ReplaceAll(t, string(rune(0)), "") // a NUL would end the tip (and panic in the conversion)
	if r := []rune(t); len(r) > maxTip {
		t = string(r[:maxTip-1]) + "…"
	}
	return t
}

// Event is what the user chose in the menu of the icon.
type Event int

const (
	EvToggle Event = iota + 1 // "Разделение ВКЛ/ВЫКЛ"
	EvShow                    // "Показать окно" (also a double click on the icon)
	EvQuit                    // "Выход"
)

// Item is a row of the menu of the icon.
type Item struct {
	Event   Event
	Label   string
	Enabled bool
	Checked bool
}

// Items are the rows of the menu for the state. Without the console window to
// hide, "Показать окно" is there but grey.
func Items(s State) []Item {
	toggle := "Разделение: ВКЛ (включить)"
	if s.On {
		toggle = "Разделение: ВЫКЛ (выключить)"
	}
	return []Item{
		{Event: EvToggle, Label: toggle, Enabled: true, Checked: s.On},
		{Event: EvShow, Label: "Показать окно", Enabled: s.CanHide},
		{Event: EvQuit, Label: "Выход", Enabled: true},
	}
}

// Commands are what the program does for the events. They are called on the
// thread of the tray, so they must not block: they hand the work to the menu.
type Commands struct {
	Toggle func() // flip the switch: the same as the menu item "Разделение"
	Show   func() // bring the console window back
	Quit   func() // quit as the "q" key does
	// EndSession is called when Windows ends the session (logoff, shutdown)
	// and must return when the cleanup is over or the budget is spent: after
	// it returns the process may be killed.
	EndSession func()
}

// Dispatch maps an event to its command. It reports whether there was one.
func (c Commands) Dispatch(e Event) bool {
	var f func()
	switch e {
	case EvToggle:
		f = c.Toggle
	case EvShow:
		f = c.Show
	case EvQuit:
		f = c.Quit
	}
	if f == nil {
		return false
	}
	f()
	return true
}

// Tray is a live icon.
type Tray interface {
	// Update shows a new state; cheap when nothing changed.
	Update(State)
	// Close removes the icon. Safe to call more than once and from any
	// goroutine; it does not wait for the desktop longer than a moment.
	Close()
}

// Settings are the switches of the user for the tray.
type Settings struct {
	NoTray bool // --no-tray
}

// Disabled says why the tray must not be started, "" if it may. It looks at
// the settings and the environment only (getenv is os.Getenv); whether the
// desktop has a notification area is for Start to find out.
func Disabled(s Settings, getenv func(string) string) string {
	switch {
	case s.NoTray:
		return "--no-tray"
	case getenv("VPNSPLIT_NO_TRAY") != "" && getenv("VPNSPLIT_NO_TRAY") != "0":
		return "VPNSPLIT_NO_TRAY"
	case getenv("SSH_CONNECTION") != "" || getenv("SSH_CLIENT") != "" || getenv("SSH_TTY") != "":
		return "ssh session"
	}
	return ""
}

// ConsoleEligible tells whether the window of the console may be hidden into
// the tray, from what the process knows about its console: it must be the only
// process on it (the window goes away with the process, nobody else is
// attached to it), the classic console host (not the pseudo-console of
// Windows Terminal, VS Code, ConEmu, ...) and visible.
func ConsoleEligible(procsOnConsole int, classicHost, visible bool, getenv func(string) string) bool {
	if procsOnConsole != 1 || !classicHost || !visible {
		return false
	}
	for _, k := range []string{"WT_SESSION", "TERM_PROGRAM", "ConEmuPID", "WEZTERM_PANE", "ALACRITTY_SOCKET", "VSCODE_PID", "TMUX", "STY"} {
		if strings.TrimSpace(getenv(k)) != "" {
			return false
		}
	}
	return true
}
