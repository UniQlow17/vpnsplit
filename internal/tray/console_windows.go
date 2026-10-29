//go:build windows

package tray

import (
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	user32                    = windows.NewLazySystemDLL("user32.dll")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procShowWindow            = user32.NewProc("ShowWindow")
	procSetForegroundWindow   = user32.NewProc("SetForegroundWindow")
	procIsWindowVisible       = user32.NewProc("IsWindowVisible")
	procGetClassNameW         = user32.NewProc("GetClassNameW")
)

const (
	swHide    = 0
	swRestore = 9

	// the class of the window of the classic console host (conhost); the
	// pseudo-console of Windows Terminal and the like has another one
	classicConsoleClass = "ConsoleWindowClass"
)

var (
	hideOnce sync.Once
	hideOK   bool
	hidden   atomic.Bool
)

func consoleWindow() uintptr {
	h, _, _ := procGetConsoleWindow.Call()
	return h
}

// ConsoleCanHide tells whether the console window of this process may be hidden
// into the tray: the process is alone on its console, which is the classic
// console host of its own (not Windows Terminal, ConEmu, VS Code, tmux...), and
// the window is visible. It is decided once, at the first call, before the
// window is hidden.
func ConsoleCanHide() bool {
	hideOnce.Do(func() {
		hwnd := consoleWindow()
		if hwnd == 0 {
			return
		}
		var pids [2]uint32
		n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
		var class [64]uint16
		l, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
		classic := windows.UTF16ToString(class[:l]) == classicConsoleClass
		vis, _, _ := procIsWindowVisible.Call(hwnd)
		hideOK = ConsoleEligible(int(n), classic, vis != 0, os.Getenv)
	})
	return hideOK
}

// ConsoleHide hides the console window (the process goes on; Ctrl+C and the
// close button are out of reach until it is shown again). It reports whether
// the window was hidden.
func ConsoleHide() bool {
	if !ConsoleCanHide() {
		return false
	}
	procShowWindow.Call(consoleWindow(), swHide)
	hidden.Store(true)
	return true
}

// ConsoleShow brings the console window back and to the front (also when it
// was only minimized). Safe to call at any time and more than once.
func ConsoleShow() {
	if !ConsoleCanHide() {
		return
	}
	hwnd := consoleWindow()
	procShowWindow.Call(hwnd, swRestore)
	procSetForegroundWindow.Call(hwnd)
	hidden.Store(false)
}

// ConsoleHidden tells whether ConsoleHide hid the window and it is still hidden.
func ConsoleHidden() bool { return hidden.Load() }
