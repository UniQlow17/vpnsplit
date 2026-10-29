//go:build unix

package termsize

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func goos() string { return runtime.GOOS }

// isConsole: there is no console API outside Windows.
func isConsole(*os.File) bool { return false }

// consoleFit: there is no console API outside Windows.
func consoleFit(Size, *os.File) (func(), bool) { return nil, false }

// ttySize is the size of the terminal f; false if f is not a terminal.
func ttySize(f *os.File) (Size, bool) {
	if f == nil {
		return Size{}, false
	}
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 || ws.Row == 0 {
		return Size{}, false
	}
	return Size{Cols: int(ws.Col), Rows: int(ws.Row)}, true
}
