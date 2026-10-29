//go:build windows

package termsize

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func goos() string { return runtime.GOOS }

// ttySize is not used on Windows: the console API is.
func ttySize(*os.File) (Size, bool) { return Size{}, false }

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procSetBufferSize = kernel32.NewProc("SetConsoleScreenBufferSize")
	procSetWindowInfo = kernel32.NewProc("SetConsoleWindowInfo")
	procLargestWindow = kernel32.NewProc("GetLargestConsoleWindowSize")
)

type coord struct{ x, y int16 }

type smallRect struct{ left, top, right, bottom int16 }

func setBufferSize(h windows.Handle, c coord) error {
	// a COORD travels by value in one register
	r, _, err := procSetBufferSize.Call(uintptr(h), uintptr(*(*uint32)(unsafe.Pointer(&c))))
	if r == 0 {
		return err
	}
	return nil
}

func setWindow(h windows.Handle, r smallRect) error {
	ret, _, err := procSetWindowInfo.Call(uintptr(h), 1, uintptr(unsafe.Pointer(&r)))
	if ret == 0 {
		return err
	}
	return nil
}

func largest(h windows.Handle) (cols, rows int) {
	r, _, _ := procLargestWindow.Call(uintptr(h))
	v := uint32(r)
	return int(int16(v & 0xffff)), int(int16(v >> 16))
}

// isConsole: f is a console screen buffer (not a pipe, a file or a pseudo-console of another terminal's making).
func isConsole(f *os.File) bool {
	var mode uint32
	return f != nil && windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// consoleFit grows the window of the classic console to want: the buffer first,
// then the window. It returns the function that puts the buffer and the window
// back as they were; false if out is not a console or nothing was done. A
// window that is big enough is left alone, and one that cannot be as big as
// asked (the screen is smaller) gets as big as it can.
func consoleFit(want Size, out *os.File) (func(), bool) {
	// the output must be the console itself: with a pipe or a file the window
	// that happens to belong to the process is not the one the user looks at
	if !isConsole(out) {
		return nil, false
	}
	name, err := windows.UTF16PtrFromString("CONOUT$")
	if err != nil {
		return nil, false
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, false
	}
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, false
	}
	curW := int(info.Window.Right-info.Window.Left) + 1
	curH := int(info.Window.Bottom-info.Window.Top) + 1
	maxW, maxH := largest(h)
	wantW, wantH := want.Cols, want.Rows
	if maxW > 0 {
		wantW = min(wantW, maxW)
	}
	if maxH > 0 {
		wantH = min(wantH, maxH)
	}
	newW, newH := max(curW, wantW), max(curH, wantH)
	if newW == curW && newH == curH {
		windows.CloseHandle(h)
		return nil, false
	}
	savedBuf := coord{info.Size.X, info.Size.Y}
	savedWin := smallRect{info.Window.Left, info.Window.Top, info.Window.Right, info.Window.Bottom}
	buf := coord{int16(max(int(savedBuf.x), newW)), int16(max(int(savedBuf.y), newH))}
	if err := setBufferSize(h, buf); err != nil {
		windows.CloseHandle(h)
		return nil, false
	}
	if err := setWindow(h, smallRect{0, 0, int16(newW - 1), int16(newH - 1)}); err != nil {
		_ = setBufferSize(h, savedBuf)
		windows.CloseHandle(h)
		return nil, false
	}
	return func() {
		// the other way round: the window first, then the buffer
		_ = setWindow(h, savedWin)
		_ = setBufferSize(h, savedBuf)
		windows.CloseHandle(h)
	}, true
}
