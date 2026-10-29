//go:build windows

package tray

import (
	"testing"
	"unsafe"
)

// The structure goes to Shell_NotifyIconW as it is: size and offsets must be
// those of NOTIFYICONDATAW. Nothing is sent to the shell here.
func TestNotifyIconDataLayout(t *testing.T) {
	var d notifyIconData
	if unsafe.Sizeof(uintptr(0)) == 8 {
		checks := map[string][2]uintptr{
			"size":             {unsafe.Sizeof(d), 976},
			"hWnd":             {unsafe.Offsetof(d.hWnd), 8},
			"uID":              {unsafe.Offsetof(d.uID), 16},
			"uFlags":           {unsafe.Offsetof(d.uFlags), 20},
			"uCallbackMessage": {unsafe.Offsetof(d.uCallbackMessage), 24},
			"hIcon":            {unsafe.Offsetof(d.hIcon), 32},
			"szTip":            {unsafe.Offsetof(d.szTip), 40},
			"dwState":          {unsafe.Offsetof(d.dwState), 296},
			"szInfo":           {unsafe.Offsetof(d.szInfo), 304},
			"uVersion":         {unsafe.Offsetof(d.uVersion), 816},
			"szInfoTitle":      {unsafe.Offsetof(d.szInfoTitle), 820},
			"dwInfoFlags":      {unsafe.Offsetof(d.dwInfoFlags), 948},
			"guidItem":         {unsafe.Offsetof(d.guidItem), 952},
			"hBalloonIcon":     {unsafe.Offsetof(d.hBalloonIcon), 968},
		}
		for name, c := range checks {
			if c[0] != c[1] {
				t.Errorf("%s: %d, want %d", name, c[0], c[1])
			}
		}
	} else if got := unsafe.Sizeof(d); got != 956 {
		t.Errorf("size %d, want 956", got)
	}
	var w wndClassEx
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(w) != 80 {
		t.Errorf("WNDCLASSEXW: %d, want 80", unsafe.Sizeof(w))
	}
	var m msg
	if unsafe.Sizeof(uintptr(0)) == 8 && unsafe.Sizeof(m) != 48 {
		t.Errorf("MSG: %d, want 48", unsafe.Sizeof(m))
	}
}

// The data for a state: the flags, the callback, a tip that is terminated.
// It does not call the shell.
func TestNotifyIconDataFill(t *testing.T) {
	w := &winTray{}
	w.hwnd.Store(0x1234)
	d := w.data(State{On: true})
	if d.cbSize != uint32(unsafe.Sizeof(*d)) || d.hWnd != 0x1234 || d.uID != iconID || d.uCallbackMessage != wmTray {
		t.Errorf("%+v", d)
	}
	if d.uFlags != nifMessage|nifIcon|nifTip {
		t.Errorf("flags %x", d.uFlags)
	}
	if d.szTip[len(d.szTip)-1] != 0 || d.szTip[0] == 0 {
		t.Error("the tip must be there and end with zero")
	}
}

func TestLongTipFits(t *testing.T) {
	w := &winTray{}
	d := w.data(State{Danger: true, Code: string(make([]byte, 500))})
	if d.szTip[len(d.szTip)-1] != 0 {
		t.Error("the tip is not terminated")
	}
}
