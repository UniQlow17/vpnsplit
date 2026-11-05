//go:build windows

package tray

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/UniQlow17/vpnsplit/internal/lifecycle"
)

// The icon lives on one thread: a hidden window receives the messages of the
// icon and of the session, and the loop GetMessage/DispatchMessage runs on a
// goroutine locked to its OS thread (a window belongs to the thread that made it).
// No cgo: user32, shell32 and gdi32 are called through x/sys/windows.

var (
	shell32 = windows.NewLazySystemDLL("shell32.dll")
	gdi32   = windows.NewLazySystemDLL("gdi32.dll")

	procShellNotifyIcon    = shell32.NewProc("Shell_NotifyIconW")
	procRegisterClassEx    = user32.NewProc("RegisterClassExW")
	procUnregisterClass    = user32.NewProc("UnregisterClassW")
	procCreateWindowEx     = user32.NewProc("CreateWindowExW")
	procDestroyWindow      = user32.NewProc("DestroyWindow")
	procDefWindowProc      = user32.NewProc("DefWindowProcW")
	procGetMessage         = user32.NewProc("GetMessageW")
	procTranslateMessage   = user32.NewProc("TranslateMessage")
	procDispatchMessage    = user32.NewProc("DispatchMessageW")
	procPostMessage        = user32.NewProc("PostMessageW")
	procPostQuitMessage    = user32.NewProc("PostQuitMessage")
	procRegisterWindowMsg  = user32.NewProc("RegisterWindowMessageW")
	procFindWindow         = user32.NewProc("FindWindowW")
	procCreatePopupMenu    = user32.NewProc("CreatePopupMenu")
	procAppendMenu         = user32.NewProc("AppendMenuW")
	procTrackPopupMenu     = user32.NewProc("TrackPopupMenu")
	procDestroyMenu        = user32.NewProc("DestroyMenu")
	procGetCursorPos       = user32.NewProc("GetCursorPos")
	procSetTimer           = user32.NewProc("SetTimer")
	procKillTimer          = user32.NewProc("KillTimer")
	procMsgFilterEx        = user32.NewProc("ChangeWindowMessageFilterEx")
	procIconGetRect        = shell32.NewProc("Shell_NotifyIconGetRect")
	procCreateIconIndirect = user32.NewProc("CreateIconIndirect")
	procDestroyIcon        = user32.NewProc("DestroyIcon")
	procGetSystemMetrics   = user32.NewProc("GetSystemMetrics")
	procCreateBitmap       = gdi32.NewProc("CreateBitmap")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procGetModuleHandle    = kernel32.NewProc("GetModuleHandleW")
)

const (
	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nimSetVersion = 4

	nifMessage = 0x1
	nifIcon    = 0x2
	nifTip     = 0x4

	notifyIconVersion4 = 4

	wmNull          = 0x0000
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmQueryEndSess  = 0x0011
	wmEndSession    = 0x0016
	wmContextMenu   = 0x007B
	wmRButtonUp     = 0x0205
	wmLButtonDblClk = 0x0203
	wmTimer         = 0x0113
	wmApp           = 0x8000

	ninKeySelect = 0x401 // NIN_SELECT | NINF_KEY: the icon chosen by the keyboard (version 4)

	msgfltAllow = 1 // MSGFLT_ALLOW

	retryTimerID  = 1
	retryTimerMs  = 1000
	maxAddRetries = 5

	wmTray   = wmApp + 1 // the callback message of the icon
	wmUpdate = wmApp + 2 // the state changed: show it

	mfString    = 0x0
	mfGrayed    = 0x1
	mfChecked   = 0x8
	mfSeparator = 0x800

	tpmRightButton = 0x2
	tpmReturnCmd   = 0x100
	tpmNoNotify    = 0x80

	smCxSmIcon = 49

	iconID = 1
)

// notifyIconData is NOTIFYICONDATAW (Windows Vista and later layout).
type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32 // the union with uTimeout
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     uintptr
}

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type iconInfo struct {
	fIcon    uint32
	xHotspot uint32
	yHotspot uint32
	hbmMask  uintptr
	hbmColor uintptr
}

// notifyIconIdentifier is NOTIFYICONIDENTIFIER.
type notifyIconIdentifier struct {
	cbSize   uint32
	hWnd     uintptr
	uID      uint32
	guidItem windows.GUID
}

type winTray struct {
	cmds    Commands
	hwnd    atomic.Uintptr // set by the thread of the window, read by Update and Close
	taskbar uint32         // the number of the message "TaskbarCreated"; the thread of the window only
	icons   [3]uintptr
	v4      bool // the icon speaks version 4 (the thread of the window only)

	// the thread of the window only
	classOK  bool // the class is registered
	iconOn   bool // NIM_ADD succeeded
	addTries int  // the attempts to put the icon back after the explorer restarted

	mu     sync.Mutex
	want   State
	closed bool

	closeOnce sync.Once
	exited    chan struct{}
}

// the callback of a window has no context: there is one tray per process
var (
	current   *winTray
	currentMu sync.Mutex
	wndProc   = windows.NewCallback(wndProcMain)
)

// Start puts the icon into the notification area. It fails (and the program
// goes on without a tray) in a session without a desktop (session 0), when
// there is no taskbar, or when the system refuses.
func Start(c Commands) (Tray, error) {
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err == nil && sid == 0 {
		return nil, fmt.Errorf("%w: session 0 has no desktop", ErrUnsupported)
	}
	cls, _ := windows.UTF16PtrFromString("Shell_TrayWnd")
	if h, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(cls)), 0); h == 0 {
		return nil, fmt.Errorf("%w: no notification area (Shell_TrayWnd)", ErrUnsupported)
	}
	currentMu.Lock()
	if current != nil {
		currentMu.Unlock()
		return nil, errors.New("the tray is already started")
	}
	t := &winTray{cmds: c, exited: make(chan struct{})}
	current = t
	currentMu.Unlock()

	ready := make(chan error, 1)
	go t.loop(ready)
	select {
	case err := <-ready:
		if err != nil {
			t.forget()
			return nil, err
		}
	case <-time.After(5 * time.Second):
		// the thread may still finish: it is told to stop the moment it does
		go t.Close()
		return nil, errors.New("the tray did not start in time")
	}
	return t, nil
}

func (t *winTray) forget() {
	currentMu.Lock()
	if current == t {
		current = nil
	}
	currentMu.Unlock()
}

// loop is the thread of the window: it makes the window and the icon, runs the
// message loop and takes everything down when the loop ends, by any road.
func (t *winTray) loop(ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(t.exited)
	sent := false
	sendReady := func(err error) {
		if !sent {
			sent = true
			ready <- err // buffered: never blocks
		}
	}
	defer func() {
		if r := recover(); r != nil {
			sendReady(fmt.Errorf("tray thread: %v", r))
		}
	}()
	defer t.cleanup() // runs before the recover above, also on a panic

	err := t.create()
	sendReady(err)
	if err != nil {
		return
	}
	var m msg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 { // 0: WM_QUIT, -1: error
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// cleanup takes down what create made, whatever stage it got to. On the thread
// of the window.
func (t *winTray) cleanup() {
	if t.iconOn {
		t.deleteIcon()
		t.iconOn = false
	}
	if h := t.hwnd.Swap(0); h != 0 {
		procDestroyWindow.Call(h) // fails harmlessly if the window is gone already
	}
	for i, h := range t.icons {
		if h != 0 {
			procDestroyIcon.Call(h)
			t.icons[i] = 0
		}
	}
	if t.classOK {
		name, _ := windows.UTF16PtrFromString(className)
		hinst, _, _ := procGetModuleHandle.Call(0)
		procUnregisterClass.Call(uintptr(unsafe.Pointer(name)), hinst)
		t.classOK = false
	}
}

const className = "vpnsplit.tray"

func (t *winTray) create() error {
	hinst, _, _ := procGetModuleHandle.Call(0)
	name, err := windows.UTF16PtrFromString(className)
	if err != nil {
		return err
	}
	wc := wndClassEx{lpfnWndProc: wndProc, hInstance: hinst, lpszClassName: name}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	if a, _, e := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); a == 0 {
		return fmt.Errorf("RegisterClassEx: %w", e)
	}
	t.classOK = true
	// A top-level window that is never shown (not a message-only one): only
	// such windows get WM_QUERYENDSESSION and WM_ENDSESSION.
	title, _ := windows.UTF16PtrFromString("vpnsplit")
	h, _, e := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(title)),
		0, 0, 0, 0, 0, 0, 0, hinst, 0)
	if h == 0 {
		return fmt.Errorf("CreateWindowEx: %w", e)
	}
	t.hwnd.Store(h)
	// Close may have come while the window was being made (the start gave up
	// waiting): it saw no window to close, so the thread stops by itself.
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return errors.New("the tray was closed during the start")
	}
	tb, _ := windows.UTF16PtrFromString("TaskbarCreated")
	n, _, _ := procRegisterWindowMsg.Call(uintptr(unsafe.Pointer(tb)))
	t.taskbar = uint32(n)
	if t.taskbar != 0 {
		// An elevated process does not get messages of a lower level: the
		// explorer's TaskbarCreated is let through, this message only. A
		// failure keeps the retry of addIcon by timer as the fallback.
		procMsgFilterEx.Call(h, uintptr(t.taskbar), msgfltAllow, 0)
	}

	size, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	if size < 16 {
		size = 16
	}
	for i := range t.icons {
		t.icons[i], err = makeIcon(Icon(i), int(size))
		if err != nil {
			return err
		}
	}
	return t.addIcon()
}

// readd puts the icon back after the explorer was restarted. The notification
// area may not be ready at that moment: it tries again by timer, and if it never
// works the console window is shown again, so that the program is not left
// hidden with no icon.
func (t *winTray) readd() {
	t.addTries = 0
	if t.addIcon() == nil {
		return
	}
	procSetTimer.Call(t.hwnd.Load(), retryTimerID, retryTimerMs, 0)
}

func (t *winTray) retry() {
	t.addTries++
	if t.addIcon() == nil {
		procKillTimer.Call(t.hwnd.Load(), retryTimerID)
		return
	}
	if t.addTries >= maxAddRetries {
		procKillTimer.Call(t.hwnd.Load(), retryTimerID)
		t.iconOn = false
		ConsoleShow() // also clears "hidden"
	}
}

// data fills NOTIFYICONDATAW for the state.
func (t *winTray) data(s State) *notifyIconData {
	d := &notifyIconData{hWnd: t.hwnd.Load(), uID: iconID, uFlags: nifMessage | nifIcon | nifTip, uCallbackMessage: wmTray}
	d.cbSize = uint32(unsafe.Sizeof(*d))
	d.hIcon = t.icons[s.Icon()]
	tip := windows.StringToUTF16(s.Tooltip())
	copy(d.szTip[:len(d.szTip)-1], tip)
	return d
}

func notify(msg uint32, d *notifyIconData) bool {
	r, _, _ := procShellNotifyIcon.Call(uintptr(msg), uintptr(unsafe.Pointer(d)))
	return r != 0
}

// addIcon puts the icon (again, after the explorer was restarted) and asks for
// the behaviour of version 4: the events of the icon come in a fixed form.
func (t *winTray) addIcon() error {
	t.mu.Lock()
	s := t.want
	t.mu.Unlock()
	d := t.data(s)
	if !notify(nimAdd, d) {
		return errors.New("Shell_NotifyIcon(NIM_ADD) failed")
	}
	t.iconOn = true
	d.uVersion = notifyIconVersion4
	// a failure keeps version 0: the events still arrive, in the old form
	t.v4 = notify(nimSetVersion, d)
	return nil
}

func (t *winTray) deleteIcon() {
	d := &notifyIconData{hWnd: t.hwnd.Load(), uID: iconID}
	d.cbSize = uint32(unsafe.Sizeof(*d))
	notify(nimDelete, d)
}

// makeIcon builds an HICON of the state from the pixels drawn in Icon.Pixels.
func makeIcon(i Icon, size int) (uintptr, error) {
	px := i.Pixels(size)
	color, _, e := procCreateBitmap.Call(uintptr(size), uintptr(size), 1, 32, uintptr(unsafe.Pointer(&px[0])))
	if color == 0 {
		return 0, fmt.Errorf("CreateBitmap: %w", e)
	}
	defer procDeleteObject.Call(color)
	// the mask is not used by a 32-bit bitmap with alpha, but must be there
	mask := make([]byte, ((size+15)/16*2)*size)
	hm, _, e := procCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, uintptr(unsafe.Pointer(&mask[0])))
	if hm == 0 {
		return 0, fmt.Errorf("CreateBitmap(mask): %w", e)
	}
	defer procDeleteObject.Call(hm)
	ii := iconInfo{fIcon: 1, hbmMask: hm, hbmColor: color}
	h, _, e := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	if h == 0 {
		return 0, fmt.Errorf("CreateIconIndirect: %w", e)
	}
	return h, nil
}

// Update shows a new state. The icon is changed on the thread of the window.
func (t *winTray) Update(s State) {
	t.mu.Lock()
	if t.closed || t.want == s {
		t.mu.Unlock()
		return
	}
	t.want = s
	hwnd := t.hwnd.Load()
	t.mu.Unlock()
	if hwnd != 0 {
		procPostMessage.Call(hwnd, wmUpdate, 0, 0)
	}
}

// Close removes the icon at once from the calling goroutine (the thread of the
// window may be busy with WM_ENDSESSION) and stops the thread. It waits for the
// desktop only a moment.
func (t *winTray) Close() {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		done := make(chan struct{})
		go func() {
			defer close(done)
			t.deleteIcon()
		}()
		select {
		case <-done:
		case <-time.After(700 * time.Millisecond):
		}
		if h := t.hwnd.Load(); h != 0 {
			procPostMessage.Call(h, wmClose, 0, 0)
		}
		select {
		case <-t.exited:
		case <-time.After(300 * time.Millisecond):
		}
		t.forget()
	})
}

func loword(v uintptr) uint32 { return uint32(v) & 0xffff }

// wndProcMain is the procedure of the window.
func wndProcMain(hwnd, m, wp, lp uintptr) uintptr {
	currentMu.Lock()
	t := current
	currentMu.Unlock()
	if t == nil || t.hwnd.Load() != hwnd && t.hwnd.Load() != 0 {
		r, _, _ := procDefWindowProc.Call(hwnd, m, wp, lp)
		return r
	}
	defer func() {
		// a panic must not unwind through the callback of the system; it is
		// said on stderr (the type and the text of a runtime error only: no
		// data of the messages)
		if r := recover(); r != nil {
			reportPanic(r)
		}
	}()
	switch {
	case uint32(m) == wmTray:
		t.onIcon(wp, lp)
		return 0
	case uint32(m) == wmUpdate:
		t.refresh()
		return 0
	case t.taskbar != 0 && uint32(m) == t.taskbar:
		// the explorer was restarted: its notification area is empty again
		t.readd()
		return 0
	case uint32(m) == wmTimer && wp == retryTimerID:
		t.retry()
		return 0
	case uint32(m) == wmQueryEndSess:
		return 1 // do not hold the session back
	case uint32(m) == wmEndSession:
		if wp != 0 && t.cmds.EndSession != nil {
			// the process may be killed the moment this returns: the cleanup
			// (the same as for CTRL_SHUTDOWN) is waited for here
			t.cmds.EndSession()
		}
		return 0
	case uint32(m) == wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case uint32(m) == wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, m, wp, lp)
	return r
}

// refresh shows the wanted state: the picture and the tip.
func (t *winTray) refresh() {
	t.mu.Lock()
	s, closed := t.want, t.closed
	t.mu.Unlock()
	if closed {
		return
	}
	d := t.data(s)
	notify(nimModify, d)
}

// reportPanic says that the window procedure failed. Only what cannot carry
// the data of a message goes out.
func reportPanic(r any) {
	text := fmt.Sprintf("%T", r)
	if e, ok := r.(runtime.Error); ok {
		text += ": " + e.Error()
	}
	fmt.Fprintln(os.Stderr, "vpnsplit: ошибка в обработчике значка в трее:", text)
}

// iconRect is where the icon is on the screen now.
func (t *winTray) iconRect() (rect, bool) {
	id := notifyIconIdentifier{hWnd: t.hwnd.Load(), uID: iconID}
	id.cbSize = uint32(unsafe.Sizeof(id))
	var r struct{ left, top, right, bottom int32 }
	hr, _, _ := procIconGetRect.Call(uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&r)))
	if hr != 0 { // not S_OK
		return rect{}, false
	}
	return rect{r.left, r.top, r.right, r.bottom}, true
}

// onIcon handles an event of the icon: the menu on the right button, "show
// the window" on a double click or the key. The event is taken only if it is
// the real one (see iconEvent).
func (t *winTray) onIcon(wp, lp uintptr) {
	ev := loword(lp)
	var e iconEvent
	if t.v4 {
		// version 4: the event is in the low word of lParam, the id of the icon
		// in the high one, the anchor of a keyboard event in wParam
		e.idMatch = uint32(lp>>16)&0xffff == iconID
		e.anchor = point{int32(int16(wp & 0xffff)), int32(int16((wp >> 16) & 0xffff))}
		e.anchorOK = true
	} else {
		e.idMatch = uint32(wp) == iconID
	}
	switch ev {
	case wmRButtonUp, wmLButtonDblClk:
		e.kind = kindMouse
	case wmContextMenu:
		e.kind = kindContext
	case ninKeySelect:
		if !t.v4 {
			return
		}
		e.kind = kindKey
	default:
		return
	}
	if !e.idMatch {
		return
	}
	var pt point
	if r, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt))); r != 0 {
		e.cursor, e.cursorOK = pt, true
	}
	e.icon, e.iconOK = t.iconRect()
	if !e.accept() {
		return
	}
	switch ev {
	case wmContextMenu, wmRButtonUp:
		at := e.cursor
		if !e.cursorOK || !e.icon.contains(at) {
			at = e.anchor
		}
		t.popup(at)
	case wmLButtonDblClk, ninKeySelect:
		t.run(EvShow)
	}
}

// popup shows the menu at the point and runs the chosen command.
func (t *winTray) popup(at point) {
	t.mu.Lock()
	s := t.want
	t.mu.Unlock()
	s.CanHide = ConsoleCanHide()
	s.Hidden = ConsoleHidden()
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	items := Items(s)
	for _, it := range items {
		fl := uintptr(mfString)
		if !it.Enabled {
			fl |= mfGrayed
		}
		if it.Checked {
			fl |= mfChecked
		}
		if it.Event == EvQuit {
			procAppendMenu.Call(menu, mfSeparator, 0, 0)
		}
		lbl, _ := windows.UTF16PtrFromString(it.Label)
		procAppendMenu.Call(menu, fl, uintptr(it.Event), uintptr(unsafe.Pointer(lbl)))
	}
	hwnd := t.hwnd.Load()
	// without SetForegroundWindow the menu does not close when the user clicks elsewhere
	procSetForegroundWindow.Call(hwnd)
	shown := time.Now()
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmRightButton|tpmReturnCmd|tpmNoNotify,
		uintptr(at.x), uintptr(at.y), 0, hwnd, 0)
	procPostMessage.Call(hwnd, wmNull, 0, 0)
	if cmd != 0 && menuChoiceOK(shown, time.Now()) {
		t.run(Event(cmd))
	}
}

// run hands the command to the program on its own goroutine: the thread of the
// window never waits for the menu of the program.
func (t *winTray) run(e Event) {
	lifecycle.SafeGo(func() { t.cmds.Dispatch(e) }, nil)
}
