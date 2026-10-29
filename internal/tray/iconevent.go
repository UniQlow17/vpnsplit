package tray

import "time"

// Who may drive the menu of the icon. The callback message of the icon is an
// ordinary window message: any process of the same user and level can post one
// to the hidden window, and a menu popping up under a click meant for something
// else (or a "Выход" the user never chose) is clickjacking. So an event counts
// only when it is the one of our icon, the pointer (or, for the keyboard, the
// anchor the shell gives) is on the icon, and the item is not chosen before the
// user could have seen the menu. Pure functions: tested without a desktop.

type point struct{ x, y int32 }

// rect is a RECT of the screen: Left/Top are inside, Right/Bottom are not.
type rect struct{ left, top, right, bottom int32 }

func (r rect) contains(p point) bool {
	return p.x >= r.left && p.x < r.right && p.y >= r.top && p.y < r.bottom
}

// iconKind is how an event of the icon is delivered.
type iconKind int

const (
	kindMouse   iconKind = iota // right button up, double click: the pointer is on the icon
	kindContext                 // WM_CONTEXTMENU: by the mouse or by the keyboard (the anchor is in wParam)
	kindKey                     // NIN_KEYSELECT: the keyboard only, the anchor is in wParam
)

// iconEvent is what the callback message says, with the facts about the screen.
type iconEvent struct {
	idMatch  bool // the id of the message is the id of our icon
	kind     iconKind
	cursor   point
	cursorOK bool
	anchor   point // version 4: the point the shell gives for a keyboard event
	anchorOK bool
	icon     rect // Shell_NotifyIconGetRect
	iconOK   bool
}

// accept: the event is a real one. Without the rectangle of the icon nothing
// can be checked, and it is refused (the console window is always there).
func (e iconEvent) accept() bool {
	if !e.idMatch || !e.iconOK {
		return false
	}
	onIcon := func(p point, ok bool) bool { return ok && e.icon.contains(p) }
	switch e.kind {
	case kindMouse:
		return onIcon(e.cursor, e.cursorOK)
	case kindContext:
		return onIcon(e.cursor, e.cursorOK) || onIcon(e.anchor, e.anchorOK)
	case kindKey:
		return onIcon(e.anchor, e.anchorOK)
	}
	return false
}

// minMenuTime is how long after the menu appeared a choice may be taken: an
// item "chosen" sooner was not chosen by a person who read it.
const minMenuTime = 300 * time.Millisecond

func menuChoiceOK(shown, chosen time.Time) bool { return chosen.Sub(shown) >= minMenuTime }
