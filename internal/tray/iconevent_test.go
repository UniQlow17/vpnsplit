package tray

import (
	"testing"
	"time"
)

func TestIconEventAccept(t *testing.T) {
	r := rect{100, 200, 116, 216}
	in, out := point{105, 205}, point{500, 500}
	base := iconEvent{idMatch: true, icon: r, iconOK: true}
	with := func(f func(*iconEvent)) iconEvent { e := base; f(&e); return e }
	cases := []struct {
		name string
		e    iconEvent
		want bool
	}{
		{"mouse on the icon", with(func(e *iconEvent) { e.kind, e.cursor, e.cursorOK = kindMouse, in, true }), true},
		{"mouse elsewhere", with(func(e *iconEvent) { e.kind, e.cursor, e.cursorOK = kindMouse, out, true }), false},
		{"mouse, no cursor", with(func(e *iconEvent) { e.kind = kindMouse }), false},
		{"mouse: an anchor does not count", with(func(e *iconEvent) {
			e.kind, e.cursor, e.cursorOK, e.anchor, e.anchorOK = kindMouse, out, true, in, true
		}), false},
		{"context by the mouse", with(func(e *iconEvent) { e.kind, e.cursor, e.cursorOK = kindContext, in, true }), true},
		{"context by the keyboard", with(func(e *iconEvent) {
			e.kind, e.cursor, e.cursorOK, e.anchor, e.anchorOK = kindContext, out, true, in, true
		}), true},
		{"context, both elsewhere", with(func(e *iconEvent) {
			e.kind, e.cursor, e.cursorOK, e.anchor, e.anchorOK = kindContext, out, true, out, true
		}), false},
		{"key on the anchor", with(func(e *iconEvent) { e.kind, e.anchor, e.anchorOK = kindKey, in, true }), true},
		{"key: the cursor does not count", with(func(e *iconEvent) { e.kind, e.cursor, e.cursorOK = kindKey, in, true }), false},
		{"edge: right/bottom are outside", with(func(e *iconEvent) { e.kind, e.cursor, e.cursorOK = kindMouse, point{116, 205}, true }), false},
		{"edge: left/top are inside", with(func(e *iconEvent) { e.kind, e.cursor, e.cursorOK = kindMouse, point{100, 200}, true }), true},
		{"foreign icon id", with(func(e *iconEvent) { e.idMatch, e.kind, e.cursor, e.cursorOK = false, kindMouse, in, true }), false},
		{"no rectangle: refused", with(func(e *iconEvent) { e.iconOK, e.kind, e.cursor, e.cursorOK = false, kindMouse, in, true }), false},
	}
	for _, c := range cases {
		if got := c.e.accept(); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMenuChoiceNeedsTime(t *testing.T) {
	t0 := time.Now()
	if menuChoiceOK(t0, t0.Add(50*time.Millisecond)) {
		t.Error("a choice 50 ms after the menu appeared is not taken")
	}
	if !menuChoiceOK(t0, t0.Add(minMenuTime)) || !menuChoiceOK(t0, t0.Add(2*time.Second)) {
		t.Error("a later choice is taken")
	}
}
