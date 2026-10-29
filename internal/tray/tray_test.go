package tray

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func env(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

func TestStateIcon(t *testing.T) {
	cases := []struct {
		s    State
		want Icon
	}{
		{State{}, IconOff},
		{State{On: true}, IconOn},
		{State{Danger: true}, IconDanger},
		{State{On: true, Danger: true}, IconDanger},
	}
	for _, c := range cases {
		if got := c.s.Icon(); got != c.want {
			t.Errorf("%+v: icon %v, want %v", c.s, got, c.want)
		}
	}
}

func TestTooltip(t *testing.T) {
	if got := (State{On: true}).Tooltip(); !strings.Contains(got, "включено") {
		t.Errorf("on: %q", got)
	}
	if got := (State{}).Tooltip(); !strings.Contains(got, "выключено") {
		t.Errorf("off: %q", got)
	}
	d := State{On: true, Danger: true, Code: "GPO_NRPT"}.Tooltip()
	if !strings.Contains(d, "GPO_NRPT") || !strings.Contains(d, "Внимание") {
		t.Errorf("danger: %q", d)
	}
	long := State{Danger: true, Code: strings.Repeat("X", 400)}.Tooltip()
	if utf8.RuneCountInString(long) > maxTip {
		t.Errorf("the tooltip does not fit szTip: %d runes", utf8.RuneCountInString(long))
	}
}

func TestItems(t *testing.T) {
	on := Items(State{On: true, CanHide: true})
	if len(on) != 3 || on[0].Event != EvToggle || on[1].Event != EvShow || on[2].Event != EvQuit {
		t.Fatalf("%+v", on)
	}
	if !on[0].Checked || !on[1].Enabled || !on[2].Enabled {
		t.Errorf("%+v", on)
	}
	off := Items(State{})
	if off[0].Checked || off[1].Enabled {
		t.Errorf("no console to hide: the item must be grey; %+v", off)
	}
	if on[0].Label == off[0].Label {
		t.Error("the label of the switch must say what a click does")
	}
}

func TestDispatch(t *testing.T) {
	var got []string
	c := Commands{
		Toggle: func() { got = append(got, "toggle") },
		Show:   func() { got = append(got, "show") },
		Quit:   func() { got = append(got, "quit") },
	}
	for _, e := range []Event{EvToggle, EvShow, EvQuit} {
		if !c.Dispatch(e) {
			t.Errorf("event %v has no command", e)
		}
	}
	if strings.Join(got, ",") != "toggle,show,quit" {
		t.Errorf("%v", got)
	}
	if c.Dispatch(Event(99)) || (Commands{}).Dispatch(EvQuit) {
		t.Error("an unknown event or a missing command must do nothing")
	}
}

func TestDisabled(t *testing.T) {
	cases := []struct {
		name string
		s    Settings
		env  func(string) string
		off  bool
	}{
		{"plain", Settings{}, env(), false},
		{"flag", Settings{NoTray: true}, env(), true},
		{"env", Settings{}, env("VPNSPLIT_NO_TRAY", "1"), true},
		{"env zero", Settings{}, env("VPNSPLIT_NO_TRAY", "0"), false},
		{"ssh connection", Settings{}, env("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22"), true},
		{"ssh client", Settings{}, env("SSH_CLIENT", "1.2.3.4 1 22"), true},
		{"ssh tty", Settings{}, env("SSH_TTY", "/dev/pts/1"), true},
	}
	for _, c := range cases {
		if got := Disabled(c.s, c.env); (got != "") != c.off {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

func TestConsoleEligible(t *testing.T) {
	none := env()
	if !ConsoleEligible(1, true, true, none) {
		t.Error("the classic console of its own is eligible")
	}
	if ConsoleEligible(2, true, true, none) {
		t.Error("another process on the console: its window must stay")
	}
	if ConsoleEligible(1, false, true, none) {
		t.Error("not the classic host")
	}
	if ConsoleEligible(1, true, false, none) {
		t.Error("the window is not visible already")
	}
	for _, k := range []string{"WT_SESSION", "TERM_PROGRAM", "ConEmuPID", "TMUX"} {
		if ConsoleEligible(1, true, true, env(k, "x")) {
			t.Errorf("%s set: a terminal that is not the console host", k)
		}
	}
}

func TestIconPixels(t *testing.T) {
	const n = 16
	for _, i := range []Icon{IconOff, IconOn, IconDanger} {
		px := i.Pixels(n)
		if len(px) != n*n*4 {
			t.Fatalf("size %d", len(px))
		}
		if px[3] != 0 {
			t.Errorf("icon %v: the corner must be transparent", i)
		}
		c := ((n/2)*n + n/2) * 4
		if px[c+3] != 255 {
			t.Errorf("icon %v: the centre must be opaque", i)
		}
	}
	a, b := IconOn.Pixels(n), IconDanger.Pixels(n)
	c := ((n/2)*n + n/2) * 4
	if a[c] == b[c] && a[c+1] == b[c+1] && a[c+2] == b[c+2] {
		t.Error("the states must differ in colour")
	}
}
