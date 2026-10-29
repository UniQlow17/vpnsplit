package termsize

import "testing"

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func TestDetect(t *testing.T) {
	for _, c := range []struct {
		name string
		goos string
		env  map[string]string
		want Method
	}{
		{"conhost", "windows", nil, Console},
		{"windows vscode", "windows", map[string]string{"TERM_PROGRAM": "vscode"}, Hint},
		{"windows git bash", "windows", map[string]string{"TERM": "xterm-256color"}, Hint},
		{"windows terminal", "windows", map[string]string{"WT_SESSION": "x"}, Hint},
		{"tmux over xterm", "linux", map[string]string{"TMUX": "/tmp/t,1,0", "XTERM_VERSION": "XTerm(380)"}, Hint},
		{"screen", "linux", map[string]string{"STY": "1.pts"}, Hint},
		{"xterm", "linux", map[string]string{"XTERM_VERSION": "XTerm(380)"}, CSI},
		{"iterm", "darwin", map[string]string{"TERM_PROGRAM": "iTerm.app"}, CSI},
		{"terminal.app", "darwin", map[string]string{"TERM_PROGRAM": "Apple_Terminal"}, CSI},
		{"vte", "linux", map[string]string{"VTE_VERSION": "7600", "TERM_PROGRAM": "iTerm.app"}, Hint},
		{"konsole", "linux", map[string]string{"KONSOLE_VERSION": "230800"}, Hint},
		{"unknown", "linux", map[string]string{"TERM": "linux"}, Hint},
		{"vscode", "darwin", map[string]string{"TERM_PROGRAM": "vscode"}, Hint},
	} {
		if got := Detect(c.goos, env(c.env)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestResizeSeq(t *testing.T) {
	if got := resizeSeq(Size{Cols: 100, Rows: 30}); got != "\x1b[8;30;100t" {
		t.Errorf("got %q", got)
	}
}

func TestFits(t *testing.T) {
	want := Size{80, 30}
	if !(Size{80, 30}).Fits(want) || !(Size{120, 40}).Fits(want) || (Size{79, 30}).Fits(want) || (Size{80, 29}).Fits(want) {
		t.Error("Fits")
	}
}

func TestOnce(t *testing.T) {
	n := 0
	f := once(func() { n++ })
	f()
	f()
	if n != 1 {
		t.Errorf("ran %d times", n)
	}
}

// A hint-only terminal is never touched, and Restore is always safe to call.
func TestFitHint(t *testing.T) {
	r := fit(Size{80, 30}, nil, Hint)
	if r.Resized || r.Restore == nil {
		t.Fatalf("%+v", r)
	}
	r.Restore()
}
