package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNormalizePath(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"plain", `C:\Users\me\rules.txt`, `C:\Users\me\rules.txt`},
		{"empty", ``, ``},
		{"only spaces and breaks", " \r\n\t \n", ``},
		{"spaces around", `   C:\a\b.txt   `, `C:\a\b.txt`},
		{"double quotes (Copy as path)", `"C:\Users\me\rules.txt"`, `C:\Users\me\rules.txt`},
		{"single quotes", `'C:\Users\me\rules.txt'`, `C:\Users\me\rules.txt`},
		{"quotes with spaces inside path", `"C:\Program Files\my rules.txt"`, `C:\Program Files\my rules.txt`},
		{"unquoted path with spaces", `C:\Program Files\my rules.txt`, `C:\Program Files\my rules.txt`},
		{"CRLF at the end", "C:\\a.txt\r\n", `C:\a.txt`},
		{"LF at the end", "C:\\a.txt\n", `C:\a.txt`},
		{"bare CR", "C:\\a.txt\r", `C:\a.txt`},
		{"quoted with CRLF", "\"C:\\a b.txt\"\r\n", `C:\a b.txt`},
		{"quoted with spaces inside quotes", `" C:\a.txt "`, `C:\a.txt`},
		{"multiline takes the first line", "C:\\first.txt\r\nC:\\second.txt\r\n", `C:\first.txt`},
		{"multiline skips blank lines", "\r\n\r\n  \"C:\\first.txt\"  \r\nC:\\second.txt", `C:\first.txt`},
		{"unix path", "/home/me/rules.txt\n", "/home/me/rules.txt"},
		{"home path", "~/Downloads/x.txt", "~/Downloads/x.txt"},
		{"cyrillic", "\"C:\\Users\\Алексей\\правила.txt\"", `C:\Users\Алексей\правила.txt`},
		{"nested quote kinds", `"'C:\a.txt'"`, `C:\a.txt`},
		{"lone leading quote", `"C:\a.txt`, `C:\a.txt`},
		{"lone trailing quote", `C:\a.txt"`, `C:\a.txt`},
		{"lone leading single quote", `'C:\a.txt`, `C:\a.txt`},
		{"lone trailing single quote", `C:\a.txt'`, `C:\a.txt`},
		{"apostrophe inside is kept", `C:\it's\a.txt`, `C:\it's\a.txt`},
		{"two apostrophes inside are kept", `C:\it's\bob's.txt`, `C:\it's\bob's.txt`},
		{"BOM and zero width", "\ufeff\"C:\\a.txt\"\u200b", `C:\a.txt`},
		{"bidi mark from Explorer", "\u202aC:\\a.txt", `C:\a.txt`},
		{"bidi marks around quotes", "\u202a\"C:\\a.txt\"\u202c", `C:\a.txt`},
		{"NUL", "C:\\a.txt\x00", `C:\a.txt`},
		{"one double quote", `"`, ``},
		{"one single quote", `'`, ``},
		{"empty double quotes", `""`, ``},
		{"empty single quotes", `''`, ``},
		{"quote closed in the middle", `"C:\a"b`, `"C:\a"b`},
		{"UNC", `\\srv\share\a.txt`, `\\srv\share\a.txt`},
		{"UNC quoted", `"\\srv\share\a.txt"`, `\\srv\share\a.txt`},
	} {
		if got := normalizePath(c.in); got != c.want {
			t.Errorf("%s: normalizePath(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// isFullPath must not depend on the OS the tests run on.
func TestIsFullPath(t *testing.T) {
	for in, want := range map[string]bool{
		`C:\x\r.txt`: true, `c:\x`: true, `Z:/x`: true, `\\srv\share\a.txt`: true,
		"/etc/hosts": true, "~/Desktop/r.txt": true, `~\Desktop\r.txt`: true,
		"": false, "rules.txt": false, `x\y.txt`: false, "C:": false, `C:x`: false,
		`1:\x`: false, "./a.txt": false, `\x`: false,
	} {
		if got := isFullPath(in); got != want {
			t.Errorf("isFullPath(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestResolvePathDropsUntouchedDefault(t *testing.T) {
	const def = "~/Downloads/"
	for in, want := range map[string]string{
		def:                         "~/Downloads/",
		def + "rules.txt":           "~/Downloads/rules.txt",
		def + `"C:\x\r.txt"`:        `C:\x\r.txt`,
		def + `C:\x\r.txt`:          `C:\x\r.txt`,
		def + `\\srv\share\a.txt`:   `\\srv\share\a.txt`,
		`"` + def + `rules.txt"`:    "~/Downloads/rules.txt",
		def + "~/Desktop/r.txt\r\n": "~/Desktop/r.txt",
		"/etc/hosts":                "/etc/hosts",
	} {
		if got := resolvePath(in, def); got != want {
			t.Errorf("resolvePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func importModel(def string) model {
	m := testModel()
	m.sc = scRules
	m.beginInput("import", def, "Файл: ")
	return m
}

func send(m model, msgs ...tea.Msg) model {
	for _, msg := range msgs {
		got, _ := m.Update(msg)
		m = got.(model)
	}
	return m
}

var enter = tea.KeyMsg{Type: tea.KeyEnter}

// fakeClock is the time of the model in tests: it moves only when told to.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// streamModel is a model with the key-stream paste heuristic switched on
// explicitly (it is on by default only on Windows) and a fake clock.
func streamModel(purpose, def string) (model, *fakeClock) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	m := testModel()
	m.streamPaste, m.now = true, c.Now
	m.sc = scRules
	m.beginInput(purpose, def, "Ввод: ")
	return m, c
}

// feed sends msgs one by one, gap apart.
func feed(m model, c *fakeClock, gap time.Duration, msgs ...tea.Msg) model {
	for _, msg := range msgs {
		c.advance(gap)
		m = send(m, msg)
	}
	return m
}

// A paste on Windows is a stream of key events with Enter inside: it must
// neither submit early nor let the following lines leak into the path.
func TestPasteStreamDoesNotSubmit(t *testing.T) {
	const gap = time.Millisecond
	paste := func() (model, *fakeClock, *[]string) {
		m, c := streamModel("import", "")
		var opened []string
		m.readFile = func(p string) ([]byte, error) {
			opened = append(opened, p)
			return nil, errors.New("test")
		}
		m = feed(m, c, gap,
			keyMsg(`"C:\no\such`), keyMsg(` dir\a.txt"`),
			enter, // CR of the pasted text
			keyMsg(`C:\second.txt`),
			enter,
		)
		return m, c, &opened
	}

	m, _, _ := paste()
	if !m.inputting {
		t.Fatal("Enter inside a pasted block submitted the input")
	}
	if got := resolvePath(m.input.Value(), m.inputDef); got != `C:\no\such dir\a.txt` {
		t.Fatalf("path after paste = %q", got)
	}
	if m.flash != flashPasted {
		t.Errorf("flash after a swallowed Enter = %q", m.flash)
	}

	// 39 ms after the previous key is still the paste
	m, c, opened := paste()
	c.advance(pasteBurst - time.Millisecond)
	m = send(m, enter)
	if !m.inputting || len(*opened) != 0 {
		t.Fatal("Enter 39 ms after the previous key must still be part of the paste")
	}

	// 40 ms is a deliberate Enter: it submits, without the quotes
	m, c, opened = paste()
	c.advance(pasteBurst)
	m = send(m, enter)
	if m.inputting {
		t.Fatal("Enter 40 ms after the previous key must submit")
	}
	if len(*opened) != 1 || (*opened)[0] != `C:\no\such dir\a.txt` {
		t.Fatalf("file opened: %q", *opened)
	}
}

// A pasted block that starts with blank lines: they are skipped, the first
// non-blank line is taken and the rest dropped, same as firstLine.
func TestPasteStreamLeadingBlankLines(t *testing.T) {
	const gap = time.Millisecond
	m, c := streamModel("import", "")
	m = feed(m, c, gap, enter, enter, keyMsg(`C:\first.txt`), enter, keyMsg(`C:\second.txt`), enter, keyMsg(`C:\third.txt`))
	if !m.inputting {
		t.Fatal("the paste submitted the input")
	}
	if got := m.input.Value(); got != `C:\first.txt` {
		t.Fatalf("input = %q, want the first non-blank line only", got)
	}
	// the same text through the clipboard gives the same result
	m = importModel("")
	m = send(m, clipMsg{gen: m.inputGen, text: "\r\n\r\nC:\\first.txt\r\nC:\\second.txt"})
	if got := m.input.Value(); got != `C:\first.txt` {
		t.Fatalf("clipboard input = %q", got)
	}
	// a space-only line is blank too
	m, c = streamModel("import", "")
	m = feed(m, c, gap, keyMsg(" "), enter, keyMsg(`C:\first.txt`))
	if got := strings.TrimSpace(m.input.Value()); got != `C:\first.txt` {
		t.Fatalf("input = %q", got)
	}
}

func TestPasteStreamNonPathFieldsSayFirstLineOnly(t *testing.T) {
	m, c := streamModel("rule", "")
	m = feed(m, c, time.Millisecond, keyMsg("a.example.com"), enter, keyMsg("b.example.com"), enter)
	if got := m.input.Value(); got != "a.example.com" {
		t.Fatalf("input = %q", got)
	}
	if m.flash != flashFirstLineOnly {
		t.Errorf("flash = %q", m.flash)
	}
	// clipboard
	m = testModel()
	m.beginInput("rule", "", "x")
	m = send(m, clipMsg{gen: m.inputGen, text: "a.example.com\nb.example.com"})
	if m.input.Value() != "a.example.com" || m.flash != flashFirstLineOnly {
		t.Errorf("clipboard: input %q, flash %q", m.input.Value(), m.flash)
	}
}

// Without the heuristic (every OS but Windows) a fast Enter is an Enter: ssh,
// tmux and scripted input must keep working.
func TestFastEnterSubmitsWithoutStreamPaste(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	m := testModel()
	if m.streamPaste {
		t.Fatal("the heuristic must be off by default in a bare model")
	}
	m.now = c.Now
	m.sc = scRules
	m.beginInput("import", "", "x")
	var opened string
	m.readFile = func(p string) ([]byte, error) { opened = p; return nil, errors.New("test") }
	m = send(m, keyMsg(`C:\a.txt`), enter) // no time passes at all
	if m.inputting || opened != `C:\a.txt` {
		t.Fatalf("Enter must submit at once: inputting=%v opened=%q", m.inputting, opened)
	}
}

// Esc and a new input forget the state of a half-dropped paste.
func TestPasteStateIsResetByEscAndNewInput(t *testing.T) {
	m, c := streamModel("rule", "")
	m = feed(m, c, time.Millisecond, keyMsg("a.example.com"), enter)
	if !m.skipRest || !m.burstText {
		t.Fatal("the paste state must be set after a swallowed Enter")
	}
	gen := m.inputGen
	m = send(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.inputting || m.skipRest || m.burstText || m.inputGen == gen {
		t.Fatalf("esc: inputting=%v skipRest=%v burstText=%v gen %d->%d", m.inputting, m.skipRest, m.burstText, gen, m.inputGen)
	}
	// new input starts clean: the first key is typed, not dropped
	m.skipRest, m.burstText = true, true
	m.beginInput("rule", "", "x")
	if m.skipRest || m.burstText {
		t.Fatal("a new input must start without paste state")
	}
	c.advance(time.Second)
	m = send(m, keyMsg("b"))
	if m.input.Value() != "b" {
		t.Fatalf("input = %q", m.input.Value())
	}
}

func TestPasteMsgAndClipboard(t *testing.T) {
	// bracketed paste
	m := importModel("~/Downloads/")
	m = send(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("\"C:\\a b\\r.txt\"\r\n"), Paste: true})
	if got := m.input.Value(); got != `C:\a b\r.txt` {
		t.Errorf("bracketed paste over the default: %q", got)
	}
	if !m.inputting {
		t.Error("bracketed paste must not submit")
	}
	// clipboard after ctrl+v: multi-line text, first line only
	m = importModel("")
	m = send(m, clipMsg{gen: m.inputGen, text: "'C:\\x y\\r.txt'\r\nC:\\other.txt\r\n"})
	if got := m.input.Value(); got != `C:\x y\r.txt` {
		t.Errorf("clipboard paste: %q", got)
	}
	// into the middle of existing text
	m = importModel("")
	m = send(m, keyMsg("ab"), tea.KeyMsg{Type: tea.KeyLeft}, clipMsg{gen: m.inputGen, text: "XY\n"})
	if got := m.input.Value(); got != "aXYb" {
		t.Errorf("paste at the cursor: %q", got)
	}
	// ctrl+v asks for the clipboard
	m = importModel("")
	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlV}); cmd == nil {
		t.Error("ctrl+v must read the clipboard")
	}
	// a clipboard error is shown, the input stays as it was
	m = importModel("")
	m = send(m, clipMsg{gen: m.inputGen, err: errors.New("boom")})
	if !m.inputting || m.input.Value() != "" || !strings.Contains(m.flash, "boom") {
		t.Errorf("clipboard error: inputting=%v value=%q flash=%q", m.inputting, m.input.Value(), m.flash)
	}
}

func TestClipboardAnswerForNoInputIsIgnored(t *testing.T) {
	// the input is closed
	m := importModel("~/Downloads/")
	m.inputting = false
	got := send(m, clipMsg{gen: m.inputGen, text: "x"})
	if got.inputting || got.input.Value() != "~/Downloads/" {
		t.Errorf("closed input: inputting=%v value=%q", got.inputting, got.input.Value())
	}
	// the answer of an input closed by esc must not land in the next one
	m = importModel("")
	oldGen := m.inputGen
	m = send(m, tea.KeyMsg{Type: tea.KeyEsc})
	m.beginInput("rule", "", "x")
	m = send(m, clipMsg{gen: oldGen, text: "stale.example.com"})
	if m.input.Value() != "" {
		t.Errorf("a late clipboard answer leaked into another field: %q", m.input.Value())
	}
	m = send(m, clipMsg{gen: m.inputGen, text: "fresh.example.com"})
	if m.input.Value() != "fresh.example.com" {
		t.Errorf("answer of the current input: %q", m.input.Value())
	}
}

func TestLongPathIsNotCut(t *testing.T) {
	m := importModel("")
	long := `C:\` + strings.Repeat("d", 300) + `\f.txt`
	m = send(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(`"` + long + `"`), Paste: true})
	if got := resolvePath(m.input.Value(), ""); got != long {
		t.Errorf("long path cut: %d of %d runes", len(got), len(long))
	}
}
