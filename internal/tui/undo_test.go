package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	ctrlZ = tea.KeyMsg{Type: tea.KeyCtrlZ}
	ctrlY = tea.KeyMsg{Type: tea.KeyCtrlY}
	bksp  = tea.KeyMsg{Type: tea.KeyBackspace}
)

// typeKeys sends every rune of s as its own key, gap apart.
func typeKeys(m model, c *fakeClock, gap time.Duration, s string) model {
	for _, r := range s {
		m = feed(m, c, gap, keyMsg(string(r)))
	}
	return m
}

func wantValue(t *testing.T, m model, want string) {
	t.Helper()
	if got := m.input.Value(); got != want {
		t.Fatalf("input = %q, want %q", got, want)
	}
}

// Bracketed paste: the whole paste is one undo step.
func TestUndoPasteMsg(t *testing.T) {
	m := importModel("")
	m = send(m, keyMsg("ab"))
	m = send(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(`"C:\a b\r.txt"` + "\r\n"), Paste: true})
	wantValue(t, m, `abC:\a b\r.txt`)
	m = send(m, ctrlZ)
	wantValue(t, m, "ab")
	m = send(m, ctrlY)
	wantValue(t, m, `abC:\a b\r.txt`)
}

// Clipboard (ctrl+v): one step, also when it replaces the prefilled default.
func TestUndoClipboard(t *testing.T) {
	m := importModel("~/Downloads/")
	m = send(m, clipMsg{gen: m.inputGen, text: `"C:\x\r.txt"`})
	wantValue(t, m, `C:\x\r.txt`)
	m = send(m, ctrlZ)
	wantValue(t, m, "~/Downloads/")
	if m.input.Position() != len("~/Downloads/") {
		t.Errorf("cursor after undo = %d", m.input.Position())
	}
	m = send(m, ctrlZ) // nothing more to undo
	wantValue(t, m, "~/Downloads/")
}

// A key-stream paste (Windows): one step, even glued to words typed just before.
func TestUndoStreamPaste(t *testing.T) {
	const gap = time.Millisecond
	m, c := streamModel("import", "")
	m = typeKeys(m, c, 100*time.Millisecond, "hello") // typed by hand
	m = feed(m, c, 100*time.Millisecond, keyMsg(`C:\a`))
	m = feed(m, c, gap, keyMsg(`\b b`), keyMsg(`\c.txt`), enter, keyMsg("second"))
	wantValue(t, m, `helloC:\a\b b\c.txt`)
	m = send(m, ctrlZ)
	wantValue(t, m, "hello")
	m = send(m, ctrlZ)
	wantValue(t, m, "")
	m = send(m, ctrlY, ctrlY)
	wantValue(t, m, `helloC:\a\b b\c.txt`)

	// a stream with no typing before it
	m, c = streamModel("import", "")
	m = feed(m, c, gap, keyMsg("a"), keyMsg("b"), keyMsg("c"))
	m = send(m, ctrlZ)
	wantValue(t, m, "")
	m = send(m, ctrlZ)
	wantValue(t, m, "")
}

// Typing after a pause is a new step even in a stream-paste model.
func TestUndoStreamModelTypingGroups(t *testing.T) {
	m, c := streamModel("rule", "")
	m = typeKeys(m, c, 100*time.Millisecond, "ab")
	c.advance(2 * time.Second)
	m = typeKeys(m, c, 100*time.Millisecond, "cd")
	m = send(m, ctrlZ)
	wantValue(t, m, "ab")
	m = send(m, ctrlZ)
	wantValue(t, m, "")
}

func TestUndoTypingGroupsByWord(t *testing.T) {
	m, c := streamModel("rule", "")
	m = typeKeys(m, c, 100*time.Millisecond, "foo bar baz")
	for _, want := range []string{"foo bar ", "foo ", "", ""} {
		m = send(m, ctrlZ)
		wantValue(t, m, want)
	}
	// redo walks forward the same way
	for _, want := range []string{"foo ", "foo bar ", "foo bar baz", "foo bar baz"} {
		m = send(m, ctrlY)
		wantValue(t, m, want)
	}
}

func TestUndoGroupsByKindPauseAndCursor(t *testing.T) {
	m, c := streamModel("rule", "")
	m = typeKeys(m, c, 100*time.Millisecond, "abcd")
	m = feed(m, c, 100*time.Millisecond, bksp, bksp) // delete is a group of its own
	wantValue(t, m, "ab")
	m = typeKeys(m, c, 100*time.Millisecond, "xy")
	wantValue(t, m, "abxy")
	// a cursor move closes the group
	m = feed(m, c, 100*time.Millisecond, tea.KeyMsg{Type: tea.KeyLeft})
	m = typeKeys(m, c, 100*time.Millisecond, "Q")
	wantValue(t, m, "abxQy")
	m = send(m, ctrlZ)
	wantValue(t, m, "abxy")
	if m.input.Position() != 3 {
		t.Errorf("cursor after undo = %d, want 3", m.input.Position())
	}
	m = send(m, ctrlZ)
	wantValue(t, m, "ab") // "xy" together
	m = send(m, ctrlZ)
	wantValue(t, m, "abcd") // the deletion
	m = send(m, ctrlZ)
	wantValue(t, m, "")
}

func TestUndoDeleteGroupsByWord(t *testing.T) {
	m := importModel("")
	m = send(m, clipMsg{gen: m.inputGen, text: "ab cd"}) // one step
	m = send(m, ctrlZ)
	wantValue(t, m, "")
	m = send(m, ctrlY)
	wantValue(t, m, "ab cd")
	for i := 0; i < 4; i++ {
		m = send(m, bksp) // "cd", then the space
	}
	wantValue(t, m, "a")
	for _, want := range []string{"ab", "ab ", "ab cd"} { // b, the space, then "cd"
		m = send(m, ctrlZ)
		wantValue(t, m, want)
	}
}

func TestRedoClearedByNewAction(t *testing.T) {
	m, c := streamModel("rule", "")
	m = typeKeys(m, c, 100*time.Millisecond, "ab")
	m = send(m, ctrlZ)
	wantValue(t, m, "")
	m = typeKeys(m, c, 100*time.Millisecond, "z")
	m = send(m, ctrlY)
	wantValue(t, m, "z") // nothing to redo
	// a paste clears redo too
	m = send(m, ctrlZ)
	m = send(m, clipMsg{gen: m.inputGen, text: "p"})
	m = send(m, ctrlY)
	wantValue(t, m, "p")
}

func TestUndoDepthLimit(t *testing.T) {
	m := importModel("")
	for i := 0; i < undoDepth+50; i++ {
		m = send(m, clipMsg{gen: m.inputGen, text: "x"}) // every paste is a step
	}
	n := 0
	for ; n < undoDepth+60; n++ {
		before := m.input.Value()
		m = send(m, ctrlZ)
		if m.input.Value() == before {
			break
		}
	}
	if n != undoDepth {
		t.Errorf("undone %d steps, want %d", n, undoDepth)
	}
}

func TestUndoEmptyHistoryDoesNotPanic(t *testing.T) {
	m := importModel("~/Downloads/")
	m = send(m, ctrlZ, ctrlY, ctrlZ)
	wantValue(t, m, "~/Downloads/")
	if !m.inputting {
		t.Error("ctrl+z must not close the input")
	}
	// a model that never began an input
	mm := testModel()
	mm.inputting = true
	mm.undoInput()
	mm.redoInput()
}

func TestUndoResetByEscAndNewInput(t *testing.T) {
	m := importModel("")
	m = send(m, keyMsg("abc"))
	m = send(m, tea.KeyMsg{Type: tea.KeyEsc})
	if len(m.hist.undo) != 0 || len(m.hist.redo) != 0 {
		t.Fatal("esc must drop the history")
	}
	m.beginInput("rule", "", "x")
	m = send(m, ctrlZ)
	wantValue(t, m, "") // the old "abc" is gone
	m = send(m, keyMsg("q"), ctrlZ)
	m.beginInput("rule", "dflt", "x")
	if len(m.hist.undo) != 0 || len(m.hist.redo) != 0 {
		t.Fatal("a new input must start with an empty history")
	}
}

// A clipboard answer dropped by generation leaves no undo step.
func TestUndoStaleClipboardLeavesNoStep(t *testing.T) {
	m := importModel("")
	old := m.inputGen
	m = send(m, tea.KeyMsg{Type: tea.KeyEsc})
	m.beginInput("rule", "", "x")
	m = send(m, clipMsg{gen: old, text: "stale"})
	if len(m.hist.undo) != 0 {
		t.Fatal("a stale paste must not enter the history")
	}
	m = send(m, keyMsg("a"), ctrlZ)
	wantValue(t, m, "")
}

// An empty paste or a clipboard error is not a step.
func TestUndoNoStepWithoutChange(t *testing.T) {
	m := importModel("")
	m = send(m, clipMsg{gen: m.inputGen, text: " \n "})
	if len(m.hist.undo) != 0 {
		t.Fatal("an empty paste must not be a step")
	}
}

// Ctrl+z / ctrl+y outside an input do nothing, and the input is not entered.
func TestCtrlZOutsideInputIsHarmless(t *testing.T) {
	for _, sc := range []screen{scMenu, scRules, scPick, scSettings, scStatus, scBusy} {
		m := testModel()
		m.sc, m.cursor = sc, 1
		got, cmd := m.Update(ctrlZ)
		mm := got.(model)
		if cmd != nil || mm.sc != sc || mm.inputting {
			t.Errorf("screen %d: ctrl+z changed state: sc=%d inputting=%v cmd=%v", sc, mm.sc, mm.inputting, cmd)
		}
		if _, cmd := m.Update(ctrlY); cmd != nil {
			t.Errorf("screen %d: ctrl+y returned a command", sc)
		}
	}
	// any key leaves these screens, ctrl+z included, and starts nothing
	for _, sc := range []screen{scHelp, scResult, scConfirm} {
		m := testModel()
		m.sc = sc
		got, cmd := m.Update(ctrlZ)
		mm := got.(model)
		if cmd != nil || mm.sc != scMenu || mm.inputting {
			t.Errorf("screen %d: ctrl+z: sc=%d inputting=%v cmd=%v, want the menu", sc, mm.sc, mm.inputting, cmd)
		}
	}
}

// A key message with several runes and no Paste flag (Unix without bracketed
// paste) is a paste: it does not join the typing before it.
func TestUndoMultiRuneKeyIsOwnStep(t *testing.T) {
	m, c := streamModel("rule", "")
	m = typeKeys(m, c, 100*time.Millisecond, "foo")
	m = feed(m, c, 100*time.Millisecond, keyMsg("bar")) // well within undoPause
	wantValue(t, m, "foobar")
	m = send(m, ctrlZ)
	wantValue(t, m, "foo")
	m = send(m, ctrlZ)
	wantValue(t, m, "")
	m = send(m, ctrlY, ctrlY)
	wantValue(t, m, "foobar")
	// typing right after it is a new step as well
	m = typeKeys(m, c, 100*time.Millisecond, "x")
	m = send(m, ctrlZ)
	wantValue(t, m, "foobar")
}

// Every word removed with one key press (ctrl+w, alt+backspace) is a step of its own.
func TestUndoWordDeleteStepsApart(t *testing.T) {
	for name, key := range map[string]tea.KeyMsg{
		"ctrl+w":        {Type: tea.KeyCtrlW},
		"alt+backspace": {Type: tea.KeyBackspace, Alt: true},
	} {
		m, c := streamModel("rule", "")
		m = typeKeys(m, c, 100*time.Millisecond, "foo bar ")
		m = send(m, ctrlZ) // "foo bar " is two steps: start from a known state
		m = send(m, ctrlY)
		wantValue(t, m, "foo bar ")
		m = feed(m, c, 100*time.Millisecond, key)
		wantValue(t, m, "foo ")
		m = feed(m, c, 100*time.Millisecond, key)
		wantValue(t, m, "")
		for _, want := range []string{"foo ", "foo bar "} {
			m = send(m, ctrlZ)
			if got := m.input.Value(); got != want {
				t.Fatalf("%s: undo gave %q, want %q", name, got, want)
			}
		}
	}
}

// Copies of the model do not share their history.
func TestUndoModelCopiesAreIndependent(t *testing.T) {
	m, c := streamModel("rule", "")
	m = typeKeys(m, c, 100*time.Millisecond, "ab")
	m2 := m
	c.advance(2 * time.Second)
	m2 = typeKeys(m2, c, 100*time.Millisecond, "cd")
	m2 = send(m2, ctrlZ)
	wantValue(t, m2, "ab")
	m2 = send(m2, ctrlZ)
	wantValue(t, m2, "")
	// the first copy has seen none of it
	wantValue(t, m, "ab")
	if len(m.hist.undo) != 1 || len(m.hist.redo) != 0 {
		t.Fatalf("history of the first copy changed: undo=%d redo=%d", len(m.hist.undo), len(m.hist.redo))
	}
	m = send(m, ctrlZ)
	wantValue(t, m, "")
	m = send(m, ctrlY)
	wantValue(t, m, "ab")
	// and the other way round
	m2 = send(m2, ctrlY, ctrlY)
	wantValue(t, m2, "abcd")
}

// A paste into the middle of the text: value and cursor come back with undo and redo.
func TestUndoPasteInMiddle(t *testing.T) {
	m, c := streamModel("rule", "")
	m = typeKeys(m, c, 100*time.Millisecond, "ad")
	m = feed(m, c, 100*time.Millisecond, tea.KeyMsg{Type: tea.KeyLeft})
	m = send(m, clipMsg{gen: m.inputGen, text: "XY"})
	wantValue(t, m, "aXYd")
	if p := m.input.Position(); p != 3 {
		t.Fatalf("cursor after paste = %d, want 3", p)
	}
	m = send(m, ctrlZ)
	wantValue(t, m, "ad")
	if p := m.input.Position(); p != 1 {
		t.Errorf("cursor after undo = %d, want 1", p)
	}
	m = send(m, ctrlY)
	wantValue(t, m, "aXYd")
	if p := m.input.Position(); p != 3 {
		t.Errorf("cursor after redo = %d, want 3", p)
	}
}

// CharLimit: a cut paste is one step, a paste cut away entirely is none.
func TestUndoCharLimit(t *testing.T) {
	m, c := streamModel("rule", "")
	m.input.CharLimit = 5
	m = typeKeys(m, c, 100*time.Millisecond, "abc")
	m = send(m, clipMsg{gen: m.inputGen, text: "defgh"})
	wantValue(t, m, "abcde")
	steps := len(m.hist.undo)
	m = send(m, clipMsg{gen: m.inputGen, text: "zz"}) // no room at all
	m = send(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q"), Paste: true})
	m = feed(m, c, 100*time.Millisecond, keyMsg("w"), keyMsg("long"))
	wantValue(t, m, "abcde")
	if len(m.hist.undo) != steps {
		t.Fatalf("undo steps %d -> %d: a rejected paste or key made a step", steps, len(m.hist.undo))
	}
	m = send(m, ctrlZ)
	wantValue(t, m, "abc")
	m = send(m, ctrlZ)
	wantValue(t, m, "")
}

// Ctrl+z in the middle of a key-stream paste takes back what has arrived so far
// and the rest of the stream goes on as new input.
func TestUndoInsideStreamPaste(t *testing.T) {
	const gap = time.Millisecond
	m, c := streamModel("rule", "")
	m = feed(m, c, gap, keyMsg("a"), keyMsg("b"))
	m = feed(m, c, gap, ctrlZ)
	wantValue(t, m, "")
	m = feed(m, c, gap, keyMsg("c"), keyMsg("d"))
	wantValue(t, m, "cd")
	m = send(m, ctrlZ)
	wantValue(t, m, "")
	m = send(m, ctrlZ) // nothing left
	wantValue(t, m, "")
	// and redo brings back the part that was taken
	m = send(m, ctrlY)
	wantValue(t, m, "cd")
}

// A pause of exactly undoPause keeps the group, a longer one closes it.
func TestUndoPauseBoundary(t *testing.T) {
	m, c := streamModel("rule", "")
	m = feed(m, c, 100*time.Millisecond, keyMsg("a"))
	m = feed(m, c, undoPause, keyMsg("b")) // exactly undoPause: same step
	m = feed(m, c, undoPause+time.Millisecond, keyMsg("c"))
	wantValue(t, m, "abc")
	m = send(m, ctrlZ)
	wantValue(t, m, "ab")
	m = send(m, ctrlZ)
	wantValue(t, m, "")
}
