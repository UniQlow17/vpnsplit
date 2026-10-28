package tui

import (
	"time"
	"unicode"
)

const (
	// undoDepth is how many undo steps an input field remembers.
	undoDepth = 100
	// undoPause is the pause in typing after which the next key starts a new
	// undo step.
	undoPause = time.Second
)

// editKind is the kind of the last edit; a change of kind closes the undo group.
type editKind int

const (
	editNone   editKind = iota // nothing yet, or the group was closed (cursor moved, undo)
	editType                   // characters were typed
	editDelete                 // characters were deleted
	editOther                  // replacement of text: always a step of its own
	editPaste                  // pasted text: always a step of its own
)

// snap is a state of the input field: its value and the cursor.
type snap struct {
	val string
	pos int
}

// history is the undo and redo stack of one input field.
//
// Snapshots are only appended to fresh slices: a model is copied by value on
// every update and the copies must never share a backing array.
type history struct {
	undo, redo []snap
	kind       editKind
	lastAt     time.Time // time of the last edit, for undoPause
	lastSpace  bool      // the last typed or deleted rune is a space
	// A key-stream paste (Windows) is told apart only by the gap between keys,
	// so its first key has already been taken for ordinary typing.
	burstEdit   bool // an edit was made in the current key burst
	burstPushed bool // the first edit of the burst opened an undo step of its own
	burstPre    snap // state before the first edit of the burst
}

func (h *history) push(s snap) {
	if n := len(h.undo); n > 0 && h.undo[n-1] == s {
		return
	}
	from := max(len(h.undo)-undoDepth+1, 0)
	h.undo = append(append([]snap(nil), h.undo[from:]...), s)
}

func (h *history) pushRedo(s snap) {
	h.redo = append(append([]snap(nil), h.redo...), s)
}

// reset forgets everything, for a new or closed input.
func (h *history) reset() { *h = history{} }

// breakGroup closes the current group: the next edit starts a new step.
func (h *history) breakGroup() { h.kind, h.burstEdit = editNone, false }

func (m model) snapshot() snap { return snap{m.input.Value(), m.input.Position()} }

func (m *model) restore(s snap) {
	m.input.SetValue(s.val)
	m.input.SetCursor(s.pos)
}

// diffRunes returns what was removed from a and what was added to get b: the
// texts between their common prefix and common suffix.
func diffRunes(a, b string) (removed, added []rune) {
	x, y := []rune(a), []rune(b)
	p := 0
	for p < len(x) && p < len(y) && x[p] == y[p] {
		p++
	}
	s := 0
	for s < len(x)-p && s < len(y)-p && x[len(x)-1-s] == y[len(y)-1-s] {
		s++
	}
	return x[p : len(x)-s], y[p : len(y)-s]
}

// recordPaste is called with the state before a paste that arrived as one
// piece (clipboard, bracketed paste): it is one undo step.
func (m *model) recordPaste(before snap) {
	if after := m.snapshot(); after.val == before.val {
		return
	}
	h := &m.hist
	h.push(before)
	h.redo = nil
	h.kind, h.lastAt, h.burstEdit = editPaste, m.clock(), false
}

// recordKey is called after a key went through the text field. before is the
// state ahead of the key, burst tells that the key follows the previous one
// within pasteBurst.
func (m *model) recordKey(before snap, burst bool, now time.Time) {
	h := &m.hist
	if !burst { // a new burst starts here
		h.burstEdit, h.burstPushed = false, false
	}
	after := m.snapshot()
	if after.val == before.val {
		if after.pos != before.pos {
			h.breakGroup() // moving the cursor ends the group
		}
		return
	}
	removed, added := diffRunes(before.val, after.val)
	// One key that changes more than one rune is not typing: a paste without
	// the Paste flag (several runes in a key message), ctrl+w, ctrl+u and the
	// like. Such an edit is a step of its own and closes the group.
	kind := editOther
	switch {
	case len(added) > 1:
		kind = editPaste
	case len(removed) == 0:
		kind = editType
	case len(added) == 0 && len(removed) == 1:
		kind = editDelete
	}
	space := false
	switch {
	case len(added) > 0:
		space = unicode.IsSpace(added[len(added)-1])
	case len(removed) > 0:
		space = unicode.IsSpace(removed[0])
	}

	switch {
	case burst && h.burstEdit:
		// the second key of a burst: the whole burst is one paste
		if !h.burstPushed {
			h.push(h.burstPre) // the first key was glued to the previous group
			h.burstPushed = true
		}
		kind = editPaste
	default:
		newStep := h.kind != kind || kind == editOther || kind == editPaste || now.Sub(h.lastAt) > undoPause
		switch kind {
		case editType: // a word is closed by the space after it
			newStep = newStep || (h.lastSpace && !space)
		case editDelete: // a change between a word and spaces
			newStep = newStep || h.lastSpace != space
		}
		if newStep {
			h.push(before)
		}
		h.burstEdit, h.burstPushed, h.burstPre = true, newStep, before
	}
	h.redo = nil
	h.kind, h.lastAt, h.lastSpace = kind, now, space
}

// undoInput steps back one group of edits.
func (m *model) undoInput() {
	h := &m.hist
	h.breakGroup()
	n := len(h.undo)
	if n == 0 {
		return
	}
	h.pushRedo(m.snapshot())
	s := h.undo[n-1]
	h.undo = append([]snap(nil), h.undo[:n-1]...)
	m.restore(s)
}

// redoInput repeats what undoInput took back.
func (m *model) redoInput() {
	h := &m.hist
	h.breakGroup()
	n := len(h.redo)
	if n == 0 {
		return
	}
	h.undo = append(append([]snap(nil), h.undo...), m.snapshot())
	s := h.redo[n-1]
	h.redo = append([]snap(nil), h.redo[:n-1]...)
	m.restore(s)
}
