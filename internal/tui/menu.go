package tui

import (
	"fmt"
	"strings"
)

// The main menu never scrolls: all its items are always visible. When the
// window is too short, parts of the screen are given up following the ladder
// of menuLadder, from the full layout to the smallest one. The first layout
// that fits is used.

type (
	diagramMode int
	tipMode     int
	hintMode    int
)

const (
	diagFull    diagramMode = iota // route scheme, up to 4 lines
	diagCompact                    // one or two lines
	diagNone
)

const (
	tipFull  tipMode = iota // description panel with the command
	tipShort                // first sentence of the description, one line
	tipNone
)

const (
	hintFull  hintMode = iota // keys and the marker legend, two lines
	hintShort                 // keys only, one line
	hintNone
)

// menuLayout says what the main menu shows.
type menuLayout struct {
	diagram diagramMode
	status  bool
	tip     tipMode
	hint    hintMode
	blanks  bool // blank separator lines
	padV    bool // vertical padding of the frame (it exists on tall windows only)
	title   bool
	flash   bool // flash message and the auto-mode spinner line
	box     bool // the frame (border); without it the text takes the whole window
}

// menuLadder goes from the full layout to the smallest one. What is given up,
// in this order: the description and the hints (shortened, then removed), the
// scheme (compact, then removed), the status line, blank separators and the
// vertical padding of the frame. The next two steps are the extreme measure
// for windows lower than the frame, title and nine items (13 lines): first the
// title, then the flash message go. The step after them drops the frame itself
// (border and padding), so the nine items fit a window of 9 lines. The nine
// items are never given up in these steps. Only when even they do not fit
// (a window of less than 9 lines) a window of the items around the selected one
// is shown; in this extreme case the hidden items are not marked in any way.
//
// The last field, box, says whether the frame is drawn at all.
var menuLadder = []menuLayout{
	{diagFull, true, tipFull, hintFull, true, true, true, true, true},
	{diagFull, true, tipShort, hintShort, true, true, true, true, true},
	{diagFull, true, tipNone, hintShort, true, true, true, true, true},
	{diagFull, true, tipNone, hintNone, true, true, true, true, true},
	{diagCompact, true, tipNone, hintNone, true, true, true, true, true},
	{diagNone, true, tipNone, hintNone, true, true, true, true, true},
	{diagNone, false, tipNone, hintNone, true, true, true, true, true},
	{diagNone, false, tipNone, hintNone, false, true, true, true, true},
	{diagNone, false, tipNone, hintNone, false, false, true, true, true},
	{diagNone, false, tipNone, hintNone, false, false, false, true, true},
	{diagNone, false, tipNone, hintNone, false, false, false, false, true},
	{diagNone, false, tipNone, hintNone, false, false, false, false, false},
}

// menuItemLines are the nine items of the menu.
func (m model) menuItemLines() []string {
	var out []string
	for i, it := range menuItems {
		label := it.Label
		if i == itemAuto {
			label += ": " + map[bool]string{true: "вкл", false: "выкл"}[m.auto]
		}
		num := i + 1
		if i == itemExit {
			num = 0
		}
		extra := ""
		if it.Admin {
			extra = sYel.Render("●")
		}
		out = append(out, m.row(i, fmt.Sprintf("%d) %s", num, label), extra))
	}
	return out
}

// shortTip is the first sentence of the description of the selected item, in
// one line.
func (m model) shortTip() string {
	if m.cursor < 0 || m.cursor >= len(menuItems) {
		return ""
	}
	h := menuItems[m.cursor].Hint
	if i := strings.Index(h, ". "); i >= 0 {
		h = h[:i+1]
	}
	return strings.Repeat(" ", textIndent) + sGray.Render(fit(h, m.contentW()-textIndent))
}

// menuLines builds the menu in the given layout.
func (m model) menuLines(l menuLayout) []string {
	var out []string
	sep := func() {
		if l.blanks {
			out = append(out, "")
		}
	}
	if l.title {
		out = append(out, m.titleLine())
		sep()
	}
	switch l.diagram {
	case diagFull:
		out = append(out, splitLines(m.diagram())...)
		sep()
	case diagCompact:
		if d := m.compactDiagram(); len(d) > 0 {
			out = append(out, d...)
			sep()
		}
	}
	if l.status {
		out = append(out, m.statusRows()...)
		sep()
	}
	out = append(out, m.menuItemLines()...)
	switch l.tip {
	case tipFull:
		out = append(out, "")
		out = append(out, splitLines(panel(menuTips(), m.cursor, min(tipWidth, m.contentW()-textIndent)))...)
	case tipShort:
		out = append(out, "", m.shortTip())
	}
	if l.flash {
		out = append(out, m.busyFlashLines()...)
	}
	switch l.hint {
	case hintFull:
		out = append(out, "")
		out = append(out, m.blockLines(sDim, "↑↓ выбор · enter запуск · цифры — номер · q — выход")...)
		out = append(out, m.blockLines(sDim, "● — пункт требует прав администратора")...)
	case hintShort:
		out = append(out, "")
		out = append(out, m.blockLines(sDim, "↑↓ · enter · цифры · q")...)
	}
	return out
}

// menuChrome is the number of lines the frame of the layout takes around the text.
func (m model) menuChrome(l menuLayout) int {
	if !l.box {
		return 0
	}
	padV, _ := m.boxPadding()
	if !l.padV {
		padV = 0
	}
	return 2 + 2*padV
}

// menuFrameHeight is the number of text lines available to the layout; 0 while
// the window size is unknown.
func (m model) menuFrameHeight(l menuLayout) int {
	if m.height <= 0 {
		return 0
	}
	if !l.box {
		return m.height
	}
	return m.frameHeightFor(l.padV)
}

// menuPlan picks the first layout of the ladder that fits the window; ok is
// false when none does.
func (m model) menuPlan() (idx int, lines []string, ok bool) {
	for i, l := range menuLadder {
		lines = m.menuLines(l)
		if h := m.menuFrameHeight(l); h == 0 || len(lines) <= h {
			return i, lines, true
		}
	}
	return len(menuLadder) - 1, lines, false
}

// menuWindow is the window of the items around the selected one, for a window
// lower than the nine items.
func (m model) menuWindow() []string {
	items := m.menuItemLines()
	h := clamp(m.height, 1, len(items))
	start := clamp(m.cursor-h/2, 0, len(items)-h)
	return items[start : start+h]
}

func (m model) menuView() string {
	idx, lines, ok := m.menuPlan()
	l := menuLadder[idx]
	if !ok {
		lines = m.menuWindow()
	}
	if !l.box {
		w := m.width
		if w <= 0 {
			w = defaultWidth
		}
		return clampLines(strings.Join(lines, "\n"), max(w-rightMargin, 1))
	}
	padV, padH := m.boxPadding()
	if !l.padV {
		padV = 0
	}
	cw := m.contentW()
	return sBox.Padding(padV, padH).Width(cw + 2*padH).Render(clampLines(strings.Join(lines, "\n"), cw))
}
