package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	tea "github.com/charmbracelet/bubbletea"
)

// manyRules adds enough rules and adapters to overflow a short window.
func manyRules(m model) model {
	for i := 0; i < 30; i++ {
		m.cfg.Networks = append(m.cfg.Networks, "10."+strings.Repeat("1", i%3+1)+".0.0/16")
		m.cfg.DirectDomains = append(m.cfg.DirectDomains, "host"+strings.Repeat("x", i)+".example.com")
		m.ifs = append(m.ifs, m.ifs[0])
	}
	return m
}

func frameLines(v string) []string { return strings.Split(v, "\n") }

// The frame is never taller than the window, the title stays on top, and
// every line of the frame has the same width.
func TestViewFitsTerminalHeight(t *testing.T) {
	for _, size := range []struct{ w, h int }{{80, 24}, {80, 40}, {50, 24}, {120, 30}, {40, 16}} {
		for sc, name := range screenNames {
			for _, cur := range []int{0, 3, 20} {
				m := manyRules(richModel(size.w))
				m.height = size.h
				m.sc, m.cursor = sc, cur
				if sc == scSettings {
					m.cursor = cur % 4
				}
				v := m.View()
				lines := frameLines(v)
				if len(lines) > size.h {
					t.Errorf("%dx%d %s cursor %d: frame is %d lines tall", size.w, size.h, name, cur, len(lines))
				}
				if !strings.Contains(strings.Join(lines[:3], " "), "VPN SPLIT") {
					t.Errorf("%dx%d %s: title is not at the top of the frame: %q", size.w, size.h, name, lines[:3])
				}
				for i, l := range lines {
					if got := lipgloss.Width(l); got != size.w-rightMargin {
						t.Errorf("%dx%d %s: line %d is %d cells, want %d", size.w, size.h, name, i, got, size.w-rightMargin)
						break
					}
				}
			}
		}
		// with the input and a flash on a short window
		m := manyRules(richModel(size.w))
		m.height, m.sc = size.h, scRules
		m.beginInput("import", "~/Downloads/", "Файл со списком правил: ")
		m.setFlash(flashPasted)
		if n := len(frameLines(m.View())); n > size.h {
			t.Errorf("%dx%d input: frame is %d lines tall", size.w, size.h, n)
		}
	}
}

// The selected row stays on screen when the list is cut to the window.
func TestSelectedRowStaysVisible(t *testing.T) {
	m := manyRules(richModel(80))
	m.height, m.sc = 24, scRules
	for _, cur := range []int{0, 5, 17, ruleRows + 30, len(m.ruleItems()) + ruleRows - 1} {
		m.cursor = cur
		if !strings.Contains(m.View(), "▸") {
			t.Errorf("cursor %d: the selected row is not shown", cur)
		}
	}
	m.sc = scPick
	for _, cur := range []int{0, 10, len(m.ifs) + 1} {
		m.cursor = cur
		if !strings.Contains(m.View(), "▸") {
			t.Errorf("pick, cursor %d: the selected row is not shown", cur)
		}
	}
}

// A narrow window: the frame must not become wider than the window, down to
// the smallest sizes.
func TestFrameNeverWiderThanWindow(t *testing.T) {
	for _, w := range []int{20, 21, 24, 30} {
		for sc, name := range screenNames {
			m := richModel(w)
			m.sc = sc
			first := -1
			for i, l := range frameLines(m.View()) {
				got := lipgloss.Width(l)
				if got > w-rightMargin {
					t.Errorf("width %d %s: line %d is %d cells wide", w, name, i, got)
				}
				if first < 0 {
					first = got
				} else if got != first {
					t.Errorf("width %d %s: line %d is %d cells, the first is %d", w, name, i, got, first)
				}
			}
		}
	}
}

// Scrolling reaches the end of a long status screen and stays inside it.
func TestStatusScrollsWithinWindow(t *testing.T) {
	m := manyRules(richModel(80))
	m.height, m.sc = 24, scStatus
	if m.scrollMax() == 0 {
		t.Fatal("the status screen must not fit 24 lines in this test")
	}
	for i := 0; i < 500; i++ {
		m = send(m, tea.KeyMsg{Type: tea.KeyDown})
	}
	if m.scroll != m.scrollMax() {
		t.Fatalf("scroll = %d, max %d", m.scroll, m.scrollMax())
	}
	if n := len(frameLines(m.View())); n > 24 {
		t.Fatalf("scrolled frame is %d lines", n)
	}
	last := m.statusLines()
	if !strings.Contains(m.View(), strings.TrimSpace(last[len(last)-1])[:5]) {
		t.Error("the last status line must be reachable")
	}
	m = send(m, tea.KeyMsg{Type: tea.KeyPgUp})
	if m.scroll >= m.scrollMax() {
		t.Error("pgup must scroll back")
	}
	// help and result scroll too; any other key leaves
	m.sc, m.scroll = scHelp, 0
	m = send(m, tea.KeyMsg{Type: tea.KeyDown})
	if m.sc != scHelp || m.scroll != 1 {
		t.Errorf("help: sc=%v scroll=%d", m.sc, m.scroll)
	}
	m = send(m, keyMsg("x"))
	if m.sc != scMenu {
		t.Error("any other key must leave the help")
	}
}

func TestTipLinesFitWidth(t *testing.T) {
	tips := append(append(menuTips(), settingsTips...), pickTips[:]...)
	tips = append(tips, rulesTip)
	for _, w := range []int{10, 20, 40, tipWidth} {
		for _, tp := range tips {
			for _, l := range tipLines(tp, w) {
				if got := lipgloss.Width(l); got > w {
					t.Fatalf("width %d: tip line is %d cells: %q", w, got, l)
				}
			}
		}
	}
}

func TestWrapLinesAndIndent(t *testing.T) {
	for _, l := range wrapLines(strings.Repeat("слово ", 20)+strings.Repeat("я", 30)+" 漢字漢字漢字", 12) {
		if lipgloss.Width(l) > 12 {
			t.Errorf("wrapLines: %q is %d cells", l, lipgloss.Width(l))
		}
	}
	got := wrapIndent("    очень длинное правило домен", 14)
	if len(got) < 2 {
		t.Fatalf("expected a wrap, got %q", got)
	}
	for _, l := range got {
		if !strings.HasPrefix(l, "    ") || lipgloss.Width(l) > 14 {
			t.Errorf("wrapIndent line %q lost the indent or is too wide", l)
		}
	}
}

// menuNames are the titles of the nine main menu items as they appear in the frame.
func menuNames() []string {
	var out []string
	for _, it := range menuItems {
		out = append(out, it.Label)
	}
	return out
}

// menuRow is an item row of the main menu found in a rendered frame.
type menuRow struct {
	pos int  // place in the menu: 1..8 for "1)".."8)", 9 for "0)"
	sel bool // the row carries the selection mark
}

// itemNumRe is the numbering of an item: only item rows start with it (after the
// frame border, the indent and the selection mark); hints and the scheme do not.
var itemNumRe = regexp.MustCompile(`^[\s│]*(▸\s+)?(\d)\) `)

// menuRows are the item rows of the frame, in order.
func menuRows(v string) []menuRow {
	var out []menuRow
	for _, l := range frameLines(ansi.Strip(v)) {
		sub := itemNumRe.FindStringSubmatch(l)
		if sub == nil {
			continue
		}
		n, _ := strconv.Atoi(sub[2])
		if n == 0 {
			n = 9
		}
		out = append(out, menuRow{pos: n, sel: sub[1] != ""})
	}
	return out
}

// wantAllItems checks that all nine items are shown, in order.
func wantAllItems(t *testing.T, ctx, v string) {
	t.Helper()
	rows := menuRows(v)
	if len(rows) != len(menuItems) {
		t.Errorf("%s: %d item rows, want %d:\n%s", ctx, len(rows), len(menuItems), v)
		return
	}
	for i, r := range rows {
		if r.pos != i+1 {
			t.Errorf("%s: row %d is item %d", ctx, i, r.pos)
		}
	}
}

// The main menu shows all nine items without any scroll marks at any height
// that can hold them, and the frame fits the window.
func TestMenuShowsAllItems(t *testing.T) {
	for _, h := range []int{16, 24, 30, 40} {
		for _, w := range []int{40, 60, 80, 120} {
			for _, flash := range []bool{false, true} {
				for _, cur := range []int{0, 4, itemExit} {
					m := richModel(w)
					m.height, m.sc, m.cursor = h, scMenu, cur
					if flash {
						m.setFlash(flashPasted)
					}
					v := m.View()
					assertFits(t, "menu", v, w-rightMargin)
					if n := len(frameLines(v)); n > h {
						t.Errorf("%dx%d flash=%v: frame is %d lines tall", w, h, flash, n)
					}
					if strings.Contains(v, "ещё") {
						t.Errorf("%dx%d: the menu shows a scroll mark:\n%s", w, h, v)
					}
					for _, name := range menuNames() {
						// a long label may be cut with an ellipsis on narrow windows
						if !strings.Contains(v, string([]rune(name)[:5])) {
							t.Errorf("%dx%d cursor %d: item %q is missing:\n%s", w, h, cur, name, v)
						}
					}
					if !strings.Contains(strings.Join(frameLines(v)[:3], " "), "VPN SPLIT") {
						t.Errorf("%dx%d: no title at the top", w, h)
					}
				}
			}
		}
	}
}

// Items are checked by the whole name on a window wide enough for the longest one.
func TestMenuItemNamesWhole(t *testing.T) {
	for _, h := range []int{13, 16, 24, 30, 40} {
		m := richModel(80)
		m.height, m.sc = h, scMenu
		v := m.View()
		for _, name := range menuNames() {
			if !strings.Contains(v, name) {
				t.Errorf("height %d: item %q is missing", h, name)
			}
		}
	}
}

// A tall window gets the full scheme and the description; a low one loses them.
func TestMenuDegradesInOrder(t *testing.T) {
	m := richModel(100)
	m.sc, m.cursor = scMenu, itemApply
	tip := "Корпоративные правила уходят"
	m.height = 50
	v := m.View()
	if !strings.Contains(v, "интранет") || !strings.Contains(v, "DIRECT") || !strings.Contains(v, tip) || !strings.Contains(v, "vpnsplit apply") {
		t.Errorf("tall window must show the full scheme and description:\n%s", v)
	}
	if !strings.Contains(v, "требует прав администратора") {
		t.Error("tall window must show the hints")
	}
	m.height = 16
	v = m.View()
	if strings.Contains(v, "vpnsplit apply") || strings.Contains(v, "интранет") {
		t.Errorf("height 16 must lose the description and the full scheme:\n%s", v)
	}
	if n := len(frameLines(v)); n > 16 {
		t.Errorf("height 16: %d lines", n)
	}
}

// menuVariants are the states that change what the menu shows.
var menuVariants = map[string]func(model) model{
	"plain":    func(m model) model { return m },
	"nocfg":    func(m model) model { m.cfg = nil; return m },
	"nodirect": func(m model) model { m.cfg.DirectNetworks, m.cfg.DirectDomains = nil, nil; return m },
	"busy":     func(m model) model { m.busy, m.quiet = "Определяю VPN", true; return m },
	"flash": func(m model) model {
		m.setFlash("Конфиг повреждён: исправьте или удалите его (vpnsplit reset --purge)")
		return m
	},
}

// menuWidths are the widths the menu is checked at: the narrowest ones and the usual ones.
func menuWidths() []int {
	var ws []int
	for w := 20; w < 40; w++ {
		ws = append(ws, w)
	}
	return append(ws, 40, 80, 120)
}

// Along the ladder the menu only gets shorter (frame included; equal layouts
// are fine), a layout is found for every height, and from 9 lines up all nine
// items are visible.
func TestMenuLadder(t *testing.T) {
	for name, variant := range menuVariants {
		for _, w := range menuWidths() {
			m := variant(richModel(w))
			m.sc = scMenu
			for _, h := range []int{24, 50} { // the vertical padding depends on the height
				m.height = h
				prev := 1 << 30
				for i, l := range menuLadder {
					n := len(m.menuLines(l)) + m.menuChrome(l)
					if n > prev {
						t.Errorf("%s width %d height %d: layout %d is taller (%d) than layout %d (%d)", name, w, h, i, n, i-1, prev)
					}
					prev = n
				}
			}
			for h := 1; h <= 60; h++ {
				ctx := fmt.Sprintf("%s width %d height %d", name, w, h)
				m.height = h
				idx, lines, ok := m.menuPlan()
				if idx < 0 || idx >= len(menuLadder) || len(lines) == 0 {
					t.Fatalf("%s: no plan (idx %d, %d lines)", ctx, idx, len(lines))
				}
				if ok != (h >= len(menuItems)) {
					t.Errorf("%s: ok=%v", ctx, ok)
				}
				if ok && len(lines) > m.menuFrameHeight(menuLadder[idx]) {
					t.Errorf("%s: layout %d is too tall", ctx, idx)
				}
				v := m.View()
				if n := len(frameLines(v)); n > h {
					t.Errorf("%s: frame is %d lines", ctx, n)
				}
				assertFits(t, ctx, v, w-rightMargin)
				if h >= len(menuItems) {
					wantAllItems(t, ctx, v)
				}
			}
			if name == "plain" {
				// title + nine items + frame is 12 lines
				m.height = 12
				if _, lines, ok := m.menuPlan(); !ok || len(lines) != 10 {
					t.Errorf("width %d height 12: ok=%v lines=%d, want the layout of 10 lines", w, ok, len(lines))
				}
			}
		}
	}
}

// The last step has no frame: nine items on a window of 9 and 10 lines.
func TestMenuWithoutFrame(t *testing.T) {
	for _, h := range []int{9, 10} {
		m := richModel(80)
		m.height, m.sc = h, scMenu
		idx, _, ok := m.menuPlan()
		if !ok || menuLadder[idx].box {
			t.Fatalf("height %d: ok=%v idx=%d, want the layout without frame", h, ok, idx)
		}
		v := m.View()
		if strings.ContainsAny(v, "╭╮╰╯│") {
			t.Errorf("height %d: the frame is drawn:\n%s", h, v)
		}
		wantAllItems(t, fmt.Sprintf("height %d", h), v)
	}
	m := richModel(80)
	m.height, m.sc = 11, scMenu
	if idx, _, ok := m.menuPlan(); !ok || !menuLadder[idx].box {
		t.Errorf("height 11 must still have a frame")
	}
}

// Below 9 lines not even the items fit: a window of them around the selected
// one is shown, continuous, with the selected item inside and no scroll marks.
func TestMenuExtremeHeight(t *testing.T) {
	for _, w := range []int{20, 80} {
		for h := 1; h < len(menuItems); h++ {
			for cur := range menuItems {
				m := richModel(w)
				m.height, m.sc, m.cursor = h, scMenu, cur
				v := m.View()
				ctx := fmt.Sprintf("width %d height %d cursor %d", w, h, cur)
				if n := len(frameLines(v)); n > h {
					t.Errorf("%s: %d lines", ctx, n)
				}
				assertFits(t, ctx, v, w-rightMargin)
				if strings.Contains(v, "ещё") {
					t.Errorf("%s: scroll mark shown:\n%s", ctx, v)
				}
				rows := menuRows(v)
				if len(rows) != h {
					t.Errorf("%s: %d item rows, want %d:\n%s", ctx, len(rows), h, v)
					continue
				}
				want := cur + 1 // position of the selected item in the menu
				sel := false
				for i, r := range rows {
					if i > 0 && r.pos != rows[i-1].pos+1 {
						t.Errorf("%s: rows %d and %d are not consecutive", ctx, rows[i-1].pos, r.pos)
					}
					if r.sel {
						sel = r.pos == want
					}
				}
				if !sel {
					t.Errorf("%s: item %d is not shown as selected:\n%s", ctx, want, v)
				}
			}
		}
	}
}
