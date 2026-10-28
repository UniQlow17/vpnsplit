package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// defaultWidth is assumed until the first tea.WindowSizeMsg arrives.
const defaultWidth = 100

// Fixed parts of the layout, in terminal cells.
const (
	textIndent   = 2 // indent of plain text lines inside the frame
	rowIndent    = 5 // list row: indent before the label ("  ▸ " when selected)
	rowGap       = 2 // list row: gap between the label and the extra column
	rowPrefix    = rowIndent + rowGap
	inputReserve = textIndent + 2 + 1 // input line: indent, "> " prompt, cursor
	pickExtra    = 10                 // pick row: "★ подкл. " plus a space of the addresses
	ruleExtra    = 14                 // rules row: "напрямую" + space + "домен"
	tagWidth     = 6                  // scheme row: "HOME  ", "CORP  ", "DIRECT"
	rightMargin  = 1                  // spare column so a write to the last column cannot auto-wrap
)

// fit shortens s to at most w cells, ending it with an ellipsis when cut.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	return ansi.Truncate(s, w, "…")
}

// padRight pads s with spaces to w display cells.
func padRight(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// wrapLines breaks s into lines of at most w cells; explicit newlines are
// kept, words longer than w are split.
func wrapLines(s string, w int) []string {
	if w < 1 {
		w = 1
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		out = append(out, strings.Split(ansi.Wrap(l, w, ""), "\n")...)
	}
	return out
}

// wrapIndent wraps s like wrapLines but keeps the leading spaces of s on every
// resulting line, so continuation lines stay under their text.
func wrapIndent(s string, w int) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		body := strings.TrimLeft(l, " ")
		ind := len(l) - len(body)
		if ind >= w { // no room left for the text: drop the indent
			ind = 0
		}
		for _, part := range wrapLines(body, w-ind) {
			out = append(out, strings.Repeat(" ", ind)+part)
		}
	}
	return out
}

// clampLines makes sure that no line of s is wider than w cells.
func clampLines(s string, w int) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = fit(l, w)
	}
	return strings.Join(lines, "\n")
}

// joinFit joins parts with sep on one line while they fit into w cells and
// continues on the next line otherwise.
func joinFit(w int, sep string, parts ...string) string {
	var lines []string
	cur := ""
	for _, p := range parts {
		switch {
		case cur == "":
			cur = p
		case lipgloss.Width(cur)+lipgloss.Width(sep)+lipgloss.Width(p) <= w:
			cur += sep + p
		default:
			lines = append(lines, cur)
			cur = p
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return strings.Join(lines, "\n")
}
