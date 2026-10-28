package tui

import (
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
)

// pasteBurst is the longest gap between two key events that still counts as
// one paste. On Windows the console delivers a paste as a stream of ordinary
// key events (bubbletea reads them with ReadConsoleInput; there is no
// bracketed paste), and a person cannot type two keys that close together.
const pasteBurst = 40 * time.Millisecond

// streamPasteDefault turns the burst heuristic on only where it is needed:
// elsewhere terminals send bracketed paste, and the heuristic would break fast
// scripted input (ssh, tmux, xdotool).
const streamPasteDefault = runtime.GOOS == "windows"

const (
	flashPasted        = "вставлено — нажмите Enter для подтверждения"
	flashFirstLineOnly = "вставлена только первая строка"
)

// clipMsg carries the clipboard contents read after ctrl+v. gen is the
// generation of the input that asked for it: a late answer must not land in
// another field.
type clipMsg struct {
	gen  int
	text string
	err  error
}

// clipboardCmd reads the system clipboard off the update loop.
func clipboardCmd(gen int) tea.Cmd {
	return func() tea.Msg {
		s, err := clipboard.ReadAll()
		return clipMsg{gen: gen, text: s, err: err}
	}
}

// textLines returns the non-blank lines of s, trimmed. Lines may end with \n,
// \r\n or a bare \r.
func textLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = trimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// firstLine returns the first non-blank line of s, trimmed.
func firstLine(s string) string {
	if l := textLines(s); len(l) > 0 {
		return l[0]
	}
	return ""
}

// trimSpace trims Unicode spaces, NUL and all format characters (category Cf:
// BOM, zero-width and bidi marks such as U+202A, which Explorer's "Security"
// tab adds) from both ends of s.
func trimSpace(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) || r == 0
	})
}

// normalizePath cleans a path that was typed or pasted: it takes the first
// non-blank line and strips surrounding whitespace and quotes, as Explorer's
// "Copy as path" produces. Matching pairs of "..." or '...' are removed
// (repeatedly); after that a single dangling quote of either kind at the start
// or at the end is removed too, if that quote character occurs nowhere else
// in the path. A quote inside (C:\a"b, C:\it's\a.txt) is kept.
func normalizePath(s string) string {
	s = firstLine(s)
	for len(s) >= 2 {
		q := s[0]
		if (q != '"' && q != '\'') || s[len(s)-1] != q {
			break
		}
		s = trimSpace(s[1 : len(s)-1])
	}
	for _, q := range []string{`"`, `'`} {
		if strings.Count(s, q) != 1 {
			continue
		}
		if strings.HasPrefix(s, q) {
			s = trimSpace(strings.TrimPrefix(s, q))
		} else if strings.HasSuffix(s, q) {
			s = trimSpace(strings.TrimSuffix(s, q))
		}
	}
	return s
}

// isFullPath reports whether p is an absolute or home-relative path. The check
// is textual and does not depend on the OS the program runs on: "/x", UNC
// \\srv\share, "C:\x" or "C:/x", "~/x" and `~\x`.
func isFullPath(p string) bool {
	for _, pre := range []string{"/", `\\`, "~/", `~\`} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return false
	}
	c := p[0] | 0x20 // ASCII lower case
	return c >= 'a' && c <= 'z'
}

// pathPurpose tells whether the input asks for a file path.
func pathPurpose(purpose string) bool { return purpose == "import" || purpose == "export" }

// stripDefault drops the prefilled default from the start of raw when what
// follows it is a full path: a path pasted onto "~/Downloads/" must not be
// glued to it.
func stripDefault(raw, def string) string {
	if def == "" {
		return raw
	}
	if rest, ok := strings.CutPrefix(raw, def); ok {
		if p := normalizePath(rest); isFullPath(p) {
			return p
		}
	}
	return raw
}

// resolvePath is the final path to use for the typed or pasted input.
func resolvePath(raw, def string) string {
	return normalizePath(stripDefault(raw, def))
}

// pasteText prepares pasted text for the field of the given purpose: a single
// clean line, for paths without quotes.
func pasteText(purpose, s string) string {
	if pathPurpose(purpose) {
		return normalizePath(s)
	}
	return firstLine(s)
}

// insertPasted puts pasted text into the input at the cursor.
func (m *model) insertPasted(text string) {
	s := pasteText(m.purpose, text)
	if s == "" {
		return
	}
	if !pathPurpose(m.purpose) && len(textLines(text)) > 1 {
		m.setFlash(flashFirstLineOnly)
	}
	before := m.snapshot()
	if pathPurpose(m.purpose) && m.input.Value() == m.inputDef && isFullPath(s) {
		m.input.SetValue("")
	}
	m.input, _ = m.input.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
	m.recordPaste(before) // the whole paste, default replacement included, is one undo step
}
