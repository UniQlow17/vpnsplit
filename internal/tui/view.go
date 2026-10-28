package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// minListRows is how many rows of the main list are kept when the window is
// too short for everything: the tips below the list are cut first.
const minListRows = 6

// screenParts is a screen split into the regions that the height fitter treats
// differently. The header (title, scheme, status) and the footer (hints, input,
// flash) are common and always kept.
type screenParts struct {
	list   []string // main content
	focus  int      // line of list to keep visible, -1 for none
	scroll bool     // list is scrolled by m.scroll instead of following focus
	keep   []string // always shown under the list (delete confirmation)
	tail   []string // tips under the list: the first to be cut
	hint   string   // keys hint, the first line of the footer
	hintSt lipgloss.Style
	gap    bool // blank line before the hint
}

// fitted is a screen fitted to the height of the window.
type fitted struct {
	head, list, keep, tail, foot []string
	listH                        int // lines of the list shown at most
}

func dropBlank(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func clamp(v, lo, hi int) int { return max(min(v, hi), lo) }

// frameHeight is how many text lines fit into the frame; 0 until the window size is known.
func (m model) frameHeight() int { return m.frameHeightFor(true) }

// frameHeightFor is frameHeight with or without the vertical padding of the frame.
func (m model) frameHeightFor(padV bool) int {
	if m.height <= 0 {
		return 0
	}
	pad, _ := m.boxPadding()
	if !padV {
		pad = 0
	}
	return max(m.height-2-2*pad, 1)
}

// titleLine is the program title.
func (m model) titleLine() string {
	title := rainbow("  ▌ VPN SPLIT ▐  ", m.frame)
	if sub := sGray.Render(" корп. VPN + домашний VPN + напрямую"); lipgloss.Width(title)+lipgloss.Width(sub) <= m.contentW() {
		title += sub
	}
	return title
}

// statusRows is the status line (wrapped when it is long).
func (m model) statusRows() []string {
	aw := m.contentW() - textIndent
	status := sGray.Render("маршрутов: ") + fmt.Sprint(m.routes)
	switch {
	case m.needApply && m.routes > 0:
		status = sYel.Render("VPN или правила изменились, нужно применить ") + status
	case m.routes > 0:
		status = sGreen.Render("активно ") + status
	default:
		status = sYel.Render("не применено ") + status
	}
	parts := []string{status}
	if !m.admin {
		parts = append(parts, sRed.Render("нет прав администратора"))
	}
	var lines []string
	for _, l := range wrapLines(joinFit(aw, "  ", parts...), aw) {
		lines = append(lines, strings.Repeat(" ", textIndent)+l)
	}
	return lines
}

// headLines is the part above every screen: title, scheme and status.
func (m model) headLines() []string {
	lines := []string{m.titleLine(), ""}
	lines = append(lines, splitLines(m.diagram())...)
	lines = append(lines, "")
	lines = append(lines, m.statusRows()...)
	return append(lines, "")
}

// footLines is the part under every screen: the keys hint of the screen, the
// input, the busy line and the flash.
func (m model) footLines(p screenParts, hint string) []string {
	var f []string
	if hint != "" {
		if p.gap {
			f = append(f, "")
		}
		f = append(f, m.blockLines(p.hintSt, hint)...)
	}
	if m.inputting {
		f = append(f, "")
		f = append(f, m.blockLines(lipgloss.NewStyle(), m.prompt)...)
		f = append(f, strings.Repeat(" ", textIndent)+m.input.View())
		f = append(f, m.blockLines(sGray, "enter — ок · esc — отмена · ctrl+v — вставить · ctrl+z / ctrl+y — отменить / повторить")...)
	}
	return append(f, m.busyFlashLines()...)
}

// busyFlashLines is the spinner line of a quiet background job and the flash
// message, each after a blank line; empty when there is neither.
func (m model) busyFlashLines() []string {
	var out []string
	if m.busy != "" && m.quiet {
		out = append(out, "", strings.Repeat(" ", textIndent)+m.spin.View()+" "+m.busy)
	}
	if m.flash != "" && m.frame < m.flashAt {
		out = append(out, "")
		out = append(out, m.blockLines(sYel, "› "+m.flash)...)
	}
	return out
}

// scrollPrefix is the position shown in the hint of a scrolled screen.
func scrollPrefix(from, to, total int) string {
	return fmt.Sprintf("строки %d–%d из %d · ↑↓ — прокрутка · ", from, to, total)
}

// fitScreen fits the screen into the height of the window: the tips shrink
// first, then the list is cut to a window around the selected line (or at the
// scroll offset), and as a last resort blank separator lines are dropped.
func (m model) fitScreen(p screenParts) fitted {
	n := len(p.list)
	f := fitted{keep: p.keep, listH: n}
	var foot []string
	tailH := len(p.tail)
	avail := m.frameHeight()
	compact := false
	build := func(prefix string) {
		f.head, foot = m.headLines(), m.footLines(p, prefix+p.hint)
		if compact {
			f.head, foot = dropBlank(f.head), dropBlank(foot)
		}
		if avail == 0 {
			f.listH, tailH = n, len(p.tail)
			return
		}
		rest := avail - len(f.head) - len(foot) - len(p.keep)
		minList := min(n, minListRows)
		tailH = min(len(p.tail), max(rest-minList, 0))
		f.listH = min(n, max(rest-tailH, 0))
	}
	prefix := ""
	build(prefix)
	if p.scroll && f.listH < n {
		prefix = scrollPrefix(n, n, n)
		build(prefix)
	}
	if f.listH < min(n, minListRows) {
		compact = true
		build(prefix)
	}

	start := 0
	if f.listH < n {
		switch {
		case p.scroll:
			start = clamp(m.scroll, 0, n-f.listH)
		case p.focus >= 0:
			start = clamp(p.focus-f.listH/2, 0, n-f.listH)
		}
	}
	end := start + f.listH
	f.list = append([]string(nil), p.list[start:end]...)
	f.tail = p.tail[:tailH]
	if f.listH < n {
		if p.scroll {
			foot = m.footLines(p, scrollPrefix(start+1, end, n)+p.hint)
			if compact {
				foot = dropBlank(foot)
			}
		} else if f.listH >= 3 {
			// the selected line is never at the edges of the window
			if start > 0 {
				f.list[0] = strings.Repeat(" ", textIndent) + sDim.Render(fmt.Sprintf("↑ ещё %d", start))
			}
			if end < n {
				f.list[len(f.list)-1] = strings.Repeat(" ", textIndent) + sDim.Render(fmt.Sprintf("↓ ещё %d", n-end))
			}
		}
	}
	f.foot = foot
	return f
}

// listHeight is how many lines of the list the current screen shows at once.
func (m model) listHeight() int { return m.fitScreen(m.screenParts()).listH }

// scrollMax is the largest scroll offset of the current screen.
func (m model) scrollMax() int {
	p := m.screenParts()
	if !p.scroll {
		return 0
	}
	return max(len(p.list)-m.fitScreen(p).listH, 0)
}

func (m model) View() string {
	if m.sc == scMenu {
		return m.menuView()
	}
	f := m.fitScreen(m.screenParts())
	var lines []string
	for _, part := range [][]string{f.head, f.list, f.keep, f.tail, f.foot} {
		lines = append(lines, part...)
	}
	// last line of defence: neither taller nor wider than the window
	if h := m.frameHeight(); h > 0 && len(lines) > h {
		lines = lines[:h]
	}
	padV, padH := m.boxPadding()
	cw := m.contentW()
	return sBox.Padding(padV, padH).Width(cw + 2*padH).Render(clampLines(strings.Join(lines, "\n"), cw))
}

func splitLines(s string) []string { return strings.Split(s, "\n") }

// screenParts builds the content of the current screen.
func (m model) screenParts() screenParts {
	cw := m.contentW()
	aw := cw - textIndent
	tw := min(tipWidth, aw)
	p := screenParts{focus: -1, hintSt: sGray}
	ind := strings.Repeat(" ", textIndent)
	add := func(lines ...string) { p.list = append(p.list, lines...) }

	switch m.sc {
	case scHelp:
		p.scroll = true
		for _, l := range helpText {
			if h, ok := strings.CutPrefix(l, "# "); ok {
				add(m.blockLines(lipgloss.NewStyle().Bold(true).Foreground(cCyan), h)...)
				continue
			}
			for _, w := range wrapLines(l, min(tipWidth+4, aw)) {
				add(ind + w)
			}
		}
		p.hint, p.gap = "любая клавиша — назад", true
	case scBusy:
		add(ind + m.spin.View() + " " + m.busy + strings.Repeat(".", m.frame/3%4))
	case scResult:
		p.scroll = true
		style := sGreen
		if m.resErr {
			style = sRed
		}
		add(m.blockLines(style, m.resTitle)...)
		add("")
		for _, w := range wrapLines(m.resText, aw) {
			add(ind + w)
		}
		p.hint, p.gap = "любая клавиша — назад", true
	case scConfirm:
		add(m.blockLines(sYel, "Удалить все маршруты vpnsplit и вернуть исходную маршрутизацию?")...)
		add("")
		add(m.blockLines(sGray, confirmText)...)
		p.hint, p.gap = "y — да, любая другая клавиша — отмена", true
	case scPick:
		title := "Корпоративный VPN"
		hint := netif.KindCorp
		if m.pickStep == 1 {
			title, hint = "Домашний VPN", netif.KindVPN
		}
		add(m.blockLines(lipgloss.NewStyle().Bold(true), title)...)
		add("")
		p.focus = len(p.list) + m.cursor
		add(m.row(0, "Авто — определять при каждом подключении", sGreen.Render("рекомендуется")))
		colw := min(28, max(cw-rowPrefix-pickExtra, 8))
		for i, f := range m.ifs {
			st := sRed.Render("откл.")
			if f.Connected() {
				st = sGreen.Render("подкл.")
			}
			star := " "
			if f.Kind == hint {
				star = sYel.Render("★")
			}
			line := padRight(fit(f.Label(), colw), colw)
			add(m.row(i+1, line, star+" "+st+" "+sGray.Render(strings.Join(f.Addrs, ","))))
		}
		add(m.row(len(m.ifs)+1, "ввести вручную…"))
		p.tail = append([]string{""}, splitLines(panel(pickTips[:], m.pickStep, tw))...)
		p.hint, p.hintSt = "★ — подходит по типу · enter — выбрать · esc — назад", sDim
	case scRules:
		items := m.ruleItems()
		add(m.row(0, sGreen.Render("+")+" Добавить через корп. VPN…"))
		add(m.row(1, sGreen.Render("+")+" Добавить напрямую, мимо VPN…"))
		add(m.row(2, sCyan.Render("↓")+" Импорт из файла…"))
		add(m.row(3, sCyan.Render("↑")+" Экспорт в файл…"))
		add("")
		if len(items) == 0 {
			add(strings.Repeat(" ", rowIndent) + sGray.Render("правил пока нет"))
		}
		if m.cursor < ruleRows {
			p.focus = m.cursor
		} else {
			p.focus = len(p.list) + m.cursor - ruleRows
		}
		vw := min(32, max(cw-rowPrefix-ruleExtra, 8))
		for i, it := range items {
			kind := "домен"
			switch {
			case config.IsAS(it.val):
				kind = "AS   "
			case it.isNet:
				kind = "сеть "
			}
			where := sCyan.Render("корп.   ")
			if it.direct {
				where = sYel.Render("напрямую")
			}
			add(m.row(i+ruleRows, padRight(fit(it.val, vw), vw), where+" "+sGray.Render(kind)))
		}
		if m.delAsk && m.cursor >= ruleRows && m.cursor-ruleRows < len(items) {
			p.keep = append([]string{""}, m.blockLines(sYel, "Удалить «"+items[m.cursor-ruleRows].val+"»? y / enter — да, другая клавиша — нет")...)
		}
		p.tail = append([]string{""}, splitLines(panel([]tip{rulesTip}, 0, tw))...)
		p.hint, p.hintSt = "enter — выбрать · d — удалить · esc — назад", sDim
	case scStatus:
		p.scroll = true
		for _, l := range m.statusLines() {
			add(ind + l)
		}
		p.hint, p.hintSt, p.gap = "esc — назад", sDim, true
	case scSettings:
		c := m.cfg
		yesNo := map[bool]string{true: sGreen.Render("да"), false: sRed.Render("нет")}
		dns := c.CorpDNS
		if dns == "" {
			dns = "авто"
		}
		add(m.row(0, "Корп. DNS", sGray.Render(dns)))
		add(m.row(1, "Корп. шлюз", sGray.Render(orDash(c.CorpGateway))))
		add(m.row(2, "Остальной трафик -> домашний VPN", yesNo[c.HomeDefault]))
		add(m.row(3, "Корп. домены через корп. DNS", yesNo[c.SplitDNS]))
		p.focus = m.cursor
		p.tail = append([]string{""}, splitLines(panel(settingsTips, m.cursor, tw))...)
		p.hint, p.hintSt = "enter — изменить · esc — назад", sDim
	}
	return p
}
