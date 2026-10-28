package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// boxPadding is the padding inside the frame: roomy on a wide terminal,
// minimal on a narrow or short one.
func (m model) boxPadding() (v, h int) {
	v, h = 1, 3
	if m.width > 0 && m.width < 70 {
		h = 1
	}
	if m.height > 0 && m.height < 30 {
		v = 0
	}
	return v, h
}

// contentW is the width available for text inside the frame.
func (m model) contentW() int {
	w := m.width
	if w <= 0 {
		w = defaultWidth
	}
	_, h := m.boxPadding()
	return max(w-rightMargin-2-2*h, 1)
}

// blockLines wraps text to the screen, styles every line and indents it.
func (m model) blockLines(st lipgloss.Style, text string) []string {
	lines := wrapLines(text, m.contentW()-textIndent)
	for i, l := range lines {
		lines[i] = strings.Repeat(" ", textIndent) + st.Render(l)
	}
	return lines
}

func (m model) pulse(up bool) string {
	if !up {
		return sRed.Render("○")
	}
	if (m.frame/5)%2 == 0 {
		return sGreen.Render("●")
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("29")).Render("●")
}

// flow draws a link between nodes; chevrons run along it while it is active.
func (m model) flow(n int, active bool) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		switch {
		case active && (i+m.frame/2)%5 == 0:
			b.WriteString(lipgloss.NewStyle().Foreground(cCyan).Bold(true).Render("›"))
		case active:
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("31")).Render("─"))
		default:
			b.WriteString(sDim.Render("╌"))
		}
	}
	return b.String()
}

// diagramTier is one size of the route scheme: link lengths, whether the
// "internet / intranet / bypass" tails are drawn and the smallest useful label.
type diagramTier struct {
	in, out int
	tail    bool
	minLbl  int
}

const (
	maxLabel = 24 // widest adapter label in the scheme
	tailText = 8  // width of "интернет", "интранет", "мимо VPN"
)

var diagramTiers = []diagramTier{{8, 6, true, 14}, {4, 3, true, 10}, {3, 0, false, 6}, {1, 0, false, 1}}

// overhead is the width of a scheme row without the label:
// "ТЫ " + in + " " + dot + " " + tag + " " [+ " " + out + " " + tail].
func (t diagramTier) overhead() int {
	n := 3 + t.in + 1 + 1 + 1 + tagWidth + 1
	if t.tail {
		n += 1 + t.out + 1 + tailText
	}
	return n
}

// diagramLayout picks the biggest tier that fits into w cells and the label width.
func diagramLayout(w int) (diagramTier, int) {
	for _, t := range diagramTiers {
		if l := min(maxLabel, w-t.overhead()); l >= t.minLbl {
			return t, l
		}
	}
	t := diagramTiers[len(diagramTiers)-1]
	return t, max(w-t.overhead(), 1)
}

// vpnName is how a VPN is named in the scheme: a connected one by its label,
// a missing one by what is awaited.
func (m model) vpnName(ok bool, i netif.Info, sel string) string {
	switch {
	case ok:
		return i.Label()
	case m.cfg == nil:
		return "-"
	case netif.IsAuto(sel):
		return "ждёт подключения"
	}
	return sel + " не подключён"
}

// compactDiagram is the scheme in one or two lines: a dot and a name per node.
func (m model) compactDiagram() []string {
	e := m.env
	var corpSel, homeSel string
	if m.cfg != nil {
		corpSel, homeSel = m.cfg.Corp, m.cfg.Home
	}
	aw := m.contentW() - textIndent
	node := func(tag string, up bool, label string, w int) string {
		s := m.pulse(up) + " " + tag
		if w > lipgloss.Width(tag)+3 {
			s += " " + sGray.Render(fit(label, w-lipgloss.Width(tag)-3))
		}
		return s
	}
	nodes := []struct {
		tag   string
		up    bool
		label string
	}{
		{"HOME", e.HomeOK, m.vpnName(e.HomeOK, e.Home, homeSel)},
		{"CORP", e.CorpOK, m.vpnName(e.CorpOK, e.Corp, corpSel)},
	}
	if m.cfg != nil && len(m.cfg.DirectNetworks)+len(m.cfg.DirectDomains) > 0 {
		gw := "нет Wi-Fi/Ethernet"
		if e.GWOK {
			gw = e.GW.Iface + " -> " + e.GW.Router
		}
		nodes = append(nodes, struct {
			tag   string
			up    bool
			label string
		}{"DIRECT", e.GWOK, gw})
	}
	// names while the whole scheme fits one line, then two lines, then dots only
	for _, share := range []int{aw / len(nodes), aw / 2, 0} {
		var parts []string
		for _, n := range nodes {
			parts = append(parts, node(n.tag, n.up, n.label, share-2))
		}
		lines := wrapLines(joinFit(aw, "  ", parts...), aw)
		if len(lines) <= 2 {
			for i, l := range lines {
				lines[i] = strings.Repeat(" ", textIndent) + l
			}
			return lines
		}
	}
	return nil
}

func (m model) diagram() string {
	applied := m.routes > 0
	e := m.env
	name := m.vpnName
	home := e.HomeOK && applied
	corp := e.CorpOK && applied
	var sel struct{ corp, home string }
	if m.cfg != nil {
		sel.corp, sel.home = m.cfg.Corp, m.cfg.Home
	}
	tier, lbl := diagramLayout(m.contentW() - textIndent)
	// A row never wraps: every part has a fixed display width.
	row := func(lead, tag string, on, up bool, label, tail string) string {
		s := "  " + lead + " " + m.flow(tier.in, on) + " " + m.pulse(up) + " " +
			padRight(tag+" "+sGray.Render(fit(label, lbl)), tagWidth+1+lbl)
		if tier.tail {
			s += " " + m.flow(tier.out, on) + " " + tail
		}
		return s
	}
	you := lipgloss.NewStyle().Bold(true).Render("ТЫ")
	out := row(you, "HOME  ", home, e.HomeOK, name(e.HomeOK, e.Home, sel.home), "интернет") + "\n" +
		row("  ", "CORP  ", corp, e.CorpOK, name(e.CorpOK, e.Corp, sel.corp), "интранет")
	if m.cfg != nil && len(m.cfg.DirectNetworks)+len(m.cfg.DirectDomains) > 0 {
		gw := "нет Wi-Fi/Ethernet"
		if e.GWOK {
			gw = e.GW.Iface + " -> " + e.GW.Router
		}
		out += "\n" + row("  ", "DIRECT", e.GWOK && applied, e.GWOK, gw, "мимо VPN")
	}
	return out
}

func (m model) row(i int, label string, extra ...string) string {
	e := strings.Join(extra, " ")
	// "     " + label + "  " + extra, or the same width with the selection
	if over := rowPrefix + lipgloss.Width(label) + lipgloss.Width(e) - m.contentW(); over > 0 {
		cut := min(over, max(lipgloss.Width(e)-4, 0))
		e = fit(e, lipgloss.Width(e)-cut)
		if over -= cut; over > 0 {
			label = fit(label, lipgloss.Width(label)-over)
		}
	}
	if i == m.cursor && !m.inputting {
		return "  " + sSel.Render(" ▸ "+label+" ") + " " + e
	}
	return strings.Repeat(" ", rowIndent) + label + strings.Repeat(" ", rowGap) + e
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
