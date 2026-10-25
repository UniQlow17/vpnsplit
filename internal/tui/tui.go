package tui

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/router"
)

type screen int

const (
	scMenu screen = iota
	scBusy
	scResult
	scConfirm
	scPick
	scRules
	scSettings
	scHelp
)

type (
	tickMsg   time.Time
	statusMsg struct {
		cfg         *config.Config
		corp, home  bool
		routes      int
		fromRefresh bool
	}
	opDone struct {
		title string
		text  string
		err   error
		quiet bool
	}
)

type model struct {
	sc         screen
	cursor     int
	frame      int
	cfg        *config.Config
	corpUp     bool
	homeUp     bool
	routes     int
	admin      bool
	auto       bool
	autoWait   int
	busy       string
	quiet      bool
	resTitle   string
	resText    string
	resErr     bool
	ifs        []netif.Info
	pickStep   int
	input      textinput.Model
	inputting  bool
	purpose    string
	flash      string
	flashAt    int
	spin       spinner.Model
	refreshing bool
}

var (
	cCyan   = lipgloss.Color("51")
	cGreen  = lipgloss.Color("42")
	cRed    = lipgloss.Color("203")
	cYellow = lipgloss.Color("220")
	cGray   = lipgloss.Color("244")
	cDim    = lipgloss.Color("238")

	sBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("39")).Padding(1, 3)
	sSel   = lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(cCyan).Bold(true)
	sGray  = lipgloss.NewStyle().Foreground(cGray)
	sDim   = lipgloss.NewStyle().Foreground(cDim)
	sGreen = lipgloss.NewStyle().Foreground(cGreen).Bold(true)
	sRed   = lipgloss.NewStyle().Foreground(cRed).Bold(true)
	sYel   = lipgloss.NewStyle().Foreground(cYellow)
)

var gradient = []string{"33", "39", "45", "51", "87", "123", "87", "51", "45", "39"}

func rainbow(s string, frame int) string {
	var b strings.Builder
	for i, r := range []rune(s) {
		c := gradient[(i+frame/2)%len(gradient)]
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Bold(true).Render(string(r)))
	}
	return b.String()
}

// Run starts the interactive menu.
func Run() error {
	ti := textinput.New()
	ti.CharLimit = 120
	ti.Width = 40
	sp := spinner.New(spinner.WithSpinner(spinner.Dot))
	sp.Style = lipgloss.NewStyle().Foreground(cCyan)
	m := model{admin: router.IsPrivileged(), input: ti, spin: sp}
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func refreshCmd() tea.Cmd {
	return func() tea.Msg {
		s := statusMsg{routes: len(config.LoadState().Routes)}
		if cfg, err := config.Load(); err == nil {
			s.cfg = cfg
			s.corp, s.home = netif.Up(cfg.Corp), netif.Up(cfg.Home)
		}
		return s
	}
}

func opCmd(title string, quiet bool, f func(w io.Writer) error) tea.Cmd {
	return func() tea.Msg {
		var b bytes.Buffer
		var err error
		if !router.IsPrivileged() {
			err = fmt.Errorf("нужны права администратора: %s", router.PrivHint)
		} else {
			err = f(&b)
		}
		return opDone{title: title, text: strings.TrimSpace(b.String()), err: err, quiet: quiet}
	}
}

func (m model) Init() tea.Cmd { return tea.Batch(tick(), refreshCmd(), m.spin.Tick) }

func (m *model) startApply(quiet bool) tea.Cmd {
	if m.cfg == nil {
		m.setFlash("Сначала выберите VPN-адаптеры")
		return nil
	}
	m.busy, m.quiet = "Применяю маршруты", quiet
	if !quiet {
		m.sc = scBusy
	}
	cfg := m.cfg
	return opCmd("Применение маршрутов", quiet, func(w io.Writer) error { return router.Apply(cfg, w) })
}

func (m *model) startReset(quiet bool) tea.Cmd {
	m.busy, m.quiet = "Сбрасываю маршруты", quiet
	if !quiet {
		m.sc = scBusy
	}
	return opCmd("Сброс", quiet, func(w io.Writer) error {
		n, errs := router.Reset()
		fmt.Fprintf(w, "Удалено маршрутов: %d\n", n)
		for _, e := range errs {
			fmt.Fprintln(w, "  !", e)
		}
		if len(errs) > 0 {
			return fmt.Errorf("часть маршрутов не удалена, повторите сброс")
		}
		fmt.Fprintln(w, "Маршрутизация вернулась к исходной.")
		return nil
	})
}

func (m *model) setFlash(s string) { m.flash, m.flashAt = s, m.frame+40 }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		m.frame++
		var cmds []tea.Cmd
		cmds = append(cmds, tick())
		if m.frame%20 == 0 && !m.refreshing {
			m.refreshing = true
			cmds = append(cmds, refreshCmd())
		}
		return m, tea.Batch(cmds...)

	case spinner.TickMsg:
		var c tea.Cmd
		m.spin, c = m.spin.Update(msg)
		return m, c

	case statusMsg:
		m.refreshing = false
		m.cfg, m.corpUp, m.homeUp, m.routes = msg.cfg, msg.corp, msg.home, msg.routes
		if m.auto && m.busy == "" && m.cfg != nil && m.admin && m.frame >= m.autoWait {
			both := m.corpUp && m.homeUp
			if both && m.routes == 0 {
				m.autoWait = m.frame + 100
				return m, m.startApply(true)
			}
			if !both && m.routes > 0 {
				m.autoWait = m.frame + 100
				return m, m.startReset(true)
			}
		}
		return m, nil

	case opDone:
		m.busy = ""
		if msg.quiet {
			if msg.err != nil {
				m.setFlash("Авто-режим: " + msg.err.Error())
			} else {
				m.setFlash("Авто-режим: маршруты синхронизированы")
			}
		} else {
			m.sc, m.resTitle, m.resText, m.resErr = scResult, msg.title, msg.text, msg.err != nil
			if msg.err != nil {
				m.resText += "\n\nОшибка: " + msg.err.Error()
			}
		}
		m.refreshing = true
		return m, refreshCmd()

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.inputting {
			return m.updateInput(msg)
		}
		return m.updateKeys(msg)
	}
	return m, nil
}

func (m model) updateKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	n := m.listLen()
	if m.sc == scMenu && len(k) == 1 && k[0] >= '0' && k[0] <= '9' {
		// digits only move the cursor: 1..7 are items, 0 is exit
		i := int(k[0]-'0') - 1
		if k == "0" {
			i = itemExit
		}
		if i >= 0 && i < len(menuItems) {
			m.cursor = i
		}
		return m, nil
	}
	switch k {
	case "up", "k":
		if n > 0 {
			m.cursor = (m.cursor - 1 + n) % n
		}
		return m, nil
	case "down", "j":
		if n > 0 {
			m.cursor = (m.cursor + 1) % n
		}
		return m, nil
	}

	switch m.sc {
	case scMenu:
		switch k {
		case "q":
			return m, tea.Quit
		case "enter", " ":
			switch m.cursor {
			case itemApply:
				return m, m.startApply(false)
			case itemReset:
				m.sc = scConfirm
			case itemAdapters:
				ifs, _ := netif.List()
				m.ifs, m.pickStep, m.cursor, m.sc = ifs, 0, 0, scPick
			case itemRules, itemSettings:
				if m.cfg == nil {
					m.setFlash("Сначала выберите VPN-адаптеры")
					return m, nil
				}
				m.sc = scRules
				if m.cursor == itemSettings {
					m.sc = scSettings
				}
				m.cursor = 0
			case itemAuto:
				if !m.admin {
					m.setFlash("Авто-режим требует прав администратора: " + router.PrivHint)
					return m, nil
				}
				m.auto = !m.auto
				m.autoWait = 0
			case itemHelp:
				m.sc = scHelp
			case itemExit:
				return m, tea.Quit
			}
		}
	case scHelp:
		m.sc, m.cursor = scMenu, itemHelp
	case scResult:
		m.sc, m.cursor = scMenu, 0
	case scBusy:
	case scConfirm:
		switch k {
		case "y", "Y", "enter":
			m.auto = false
			m.setFlash("Авто-режим выключен, чтобы не вернуть маршруты")
			return m, m.startReset(false)
		default:
			m.sc = scMenu
		}
	case scPick:
		switch k {
		case "esc":
			m.sc, m.cursor = scMenu, itemAdapters
		case "enter":
			if m.cursor == len(m.ifs) {
				m.beginInput("pick", "", "Точное имя адаптера: ")
				return m, textinput.Blink
			}
			m.choose(m.ifs[m.cursor].Name)
		}
	case scRules:
		items := m.ruleItems()
		switch k {
		case "esc":
			m.sc, m.cursor = scMenu, itemRules
		case "a", "n":
			m.beginInput("rule", "", "Сеть / IP / домен: ")
			return m, textinput.Blink
		case "d", "delete", "backspace":
			if m.cursor < len(items) {
				it := items[m.cursor]
				if it.isNet {
					m.cfg.Networks, _ = config.RemoveVal(m.cfg.Networks, it.val)
				} else {
					m.cfg.Domains, _ = config.RemoveVal(m.cfg.Domains, it.val)
				}
				m.save()
				m.setFlash("Удалено: " + it.val + " (нажмите «Применить»)")
				if m.cursor > 0 {
					m.cursor--
				}
			}
		}
	case scSettings:
		switch k {
		case "esc":
			m.sc, m.cursor = scMenu, itemSettings
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.beginInput("dns", m.cfg.CorpDNS, "Корп. DNS (пусто = нет): ")
				return m, textinput.Blink
			case 1:
				m.beginInput("gw", m.cfg.CorpGateway, "Корп. шлюз (пусто = on-link): ")
				return m, textinput.Blink
			case 2:
				m.cfg.HomeDefault = !m.cfg.HomeDefault
				m.save()
			}
		}
	}
	return m, nil
}

func (m *model) choose(name string) {
	if m.cfg == nil {
		m.cfg = config.New()
	}
	if m.pickStep == 0 {
		m.cfg.Corp = name
		m.pickStep, m.cursor = 1, 0
		return
	}
	if name == m.cfg.Corp {
		m.setFlash("Корп. и домашний адаптеры должны отличаться")
		return
	}
	m.cfg.Home = name
	m.save()
	m.sc, m.cursor = scMenu, 0
	m.setFlash("Адаптеры сохранены")
}

func (m *model) save() {
	if err := config.Save(m.cfg); err != nil {
		m.setFlash("Ошибка сохранения: " + err.Error())
	}
}

func (m *model) beginInput(purpose, val, prompt string) {
	m.inputting, m.purpose = true, purpose
	m.input.Prompt, m.input.Placeholder = prompt, ""
	m.input.SetValue(val)
	m.input.CursorEnd()
	m.input.Focus()
}

func (m model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.inputting = false
		return m, nil
	case "enter":
		v := strings.TrimSpace(m.input.Value())
		m.inputting = false
		switch m.purpose {
		case "pick":
			if v != "" {
				m.choose(v)
			}
		case "rule":
			isNet, val, err := config.NormalizeRule(v)
			if err != nil {
				m.setFlash(err.Error())
				break
			}
			if isNet {
				m.cfg.Networks = config.AddUnique(m.cfg.Networks, val)
			} else {
				m.cfg.Domains = config.AddUnique(m.cfg.Domains, val)
			}
			m.save()
			m.setFlash("Добавлено: " + val + " (нажмите «Применить»)")
		case "dns":
			m.cfg.CorpDNS = v
			m.save()
		case "gw":
			m.cfg.CorpGateway = v
			m.save()
		}
		return m, nil
	}
	var c tea.Cmd
	m.input, c = m.input.Update(msg)
	return m, c
}

type ruleItem struct {
	val   string
	isNet bool
}

func (m model) ruleItems() []ruleItem {
	var out []ruleItem
	if m.cfg == nil {
		return out
	}
	for _, n := range m.cfg.Networks {
		out = append(out, ruleItem{n, true})
	}
	for _, d := range m.cfg.Domains {
		out = append(out, ruleItem{d, false})
	}
	return out
}

func (m model) listLen() int {
	switch m.sc {
	case scMenu:
		return len(menuItems)
	case scPick:
		return len(m.ifs) + 1
	case scRules:
		return len(m.ruleItems())
	case scSettings:
		return 3
	}
	return 0
}

// ---------- rendering ----------

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

func (m model) diagram() string {
	applied := m.routes > 0
	corpName, homeName := "не выбран", "не выбран"
	if m.cfg != nil {
		corpName, homeName = m.cfg.Corp, m.cfg.Home
	}
	home := m.homeUp && applied
	corp := m.corpUp && applied
	l1 := fmt.Sprintf("  %s %s %s %s %s", lipgloss.NewStyle().Bold(true).Render("ТЫ"), m.flow(10, home),
		m.pulse(m.homeUp), lipgloss.NewStyle().Width(16).Render("HOME "+sGray.Render(trunc(homeName, 11))), m.flow(8, home)+" интернет")
	l2 := fmt.Sprintf("  %s %s %s %s %s", "  ", m.flow(10, corp),
		m.pulse(m.corpUp), lipgloss.NewStyle().Width(16).Render("CORP "+sGray.Render(trunc(corpName, 11))), m.flow(8, corp)+" интранет")
	return l1 + "\n" + l2
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(rainbow("  ▌ VPN SPLIT ▐  ", m.frame) + sGray.Render(" двойной VPN: корп + домашний") + "\n\n")
	b.WriteString(m.diagram() + "\n\n")

	status := sGray.Render("маршрутов: ") + fmt.Sprint(m.routes)
	if m.routes > 0 {
		status = sGreen.Render("активно ") + status
	} else {
		status = sYel.Render("не применено ") + status
	}
	if !m.admin {
		status += "  " + sRed.Render("нет прав администратора")
	}
	b.WriteString("  " + status + "\n\n")

	switch m.sc {
	case scMenu:
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
			b.WriteString(m.row(i, fmt.Sprintf("%d) %s", num, label), extra) + "\n")
		}
		b.WriteString("\n" + panel(menuTips(), m.cursor))
	case scHelp:
		for _, l := range helpText {
			if h, ok := strings.CutPrefix(l, "# "); ok {
				b.WriteString("  " + lipgloss.NewStyle().Bold(true).Foreground(cCyan).Render(h) + "\n")
				continue
			}
			for _, w := range wrapText(l, tipWidth+4) {
				b.WriteString("  " + w + "\n")
			}
		}
		b.WriteString("\n  " + sGray.Render("любая клавиша — назад"))
	case scBusy:
		b.WriteString("  " + m.spin.View() + " " + m.busy + strings.Repeat(".", m.frame/3%4))
	case scResult:
		style := sGreen
		if m.resErr {
			style = sRed
		}
		b.WriteString("  " + style.Render(m.resTitle) + "\n\n")
		for _, l := range strings.Split(m.resText, "\n") {
			b.WriteString("  " + l + "\n")
		}
		b.WriteString("\n  " + sGray.Render("любая клавиша — назад"))
	case scConfirm:
		b.WriteString("  " + sYel.Render("Удалить все маршруты vpnsplit и вернуть исходную маршрутизацию?") + "\n\n")
		for _, l := range wrapText(confirmText, tipWidth) {
			b.WriteString("  " + sGray.Render(l) + "\n")
		}
		b.WriteString("\n  " + sGray.Render("y — да, любая другая клавиша — отмена"))
	case scPick:
		title := "Корпоративный VPN"
		hint := netif.KindCorp
		if m.pickStep == 1 {
			title, hint = "Домашний VPN", netif.KindVPN
		}
		b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render(title) + "\n\n")
		for i, f := range m.ifs {
			st := sRed.Render("down")
			if f.Up {
				st = sGreen.Render("up")
			}
			star := " "
			if f.Kind == hint {
				star = sYel.Render("★")
			}
			line := fmt.Sprintf("%-26s %-8s", trunc(f.Name, 26), f.Kind)
			b.WriteString(m.row(i, line, star+" "+st+" "+sGray.Render(strings.Join(f.Addrs, ","))) + "\n")
		}
		b.WriteString(m.row(len(m.ifs), "ввести имя вручную…") + "\n")
		b.WriteString("\n" + panel(pickTips[:], m.pickStep))
		b.WriteString("\n  " + sDim.Render("★ — подходит по названию · enter — выбрать · esc — назад"))
	case scRules:
		items := m.ruleItems()
		if len(items) == 0 {
			b.WriteString("  " + sGray.Render("правил пока нет, нажмите a") + "\n")
		}
		for i, it := range items {
			kind := "домен"
			if it.isNet {
				kind = "сеть "
			}
			b.WriteString(m.row(i, it.val, sGray.Render(kind)) + "\n")
		}
		b.WriteString("\n" + panel([]tip{rulesTip}, 0))
		b.WriteString("\n  " + sDim.Render("a — добавить · d — удалить · esc — назад"))
	case scSettings:
		c := m.cfg
		b.WriteString(m.row(0, "Корп. DNS", sGray.Render(orDash(c.CorpDNS))) + "\n")
		b.WriteString(m.row(1, "Корп. шлюз", sGray.Render(orDash(c.CorpGateway))) + "\n")
		b.WriteString(m.row(2, "Остальной трафик → домашний VPN", map[bool]string{true: sGreen.Render("да"), false: sRed.Render("нет")}[c.HomeDefault]) + "\n")
		b.WriteString("\n" + panel(settingsTips, m.cursor))
		b.WriteString("\n  " + sDim.Render("enter — изменить · esc — назад"))
	}

	if m.inputting {
		b.WriteString("\n\n  " + m.input.View() + "\n  " + sGray.Render("enter — ок · esc — отмена"))
	}
	if m.busy != "" && m.quiet {
		b.WriteString("\n\n  " + m.spin.View() + " " + m.busy)
	}
	if m.flash != "" && m.frame < m.flashAt {
		b.WriteString("\n\n  " + sYel.Render("› "+m.flash))
	}
	if m.sc == scMenu && !m.inputting {
		b.WriteString("\n\n  " + sDim.Render("↑↓ выбор · enter запуск · цифры — номер · q — выход"+"\n  "+"● — пункт требует прав администратора"))
	}
	return sBox.Render(b.String())
}

func (m model) row(i int, label string, extra ...string) string {
	e := strings.Join(extra, " ")
	if i == m.cursor && !m.inputting {
		return "  " + sSel.Render(" ▸ "+label+" ") + " " + e
	}
	return "     " + label + "  " + e
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
