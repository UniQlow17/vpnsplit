package tui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	scStatus
)

type (
	tickMsg   time.Time
	statusMsg struct {
		cfg          *config.Config
		env          router.Env
		st           *config.State
		routes       int
		apply, reset bool // what auto mode should do
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
	env        router.Env
	needApply  bool
	needReset  bool
	routes     int
	st         *config.State
	delAsk     bool // rules: waiting for "delete this rule?" answer
	scroll     int  // status screen
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
	sCyan  = lipgloss.NewStyle().Foreground(cCyan)
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
	admin := router.IsPrivileged()
	// with rights, keep routes in sync from the start: nothing to think about
	m := model{admin: admin, auto: admin, input: ti, spin: sp}
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func refreshCmd() tea.Cmd {
	return func() tea.Msg {
		st := config.LoadState()
		s := statusMsg{routes: len(st.Routes), st: st}
		if cfg, err := config.Load(); err == nil {
			s.cfg = cfg
			s.env = router.Detect(cfg)
			s.apply, s.reset = router.Sync(cfg, s.env, st)
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
		m.setFlash("Конфиг повреждён: исправьте или удалите его (vpnsplit reset --purge)")
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
		m.cfg, m.env, m.routes, m.st = msg.cfg, msg.env, msg.routes, msg.st
		m.needApply, m.needReset = msg.apply, msg.reset
		if m.auto && m.busy == "" && m.cfg != nil && m.admin && m.frame >= m.autoWait {
			if m.needApply {
				m.autoWait = m.frame + 100
				return m, m.startApply(true)
			}
			if m.needReset {
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
		// digits only move the cursor: 1..8 are items, 0 is exit
		i := int(k[0]-'0') - 1
		if k == "0" {
			i = itemExit
		}
		if i >= 0 && i < len(menuItems) {
			m.cursor = i
		}
		return m, nil
	}
	if m.sc == scStatus {
		return m.updateStatus(k)
	}
	if m.sc == scRules && m.delAsk {
		m.delAsk = false
		if k == "y" || k == "Y" || k == "enter" {
			m.deleteRule()
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
				if m.cfg == nil {
					m.setFlash("Конфиг повреждён: исправьте или удалите его (vpnsplit reset --purge)")
					return m, nil
				}
				m.ifs, m.pickStep, m.cursor, m.sc = vpnAdapters(), 0, 0, scPick
			case itemRules, itemSettings:
				if m.cfg == nil {
					m.setFlash("Конфиг повреждён: исправьте или удалите его (vpnsplit reset --purge)")
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
			case itemStatus:
				m.sc, m.scroll = scStatus, 0
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
			switch {
			case m.cursor == 0:
				m.choose(netif.Auto)
			case m.cursor <= len(m.ifs):
				m.choose(selector(m.ifs[m.cursor-1]))
			default:
				m.beginInput("pick", "", "Название VPN или имя адаптера: ")
				return m, textinput.Blink
			}
		}
	case scRules:
		// rows: 0 add corp, 1 add direct, then the rules
		switch {
		case k == "esc":
			m.sc, m.cursor = scMenu, itemRules
		case k == "a" || k == "n" || (k == "enter" || k == " ") && m.cursor == 0:
			m.beginInput("rule", "", "Через корп. VPN — сеть / IP / домен / AS: ")
			return m, textinput.Blink
		case k == "b" || (k == "enter" || k == " ") && m.cursor == 1:
			m.beginInput("direct", "", "Напрямую, мимо VPN — сеть / IP / домен / AS: ")
			return m, textinput.Blink
		case (k == "enter" || k == " ") && m.cursor == 2:
			m.beginInput("import", "~/Downloads/", "Файл со списком правил: ")
			return m, textinput.Blink
		case (k == "enter" || k == " ") && m.cursor == 3:
			m.beginInput("export", "~/Desktop/vpnsplit-rules.txt", "Сохранить правила в файл: ")
			return m, textinput.Blink
		case k == "enter" || k == " " || k == "d" || k == "delete" || k == "backspace":
			if m.cursor >= ruleRows {
				m.delAsk = true
			}
		}
	case scSettings:
		switch k {
		case "esc":
			m.sc, m.cursor = scMenu, itemSettings
		case "enter", " ":
			switch m.cursor {
			case 0:
				m.beginInput("dns", m.cfg.CorpDNS, "Корп. DNS (пусто = автоматически): ")
				return m, textinput.Blink
			case 1:
				m.beginInput("gw", m.cfg.CorpGateway, "Корп. шлюз (пусто = on-link): ")
				return m, textinput.Blink
			case 2:
				m.cfg.HomeDefault = !m.cfg.HomeDefault
				m.save()
			case 3:
				m.cfg.SplitDNS = !m.cfg.SplitDNS
				m.save()
			}
		}
	}
	return m, nil
}

// ruleRows is how many action rows (add corp, add direct, import, export)
// come before the rules on the rules screen.
const ruleRows = 4

// deleteRule removes the rule under the cursor.
func (m *model) deleteRule() {
	items := m.ruleItems()
	i := m.cursor - ruleRows
	if i < 0 || i >= len(items) {
		return
	}
	it := items[i]
	nets, domains := m.cfg.Lists(it.direct)
	if it.isNet {
		*nets, _ = config.RemoveVal(*nets, it.val)
	} else {
		*domains, _ = config.RemoveVal(*domains, it.val)
	}
	m.save()
	m.setFlash("Удалено: " + it.val + m.applyHint())
	if m.cursor >= len(items)+ruleRows-1 {
		m.cursor--
	}
}

// statusHeight is how many lines of the status screen fit at once.
const statusHeight = 18

func (m model) updateStatus(k string) (tea.Model, tea.Cmd) {
	maxScroll := max(len(m.statusLines())-statusHeight, 0)
	switch k {
	case "up", "k":
		m.scroll = max(m.scroll-1, 0)
	case "down", "j":
		m.scroll = min(m.scroll+1, maxScroll)
	case "pgup":
		m.scroll = max(m.scroll-statusHeight, 0)
	case "pgdown", " ":
		m.scroll = min(m.scroll+statusHeight, maxScroll)
	case "esc", "q", "enter":
		m.sc, m.cursor = scMenu, itemStatus
	}
	return m, nil
}

// statusLines is the content of the status screen: what is connected, the
// rules, and what is applied right now according to the journal.
func (m model) statusLines() []string {
	var out []string
	h := func(s string) { out = append(out, lipgloss.NewStyle().Bold(true).Foreground(cCyan).Render(s)) }
	line := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	c, e := m.cfg, m.env
	if c == nil {
		return []string{sRed.Render("Конфиг повреждён: исправьте или удалите его (vpnsplit reset --purge)")}
	}
	vpn := func(ok bool, i netif.Info, sel string) string {
		mode := sGray.Render(" (выбран: " + sel + ")")
		if netif.IsAuto(sel) {
			mode = sGray.Render(" (авто)")
		}
		if ok {
			return sGreen.Render(i.Label()) + mode
		}
		return sRed.Render("не подключён") + mode
	}
	h("Подключение")
	line("  Корп. VPN:  %s", vpn(e.CorpOK, e.Corp, c.Corp))
	line("  Домашний:   %s", vpn(e.HomeOK, e.Home, c.Home))
	if e.GWOK {
		line("  Напрямую:   %s", sGreen.Render(e.GW.Iface+" → "+e.GW.Router))
	} else {
		line("  Напрямую:   %s", sRed.Render("нет Wi-Fi/Ethernet шлюза"))
	}

	out = append(out, "")
	h("Правила")
	list := func(title string, nets, domains []string) {
		line("  %s (%d):", title, len(nets)+len(domains))
		for _, n := range nets {
			kind := "сеть"
			if config.IsAS(n) {
				kind = "все сети AS по данным RIPE"
			}
			line("    %s %s", n, sGray.Render(kind))
		}
		for _, d := range domains {
			line("    %s %s", d, sGray.Render("домен"))
		}
	}
	list("Через корп. VPN", c.Networks, c.Domains)
	list("Напрямую, мимо VPN", c.DirectNetworks, c.DirectDomains)
	line("  Остальное → домашний VPN: %s", map[bool]string{true: "да", false: "нет"}[c.HomeDefault])
	line("  Корп. домены через корп. DNS: %s", map[bool]string{true: "да", false: "нет"}[c.SplitDNS])

	out = append(out, "")
	st := m.st
	if st == nil {
		st = &config.State{}
	}
	h(fmt.Sprintf("Применено сейчас: %d маршрутов, %d DNS-записей", len(st.Routes), len(st.Resolvers)))
	if st.Empty() {
		line("  %s", sYel.Render("ничего — нажмите «Применить маршруты» или включите авто-режим"))
	}
	for _, g := range []struct{ via, title string }{
		{router.ViaCorp, "через корп. VPN"}, {router.ViaDirect, "напрямую"}, {router.ViaHome, "через домашний VPN"},
	} {
		var rs []config.Route
		for _, r := range st.Routes {
			if r.Via == g.via {
				rs = append(rs, r)
			}
		}
		if len(rs) == 0 {
			continue
		}
		line("  %s (%d):", g.title, len(rs))
		for _, r := range rs {
			via := r.Iface
			if r.Gateway != "" {
				via += " через " + r.Gateway
			}
			line("    %-20s → %s", r.Dest, sGray.Render(via))
		}
	}
	if len(st.Resolvers) > 0 {
		line("  DNS (%d):", len(st.Resolvers))
		for _, r := range st.Resolvers {
			line("    %s", r)
		}
	}
	if m.needApply && !st.Empty() {
		out = append(out, "", sYel.Render("VPN или правила изменились после применения — нужно применить заново"))
	}
	return out
}

// expandHome turns "~/x" into a path in the home directory.
func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, rest)
		}
	}
	return p
}

// vpnAdapters are the adapters worth offering: tunnels that are connected or
// that a VPN client was recognised on.
func vpnAdapters() []netif.Info {
	ifs, _ := netif.List()
	var out []netif.Info
	for _, i := range ifs {
		if (i.Kind == netif.KindCorp || i.Kind == netif.KindVPN) && (i.Connected() || i.Provider != "") {
			out = append(out, i)
		}
	}
	return out
}

// selector is what gets saved for an adapter: the VPN client name when it is
// known (it survives reconnects onto another adapter), else the adapter name.
func selector(i netif.Info) string {
	if i.Provider != "" {
		return i.Provider
	}
	return i.Name
}

// applyHint tells where a rule change takes effect.
func (m model) applyHint() string {
	if m.auto {
		return " (авто-режим применит сам)"
	}
	return " (нажмите «Применить»)"
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
	if name == m.cfg.Corp && !netif.IsAuto(name) {
		m.setFlash("Корп. и домашний VPN должны отличаться")
		return
	}
	m.cfg.Home = name
	m.save()
	m.sc, m.cursor = scMenu, 0
	m.setFlash("VPN сохранены")
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
		case "import":
			b, err := os.ReadFile(expandHome(v))
			if err != nil {
				m.setFlash("Не прочитать файл: " + err.Error())
				break
			}
			added, errs := m.cfg.ImportRules(string(b))
			m.save()
			msg := fmt.Sprintf("Импортировано новых правил: %d", added)
			if len(errs) > 0 {
				msg += fmt.Sprintf(", пропущено строк: %d (%v)", len(errs), errs[0])
			}
			m.setFlash(msg + m.applyHint())
		case "export":
			if err := config.WriteUserFile(expandHome(v), []byte(m.cfg.ExportRules())); err != nil {
				m.setFlash("Не сохранить: " + err.Error())
				break
			}
			m.setFlash("Правила сохранены в " + v)
		case "rule", "direct":
			isNet, val, err := config.NormalizeRule(v)
			if err != nil {
				m.setFlash(err.Error())
				break
			}
			nets, domains := m.cfg.Lists(m.purpose == "direct")
			if isNet {
				*nets = config.AddUnique(*nets, val)
			} else {
				*domains = config.AddUnique(*domains, val)
			}
			m.save()
			m.setFlash("Добавлено: " + val + m.applyHint())
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
	val    string
	isNet  bool
	direct bool
}

func (m model) ruleItems() []ruleItem {
	var out []ruleItem
	if m.cfg == nil {
		return out
	}
	for _, direct := range []bool{false, true} {
		nets, domains := m.cfg.Lists(direct)
		for _, n := range *nets {
			out = append(out, ruleItem{n, true, direct})
		}
		for _, d := range *domains {
			out = append(out, ruleItem{d, false, direct})
		}
	}
	return out
}

func (m model) listLen() int {
	switch m.sc {
	case scMenu:
		return len(menuItems)
	case scPick:
		return len(m.ifs) + 2 // auto + adapters + manual
	case scRules:
		return len(m.ruleItems()) + ruleRows
	case scSettings:
		return 4
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
	e := m.env
	// a connected VPN shows as "Check Point (utun4)", a missing one as what is awaited
	name := func(ok bool, i netif.Info, sel string) string {
		switch {
		case ok:
			return i.Label()
		case m.cfg == nil:
			return "—"
		case netif.IsAuto(sel):
			return "ждёт подключения"
		}
		return sel + " не подключён"
	}
	home := e.HomeOK && applied
	corp := e.CorpOK && applied
	var sel struct{ corp, home string }
	if m.cfg != nil {
		sel.corp, sel.home = m.cfg.Corp, m.cfg.Home
	}
	node := func(tag, label string) string {
		return lipgloss.NewStyle().Width(28).Render(tag + " " + sGray.Render(trunc(label, 22)))
	}
	l1 := fmt.Sprintf("  %s %s %s %s %s", lipgloss.NewStyle().Bold(true).Render("ТЫ"), m.flow(8, home),
		m.pulse(e.HomeOK), node("HOME  ", name(e.HomeOK, e.Home, sel.home)), m.flow(6, home)+" интернет")
	l2 := fmt.Sprintf("  %s %s %s %s %s", "  ", m.flow(8, corp),
		m.pulse(e.CorpOK), node("CORP  ", name(e.CorpOK, e.Corp, sel.corp)), m.flow(6, corp)+" интранет")
	out := l1 + "\n" + l2
	if m.cfg != nil && len(m.cfg.DirectNetworks)+len(m.cfg.DirectDomains) > 0 {
		gw := "нет Wi-Fi/Ethernet"
		if e.GWOK {
			gw = e.GW.Iface + " → " + e.GW.Router
		}
		direct := e.GWOK && applied
		out += "\n" + fmt.Sprintf("  %s %s %s %s %s", "  ", m.flow(8, direct),
			m.pulse(e.GWOK), node("DIRECT", gw), m.flow(6, direct)+" мимо VPN")
	}
	return out
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
	b.WriteString(rainbow("  ▌ VPN SPLIT ▐  ", m.frame) + sGray.Render(" корп. VPN + домашний VPN + напрямую") + "\n\n")
	b.WriteString(m.diagram() + "\n\n")

	status := sGray.Render("маршрутов: ") + fmt.Sprint(m.routes)
	switch {
	case m.needApply && m.routes > 0:
		status = sYel.Render("VPN или правила изменились, нужно применить ") + status
	case m.routes > 0:
		status = sGreen.Render("активно ") + status
	default:
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
		b.WriteString(m.row(0, "Авто — определять при каждом подключении", sGreen.Render("рекомендуется")) + "\n")
		for i, f := range m.ifs {
			st := sRed.Render("откл.")
			if f.Connected() {
				st = sGreen.Render("подкл.")
			}
			star := " "
			if f.Kind == hint {
				star = sYel.Render("★")
			}
			line := fmt.Sprintf("%-28s", trunc(f.Label(), 28))
			b.WriteString(m.row(i+1, line, star+" "+st+" "+sGray.Render(strings.Join(f.Addrs, ","))) + "\n")
		}
		b.WriteString(m.row(len(m.ifs)+1, "ввести вручную…") + "\n")
		b.WriteString("\n" + panel(pickTips[:], m.pickStep))
		b.WriteString("\n  " + sDim.Render("★ — подходит по типу · enter — выбрать · esc — назад"))
	case scRules:
		items := m.ruleItems()
		b.WriteString(m.row(0, sGreen.Render("+")+" Добавить через корп. VPN…") + "\n")
		b.WriteString(m.row(1, sGreen.Render("+")+" Добавить напрямую, мимо VPN…") + "\n")
		b.WriteString(m.row(2, sCyan.Render("↓")+" Импорт из файла…") + "\n")
		b.WriteString(m.row(3, sCyan.Render("↑")+" Экспорт в файл…") + "\n\n")
		if len(items) == 0 {
			b.WriteString("     " + sGray.Render("правил пока нет") + "\n")
		}
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
			b.WriteString(m.row(i+ruleRows, fmt.Sprintf("%-32s", it.val), where+" "+sGray.Render(kind)) + "\n")
		}
		if m.delAsk && m.cursor >= ruleRows && m.cursor-ruleRows < len(items) {
			b.WriteString("\n  " + sYel.Render("Удалить «"+items[m.cursor-ruleRows].val+"»? y / enter — да, другая клавиша — нет") + "\n")
		}
		b.WriteString("\n" + panel([]tip{rulesTip}, 0))
		b.WriteString("\n  " + sDim.Render("enter — выбрать · d — удалить · esc — назад"))
	case scStatus:
		lines := m.statusLines()
		end := min(m.scroll+statusHeight, len(lines))
		for _, l := range lines[min(m.scroll, end):end] {
			b.WriteString("  " + l + "\n")
		}
		more := ""
		if len(lines) > statusHeight {
			more = fmt.Sprintf("строки %d–%d из %d · ↑↓ / пробел — прокрутка · ", m.scroll+1, end, len(lines))
		}
		b.WriteString("\n  " + sDim.Render(more+"esc — назад"))
	case scSettings:
		c := m.cfg
		yesNo := map[bool]string{true: sGreen.Render("да"), false: sRed.Render("нет")}
		dns := c.CorpDNS
		if dns == "" {
			dns = "авто"
		}
		b.WriteString(m.row(0, "Корп. DNS", sGray.Render(dns)) + "\n")
		b.WriteString(m.row(1, "Корп. шлюз", sGray.Render(orDash(c.CorpGateway))) + "\n")
		b.WriteString(m.row(2, "Остальной трафик → домашний VPN", yesNo[c.HomeDefault]) + "\n")
		b.WriteString(m.row(3, "Корп. домены через корп. DNS", yesNo[c.SplitDNS]) + "\n")
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
