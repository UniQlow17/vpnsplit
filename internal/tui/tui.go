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
		apply, reset bool                 // what auto mode should do
		warns        []string             // config and journal problems found while loading
		journal      config.JournalStatus // whether the protected journal could be read
	}
	opDone struct {
		title string
		text  string
		err   error
		quiet bool
	}
	// tookOver is the answer of the [t] key: the routes of apply/watch are the session's now.
	tookOver struct{ err error }
)

type model struct {
	sc          screen
	cursor      int
	frame       int
	cfg         *config.Config
	env         router.Env
	needApply   bool
	needReset   bool
	routes      int
	st          *config.State
	warns       []string
	warnShown   string // the warnings already flashed, to flash a new set only
	journal     config.JournalStatus
	delAsk      bool // rules: waiting for "delete this rule?" answer
	scroll      int  // status screen
	admin       bool
	mgr         *router.Manager // owns the journal; nil without administrator rights and in tests
	readOnly    string          // why this copy may not change the network (no rights, or another copy owns it); "" if it may
	lastSession string          // how the previous session ended (from a file), shown on the status screen
	auto        bool
	autoWait    int
	busy        string
	quiet       bool
	resTitle    string
	resText     string
	resErr      bool
	ifs         []netif.Info
	pickStep    int
	input       textinput.Model
	inputting   bool
	purpose     string
	flash       string
	flashAt     int
	spin        spinner.Model
	refreshing  bool

	width, height int // terminal size from tea.WindowSizeMsg; 0 until known
	prompt        string
	inputDef      string    // prefilled text of the input, to tell whether it was touched
	lastKey       time.Time // when the previous key reached the input (paste detection)
	skipRest      bool      // dropping the lines of a pasted block after the first one
	burstText     bool      // the current key burst has already carried text
	streamPaste   bool      // a paste arrives as a key stream: Enter inside it is not a submit
	inputGen      int       // generation of the input, to drop a late clipboard answer
	hist          history   // undo and redo of the input field
	now           func() time.Time
	readFile      func(string) ([]byte, error)
}

// clock is the current time; tests replace it.
func (m model) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// open reads a file for import; tests replace it.
func (m model) open(path string) ([]byte, error) {
	if m.readFile != nil {
		return m.readFile(path)
	}
	return os.ReadFile(path)
}

var (
	cCyan   = lipgloss.Color("51")
	cGreen  = lipgloss.Color("42")
	cRed    = lipgloss.Color("203")
	cYellow = lipgloss.Color("220")
	cGray   = lipgloss.Color("244")
	cDim    = lipgloss.Color("238")

	sBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("39"))
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

// newInput is the text field used for all prompts.
func newInput() textinput.Model {
	ti := textinput.New()
	ti.CharLimit = 1024 // a long path in quotes must not be cut silently
	ti.Width = 40
	return ti
}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func refreshCmd() tea.Cmd {
	return func() tea.Msg {
		st, warns, journal := config.LoadStateStatus()
		s := statusMsg{routes: len(st.Routes), st: st, warns: warns, journal: journal}
		if w := deadSessionDNSWarning(st); w != "" {
			s.warns = append(s.warns, w)
		}
		if cfg, cwarns, err := config.LoadChecked(); err == nil {
			s.cfg = cfg
			s.warns = append(s.warns, cwarns...)
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
	if m.readOnly != "" || m.mgr == nil {
		m.setFlash(m.notOwner())
		return nil
	}
	m.busy, m.quiet = "Применяю маршруты", quiet
	if !quiet {
		m.sc = scBusy
	}
	cfg, mgr := m.cfg, m.mgr
	return opCmd("Применение маршрутов", quiet, func(w io.Writer) error { return mgr.Apply(cfg, w) })
}

// notOwner is why this copy may not change the network.
func (m *model) notOwner() string {
	if m.readOnly != "" {
		return m.readOnly
	}
	return "Нужны права администратора: " + router.PrivHint
}

func (m *model) startReset(quiet bool) tea.Cmd {
	if m.readOnly != "" || m.mgr == nil {
		m.setFlash(m.notOwner())
		m.sc = scMenu
		return nil
	}
	m.busy, m.quiet = "Сбрасываю маршруты", quiet
	if !quiet {
		m.sc = scBusy
	}
	mgr := m.mgr
	return opCmd("Сброс", quiet, func(w io.Writer) error {
		rep, errs := mgr.ResetReport()
		fmt.Fprintf(w, "Удалено маршрутов: %d\n", rep.Total())
		if n := rep.Notice(true); n != "" {
			fmt.Fprintln(w, n)
		}
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

// foreign reports whether the routes of apply/watch wait for the user to take them (the [t] key).
func (m model) foreign() bool { return m.mgr != nil && m.mgr.Foreign() }

// deadSessionDNSWarning is the warning about DNS rules a dead session left:
// they survive reboots and capture the DNS queries of their zones.
func deadSessionDNSWarning(st *config.State) string {
	if st.Mode != config.ModeSession || st.Owner == nil || len(st.Resolvers) == 0 || router.OwnerRunning(*st.Owner) {
		return ""
	}
	return "остались DNS-правила прошлого сеанса, запустите vpnsplit с правами администратора для очистки"
}

func (m *model) setFlash(s string) { m.flash, m.flashAt = s, m.frame+40 }

// flashWarnings tells about config or journal problems (dropped rules, a
// broken journal) once per distinct set, so they are not lost silently; the
// status screen keeps listing them.
func (m *model) flashWarnings() {
	key := strings.Join(m.warns, "\n")
	if key == m.warnShown {
		return
	}
	m.warnShown = key
	if len(m.warns) == 0 {
		return
	}
	text := "Внимание: " + m.warns[0]
	if n := len(m.warns) - 1; n > 0 {
		text += fmt.Sprintf(" (и ещё %d, см. «Статус»)", n)
	}
	m.setFlash(text)
}

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
		m.warns, m.journal = msg.warns, msg.journal
		m.flashWarnings()
		if m.auto && m.busy == "" && m.cfg != nil && m.admin && !m.foreign() && m.frame >= m.autoWait {
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

	case tookOver:
		if msg.err != nil {
			m.setFlash("Не удалось забрать маршруты: " + msg.err.Error())
			return m, nil
		}
		m.auto, m.autoWait = true, 0
		m.setFlash("Маршруты забраны в сессию: при выходе будут сняты")
		m.refreshing = true
		return m, refreshCmd()

	case opDone:
		m.busy = ""
		if msg.quiet {
			if msg.err != nil {
				m.setFlash("Авто-режим: " + msg.err.Error())
			} else {
				m.setFlash("Авто-режим: маршруты синхронизированы")
			}
		} else {
			m.sc, m.resTitle, m.resText, m.resErr, m.scroll = scResult, msg.title, msg.text, msg.err != nil, 0
			if msg.err != nil {
				m.resText += "\n\nОшибка: " + msg.err.Error()
			}
		}
		m.refreshing = true
		return m, refreshCmd()

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.fitInput()
		m.scroll = min(m.scroll, m.scrollMax())
		return m, nil

	case clipMsg:
		if !m.inputting || msg.gen != m.inputGen {
			return m, nil
		}
		if msg.err != nil {
			m.setFlash("Буфер обмена недоступен: " + msg.err.Error())
			return m, nil
		}
		m.insertPasted(msg.text)
		return m, nil

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
	if m.sc == scStatus || m.sc == scHelp || m.sc == scResult {
		if m.scrollKey(k) {
			return m, nil
		}
		if m.sc == scStatus {
			if k == "esc" || k == "q" || k == "enter" {
				m.sc, m.cursor = scMenu, itemStatus
			}
			return m, nil
		}
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
		case "t":
			if !m.foreign() {
				return m, nil
			}
			mgr := m.mgr
			return m, func() tea.Msg { return tookOver{err: mgr.TakeOver()} }
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
				if m.readOnly != "" {
					m.setFlash(m.readOnly)
					return m, nil
				}
				m.auto = !m.auto
				m.autoWait = 0
			case itemStatus:
				m.sc, m.scroll = scStatus, 0
			case itemHelp:
				m.sc, m.scroll = scHelp, 0
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

// scrollKey scrolls the status, help and result screens and reports whether
// the key was a scrolling key.
func (m *model) scrollKey(k string) bool {
	page := max(m.listHeight()-1, 1)
	switch k {
	case "up", "k":
		m.scroll--
	case "down", "j":
		m.scroll++
	case "pgup":
		m.scroll -= page
	case "pgdown":
		m.scroll += page
	case " ":
		if m.sc != scStatus {
			return false
		}
		m.scroll += page
	default:
		return false
	}
	m.scroll = max(min(m.scroll, m.scrollMax()), 0)
	return true
}

// statusLines is the content of the status screen: what is connected, the
// rules, and what is applied right now according to the journal.
func (m model) statusLines() []string {
	var out []string
	h := func(s string) { out = append(out, lipgloss.NewStyle().Bold(true).Foreground(cCyan).Render(s)) }
	line := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	c, e := m.cfg, m.env
	if c == nil {
		return wrapIndent(sRed.Render("Конфиг повреждён: исправьте или удалите его (vpnsplit reset --purge)"), m.contentW()-textIndent)
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
		line("  Напрямую:   %s", sGreen.Render(e.GW.Iface+" -> "+e.GW.Router))
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
	line("  Остальное -> домашний VPN: %s", map[bool]string{true: "да", false: "нет"}[c.HomeDefault])
	line("  Корп. домены через корп. DNS: %s", map[bool]string{true: "да", false: "нет"}[c.SplitDNS])

	out = append(out, "")
	st := m.st
	if st == nil {
		st = &config.State{}
	}
	switch m.journal {
	case config.JournalDenied:
		h("Применено сейчас")
		line("  %s", sYel.Render("журнал доступен только с правами администратора: что применено — неизвестно"))
	case config.JournalUnreadable:
		h("Применено сейчас")
		line("  %s", sRed.Render("журнал не читается (см. предупреждения ниже): что применено — неизвестно"))
	default:
		h(fmt.Sprintf("Применено сейчас: %d маршрутов, %d DNS-записей", len(st.Routes), len(st.Resolvers)))
		if st.Empty() {
			line("  %s", sYel.Render("ничего — нажмите «Применить маршруты» или включите авто-режим"))
		}
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
			line("    %-20s -> %s", r.Dest, sGray.Render(via))
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
	if m.lastSession != "" {
		out = append(out, "")
		h("Последний сеанс")
		line("  %s", sGray.Render(m.lastSession))
	}
	if len(m.warns) > 0 {
		out = append(out, "")
		h("Предупреждения")
		dropped := false
		for _, w := range m.warns {
			line("  %s", sYel.Render(w))
			dropped = dropped || strings.HasPrefix(w, "config:")
		}
		if dropped {
			line("  %s", sGray.Render("Исходный config.json сохранится как config.json.bak.* при следующем сохранении настроек"))
		}
	}
	// long lines (adapter names, rules) wrap instead of running off the screen
	var wrapped []string
	for _, l := range out {
		wrapped = append(wrapped, wrapIndent(l, m.contentW()-textIndent)...)
	}
	return wrapped
}

// expandHome turns a leading "~/" or tilde-backslash into a path in the home directory.
func expandHome(p string) string {
	for _, pre := range []string{"~/", `~\`} {
		if rest, ok := strings.CutPrefix(p, pre); ok {
			if h, err := os.UserHomeDir(); err == nil {
				return filepath.Join(h, rest)
			}
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
	m.inputGen++
	m.prompt, m.inputDef, m.skipRest, m.burstText, m.lastKey = prompt, val, false, false, m.clock()
	m.hist.reset()
	// the prompt is drawn on its own line: it may be longer than the screen
	m.input.Prompt, m.input.Placeholder = "> ", ""
	m.fitInput()
	m.input.SetValue(val)
	m.input.CursorEnd()
	m.input.Focus()
}

// fitInput sizes the text field to the terminal.
func (m *model) fitInput() {
	m.input.Width = min(max(m.contentW()-inputReserve, 8), 100)
}

// closeInput closes the input and forgets the paste state; a clipboard answer
// that is still on its way is dropped by the new generation.
func (m *model) closeInput() {
	m.inputting, m.skipRest, m.burstText = false, false, false
	m.inputGen++
	m.hist.reset()
}

func (m model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	now := m.clock()
	// On Windows a paste arrives as plain key events, line breaks included.
	// An Enter right behind another key is part of the paste, not a submit.
	d := now.Sub(m.lastKey)
	burst := m.streamPaste && d >= 0 && d < pasteBurst
	m.lastKey = now
	if !burst { // a new burst starts here
		m.skipRest, m.burstText = false, false
	}
	if msg.Paste { // bracketed paste (terminals that support it)
		m.insertPasted(string(msg.Runes))
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.closeInput()
		return m, nil
	case "ctrl+v":
		return m, clipboardCmd(m.inputGen)
	case "ctrl+z":
		m.undoInput()
		return m, nil
	case "ctrl+y":
		// bubbletea v1 cannot tell ctrl+shift+z from ctrl+z (the shift state
		// is lost on every OS), so redo lives on ctrl+y only
		m.redoInput()
		return m, nil
	case "enter":
		if burst {
			// only the first non-blank line of a pasted block is wanted:
			// leading blank lines are skipped, what follows the first line is dropped
			if m.burstText && !m.skipRest {
				m.skipRest = true
				m.setFlash(flashPasted)
			}
			return m, nil
		}
		v := strings.TrimSpace(m.input.Value())
		if pathPurpose(m.purpose) {
			v = resolvePath(m.input.Value(), m.inputDef)
		}
		m.closeInput()
		switch m.purpose {
		case "pick":
			if v != "" {
				m.choose(v)
			}
		case "import":
			b, err := m.open(expandHome(v))
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
		case "dns", "gw":
			ip := strings.TrimSpace(v)
			if ip != "" {
				var err error
				if ip, err = config.ParseIPv4(ip); err != nil {
					m.setFlash(err.Error())
					break
				}
			}
			if m.purpose == "dns" {
				m.cfg.CorpDNS = ip
			} else {
				m.cfg.CorpGateway = ip
			}
			m.save()
		}
		return m, nil
	}
	isText := msg.Type == tea.KeyRunes && strings.TrimSpace(string(msg.Runes)) != ""
	if m.skipRest {
		if isText && !pathPurpose(m.purpose) {
			m.setFlash(flashFirstLineOnly)
		}
		return m, nil
	}
	m.burstText = m.burstText || isText
	before := m.snapshot()
	var c tea.Cmd
	m.input, c = m.input.Update(msg)
	m.recordKey(before, burst, now)
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
