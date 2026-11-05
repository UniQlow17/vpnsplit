package tui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/termsize"
	"github.com/UniQlow17/vpnsplit/internal/tray"
)

type screen int

const (
	scMenu screen = iota
	scBusy
	scResult
	scConfirm
	scPick
	scRules
	scAdvanced
	scHelp
	scDiag
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
		diff         *router.Baseline     // the system against the state before the start; nil without rights
		diags        []router.Diag        // findings about the environment (proxy, client settings, overlaps...)
	}
	opDone struct {
		title string
		text  string
		err   error
		quiet bool
	}
	// tookOver is the answer of the [t] key: the routes of apply/watch are the session's now.
	tookOver struct{ err error }
	// diffMsg is the full comparison with the state before the start (DNS entries
	// included), made when the diagnostics screen is opened.
	diffMsg struct {
		b    router.Baseline
		seq  int  // the request it answers; an answer to an older one is dropped
		busy bool // an apply or reset was running when the reading began
	}
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
	mgr         *router.Manager     // owns the journal; nil without administrator rights and in tests
	readOnly    string              // why this copy may not change the network (no rights, or another copy owns it); "" if it may
	lastSession string              // how the previous session ended (from a file), shown on the status screen
	diff        *router.Baseline    // live difference from the state before the start (routes and rules only)
	diffSeq     int                 // number of the last request for the full comparison
	diffReading bool                // the request with number diffSeq is not answered yet
	diffPartial bool                // the comparison was read while routes were being changed: it may be incomplete
	fullDiff    *router.Baseline    // the same with the DNS entries, taken when the diagnostics screen is opened
	diags       []router.Diag       // findings about the environment, from the last refresh
	tr          *trayLink           // the icon in the notification area; nil without one
	resize      bool                // tell the user to enlarge a window that is too small
	refit       func(termsize.Size) // enlarges the window once more after the first status (nil: not at all)
	refitted    bool                // the window was fitted for the filled-in menu already
	small       bool                // resize is on and the window is smaller than the full menu needs: the footer asks to enlarge it
	on          bool                // the split switch: ON applies and keeps the routes in sync (every 2 s), OFF removes them
	autoWait    int                 // frame before which the sync does not try again
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
		if n := config.LegacyNote(true); n != "" {
			s.warns = append(s.warns, n) // an old journal that was found and not moved, and why
		}
		if cfg, cwarns, err := config.LoadChecked(); err == nil {
			s.cfg = cfg
			s.warns = append(s.warns, cwarns...)
			s.env = router.Detect(cfg)
			s.diags = router.Diagnose(cfg, s.env, st)
			s.apply, s.reset = router.Sync(cfg, s.env, st)
			if !s.apply && !s.reset && router.Drifted(st) {
				s.apply = true // routes of a reconnected VPN went with its old adapter
			}
		}
		if router.IsPrivileged() {
			// the routes and rules only: the DNS entries would start PowerShell on every refresh
			b := router.Diff(context.Background(), false)
			s.diff = &b
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

// startDisable removes what this session applied (the switch goes OFF): the same
// removal as at the exit, DNS first, but the session, its lock and the snapshot
// of the state before the start stay. Entries of apply/watch are not touched.
func (m *model) startDisable(quiet bool) tea.Cmd {
	if m.readOnly != "" || m.mgr == nil {
		m.setFlash(m.notOwner())
		return nil
	}
	m.busy, m.quiet = "Снимаю маршруты", quiet
	if !quiet {
		m.sc = scBusy
	}
	mgr := m.mgr
	return opCmd("Разделение выключено", quiet, func(w io.Writer) error { return disableRun(mgr, w) })
}

// disableRun removes what the session applied and reports it to w.
func disableRun(mgr *router.Manager, w io.Writer) error {
	rep, errs := mgr.Disable()
	fmt.Fprintf(w, "Снято записей: %d\n", rep.Total())
	if n := rep.Notice(true); n != "" {
		fmt.Fprintln(w, n)
	}
	for _, e := range errs {
		fmt.Fprintln(w, "  !", e)
	}
	if len(errs) > 0 {
		return fmt.Errorf("часть записей не снята: они остались в журнале, выход или повторное выключение доделает")
	}
	fmt.Fprintln(w, "Маршрутизация вернулась к исходной. Меню остаётся открытым: «Разделение: ВКЛ» применит правила снова.")
	return nil
}

// toggleSplit is the switch "Разделение": ON applies and keeps in sync, OFF removes.
func (m *model) toggleSplit() tea.Cmd {
	switch {
	case !m.admin:
		m.setFlash("Разделение требует прав администратора: " + router.PrivHint)
		return nil
	case m.readOnly != "" || m.mgr == nil:
		m.setFlash(m.notOwner())
		return nil
	case m.foreign():
		m.setFlash("Есть маршруты от apply/watch: нажмите [t], чтобы забрать их в сессию, затем включайте и выключайте разделение")
		return nil
	case m.busy != "":
		// a quiet automatic apply is running: a second operation would race it
		// for the journal, and the switch would not know which one it flips
		m.setFlash("Подождите, идёт синхронизация")
		return nil
	case m.cfg == nil:
		m.setFlash("Конфиг повреждён: исправьте или удалите его (vpnsplit reset --purge)")
		return nil
	}
	if m.on {
		m.on = false
		return m.startDisable(false)
	}
	m.on, m.autoWait = true, 0
	return m.startApply(false)
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
		text += fmt.Sprintf(" (и ещё %d, см. «Диагностику»)", n)
	}
	m.setFlash(text)
}

// Update is the step of the program; the icon in the notification area
// follows the state it leaves behind.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	nm, cmd := m.update(msg)
	if mm, ok := nm.(model); ok {
		mm.tr.push(mm)
	}
	return nm, cmd
}

func (m model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
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

	case trayToggleMsg:
		// the menu of the icon: the same switch as the menu item
		if !m.trayToggleOK() {
			m.setFlash("Значок: закончите текущее действие в окне, затем переключайте разделение")
			return m, nil
		}
		cmd := m.toggleSplit()
		return m, cmd

	case trayNoteMsg:
		m.setFlash(msg.text)
		return m, nil

	case trayRefreshMsg:
		return m, nil

	case spinner.TickMsg:
		var c tea.Cmd
		m.spin, c = m.spin.Update(msg)
		return m, c

	case statusMsg:
		m.refreshing = false
		m.cfg, m.env, m.routes, m.st = msg.cfg, msg.env, msg.routes, msg.st
		m.needApply, m.needReset = msg.apply, msg.reset
		m.warns, m.journal = msg.warns, msg.journal
		m.diff = msg.diff
		m.diags = msg.diags
		m.flashWarnings()
		var fit tea.Cmd
		if m.resize && !m.refitted && m.refit != nil {
			// the first status adds lines (warnings, findings) the empty menu did not have
			m.refitted = true
			refit, want := m.refit, m.wantSize()
			fit = func() tea.Msg { refit(want); return nil }
		}
		if m.on && m.busy == "" && m.cfg != nil && m.admin && !m.foreign() && m.frame >= m.autoWait {
			if m.needApply {
				m.autoWait = m.frame + 100
				return m, tea.Batch(fit, m.startApply(true))
			}
			if m.needReset {
				m.autoWait = m.frame + 100
				return m, tea.Batch(fit, m.startReset(true))
			}
		}
		return m, fit

	case tookOver:
		if msg.err != nil {
			m.setFlash("Не удалось забрать маршруты: " + msg.err.Error())
			return m, nil
		}
		m.on, m.autoWait = true, 0
		m.setFlash("Маршруты забраны в сессию: при выходе будут сняты")
		m.refreshing = true
		return m, refreshCmd()

	case opDone:
		m.busy = ""
		if msg.quiet {
			if msg.err != nil {
				m.setFlash("Разделение: " + msg.err.Error())
			} else {
				m.setFlash("Разделение: маршруты синхронизированы")
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
		if m.resize {
			// the request stays in the footer for as long as the window is too small
			m.small = !(termsize.Size{Cols: m.width, Rows: m.height}).Fits(m.wantSize())
		}
		return m, nil

	case diffMsg:
		if msg.seq != m.diffSeq {
			return m, nil // an answer to a request [r] has replaced
		}
		b := msg.b
		m.fullDiff, m.diffReading = &b, false
		// Diff reads the system without the lock of the manager, so a change in
		// progress (now or at the start of the reading) can show up as a difference
		m.diffPartial = msg.busy || m.busy != ""
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
	if (m.sc == scMenu || m.sc == scAdvanced) && len(k) == 1 && k[0] >= '1' && k[0] <= '9' {
		// a digit starts the item with that number at once, without enter
		if i := int(k[0]-'0') - 1; i < n {
			m.cursor = i
			return m.activate()
		}
		return m, nil
	}
	if m.sc == scDiag || m.sc == scHelp || m.sc == scResult {
		if m.scrollKey(k) {
			return m, nil
		}
		if m.sc == scDiag {
			switch k {
			case "esc", "q", "enter":
				m.sc, m.cursor = scMenu, itemDiag
			case "r":
				return m, m.diffCmd()
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
		case "m":
			if m.tr.canHideNow() {
				tray.ConsoleHide() // the window comes back from the icon or at exit
			}
		case "?":
			m.sc, m.scroll = scHelp, 0
		case "t":
			if !m.foreign() {
				return m, nil
			}
			mgr := m.mgr
			return m, func() tea.Msg { return tookOver{err: mgr.TakeOver()} }
		case "enter", " ":
			return m.activate()
		}
	case scHelp:
		m.sc, m.cursor = scMenu, itemSplit
	case scResult:
		m.sc, m.cursor = scMenu, 0
	case scBusy:
	case scConfirm:
		switch k {
		case "y", "Y", "enter":
			m.on = false
			m.setFlash("Разделение выключено, чтобы оно не вернуло маршруты")
			return m, m.startReset(false)
		default:
			m.sc, m.cursor = scAdvanced, advReset
		}
	case scPick:
		switch k {
		case "esc":
			m.sc, m.cursor = scAdvanced, advAdapters
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
		// rows: the actions (add corp, and add direct and add home where they matter), then the rules
		acts := m.ruleActions()
		on := func() string {
			if (k == "enter" || k == " ") && m.cursor < len(acts) {
				return acts[m.cursor].purpose
			}
			return ""
		}()
		switch {
		case k == "esc":
			m.sc, m.cursor = scMenu, itemRules
		case k == "a" || k == "n" || on == "rule":
			m.beginInput("rule", "", "Через корп. VPN — сеть / IP / домен / AS: ")
			return m, textinput.Blink
		case (k == "b" || on == "direct") && m.hasKind(config.DestDirect):
			m.beginInput("direct", "", "Напрямую, мимо VPN — сеть / IP / домен / AS: ")
			return m, textinput.Blink
		case (k == "h" || on == "home") && m.hasKind(config.DestHome):
			m.beginInput("home", "", "Через домашний VPN — сеть / IP / домен / AS: ")
			return m, textinput.Blink
		case k == "enter" || k == " " || k == "d" || k == "delete" || k == "backspace":
			if m.cursor >= len(acts) {
				m.delAsk = true
			}
		}
	case scAdvanced:
		switch k {
		case "esc":
			m.sc, m.cursor = scMenu, itemAdvanced
		case "enter", " ":
			return m.activate()
		}
	}
	return m, nil
}

// activate starts the item under the cursor: of the main menu, or a row of the
// screen "Дополнительно".
func (m model) activate() (tea.Model, tea.Cmd) {
	if m.sc == scAdvanced {
		return m.activateAdvanced()
	}
	switch m.cursor {
	case itemSplit:
		cmd := m.toggleSplit()
		return m, cmd
	case itemRules:
		if m.cfg == nil {
			m.setFlash(brokenConfig)
			return m, nil
		}
		m.sc, m.cursor = scRules, 0
	case itemDiag:
		m.sc, m.scroll = scDiag, 0
		return m, m.diffCmd()
	case itemAdvanced:
		m.sc, m.cursor = scAdvanced, 0
	}
	return m, nil
}

const brokenConfig = "Конфиг повреждён: исправьте или удалите его (vpnsplit reset --purge)"

// activateAdvanced starts the row under the cursor on the screen "Дополнительно".
func (m model) activateAdvanced() (tea.Model, tea.Cmd) {
	if m.cursor != advReset && m.cfg == nil {
		m.setFlash(brokenConfig)
		return m, nil
	}
	switch m.cursor {
	case advAdapters:
		m.ifs, m.pickStep, m.cursor, m.sc = vpnAdapters(), 0, 0, scPick
	case advDNS:
		m.beginInput("dns", m.cfg.CorpDNS, "Корп. DNS (пусто = автоматически): ")
		return m, textinput.Blink
	case advGateway:
		m.beginInput("gw", m.cfg.CorpGateway, "Корп. шлюз (пусто = on-link): ")
		return m, textinput.Blink
	case advRest:
		m.cfg.Rest = nextRest(m.cfg.Rest)
		m.save()
	case advSplitDNS:
		m.cfg.SplitDNS = !m.cfg.SplitDNS
		m.save()
	case advImport:
		m.beginInput("import", "~/Downloads/", "Файл со списком правил: ")
		return m, textinput.Blink
	case advExport:
		m.beginInput("export", "~/Desktop/vpnsplit-rules.txt", "Сохранить правила в файл: ")
		return m, textinput.Blink
	case advReset:
		if m.readOnly != "" || m.mgr == nil {
			m.setFlash(m.notOwner())
			return m, nil
		}
		m.sc = scConfirm
	}
	return m, nil
}

// diffCmd compares the system with the state before the start, DNS entries
// included (that can take a while, so it runs when the diagnostics are opened or
// refreshed with [r], not on every refresh). Without rights there is nothing to read.
func (m *model) diffCmd() tea.Cmd {
	if !m.admin {
		return nil
	}
	m.diffSeq++
	m.fullDiff, m.diffReading, m.diffPartial = nil, true, false
	seq, busy := m.diffSeq, m.busy != ""
	return func() tea.Msg { return diffMsg{b: router.Diff(context.Background(), true), seq: seq, busy: busy} }
}

// resizeAsk is the request to enlarge a window that is too small.
func resizeAsk(want termsize.Size) string {
	return "Окно меньше нужного: увеличьте его до " + want.String() + " (столбцов × строк), чтобы видеть всё меню"
}

// ruleAction is a row of actions on the rules screen.
type ruleAction struct{ purpose string }

// hasKind reports whether rules of a kind matter with the setting of the rest.
func (m model) hasKind(kind string) bool {
	return m.cfg != nil && slices.Contains(m.cfg.Kinds(), kind)
}

// ruleActions are the action rows before the rules: add for each kind that
// matters with the setting "rest of the traffic".
func (m model) ruleActions() []ruleAction {
	acts := []ruleAction{{"rule"}}
	if m.hasKind(config.DestDirect) {
		acts = append(acts, ruleAction{"direct"})
	}
	if m.hasKind(config.DestHome) {
		acts = append(acts, ruleAction{"home"})
	}
	return acts
}

// ruleRows is how many action rows come before the rules on the rules screen.
func (m model) ruleRows() int { return len(m.ruleActions()) }

// deleteRule removes the rule under the cursor.
func (m *model) deleteRule() {
	items := m.ruleItems()
	i := m.cursor - m.ruleRows()
	if i < 0 || i >= len(items) {
		return
	}
	it := items[i]
	nets, domains := m.cfg.ListsOf(it.kind)
	if it.isNet {
		*nets, _ = config.RemoveVal(*nets, it.val)
	} else {
		*domains, _ = config.RemoveVal(*domains, it.val)
	}
	m.save()
	m.setFlash("Удалено: " + it.val + m.applyHint())
	if m.cursor >= len(items)+m.ruleRows()-1 {
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
		if m.sc != scDiag {
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
	titles := map[string]string{config.DestCorp: "Через корп. VPN", config.DestDirect: "Напрямую, мимо VPN", config.DestHome: "Через домашний VPN"}
	for _, k := range c.Kinds() {
		nets, domains := c.ListsOf(k)
		list(titles[k], *nets, *domains)
	}
	if n := m.hiddenRules(); n > 0 {
		line("  %s", sGray.Render(fmt.Sprintf("Ещё %d правил не действуют при этом режиме «Остального трафика» и скрыты", n)))
	}
	line("  Остальной трафик: %s", config.RestLabel(c.Rest, true))
	line("  Корп. домены через корп. DNS: %s", map[bool]string{true: "да", false: "нет"}[c.SplitDNS])
	m.diagLines(&out, h)

	out = append(out, "")
	h("IPv6")
	switch lvl, _ := router.V6Status(c, m.env); lvl {
	case router.V6Leaks:
		line("  %s", sRed.Render(v6LeakText(m.env)))
	case router.V6Info:
		line("  %s", v6InfoText(m.env))
	default:
		line("  %s", sGray.Render("внимания не требует"))
	}

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
			line("  %s", sYel.Render("ничего — включите «Разделение»"))
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
	if d := m.shownDiff(); d != nil {
		out = append(out, "")
		h("Отличия от состояния до запуска (как `vpnsplit diff`)")
		if m.diffReading {
			line("  %s", sGray.Render("читаю…"))
		}
		if m.diffPartial {
			line("  %s", sYel.Render("Список может быть неполным: во время чтения шло применение"))
		}
		if d.Checked {
			line("  %s", d.Describe(true))
			if !d.Restored() {
				for _, l := range d.Lines(true) {
					line("    %s", sGray.Render(l))
				}
			}
		} else {
			line("  %s", sGray.Render(d.Lines(true)[0]))
		}
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
	if m.on {
		return " (разделение включено, применится само)"
	}
	return " (вступит в силу после «Разделение: ВКЛ»)"
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
	m.sc, m.cursor = scAdvanced, advAdapters
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
		case "rule", "direct", "home":
			isNet, val, err := config.NormalizeRule(v)
			if err != nil {
				m.setFlash(err.Error())
				break
			}
			nets, domains := m.cfg.ListsOf(purposeKind(m.purpose))
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
	val   string
	isNet bool
	kind  string // config.DestCorp, DestDirect or DestHome
}

func (m model) ruleItems() []ruleItem {
	var out []ruleItem
	if m.cfg == nil {
		return out
	}
	for _, kind := range m.cfg.Kinds() { // only the kinds that matter with the setting of the rest
		nets, domains := m.cfg.ListsOf(kind)
		for _, n := range *nets {
			out = append(out, ruleItem{n, true, kind})
		}
		for _, d := range *domains {
			out = append(out, ruleItem{d, false, kind})
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
		return len(m.ruleItems()) + m.ruleRows()
	case scAdvanced:
		return advCount
	}
	return 0
}

// purposeKind is the kind of rules an input purpose adds to.
func purposeKind(purpose string) string {
	switch purpose {
	case "direct":
		return config.DestDirect
	case "home":
		return config.DestHome
	}
	return config.DestCorp
}

// hiddenRules counts the rules of kinds that do not matter with the setting of
// the rest: they stay in the config and are not shown or applied.
func (m model) hiddenRules() int {
	n := 0
	if m.cfg == nil {
		return n
	}
	for _, k := range []string{config.DestDirect, config.DestHome} {
		if !m.hasKind(k) {
			nets, domains := m.cfg.ListsOf(k)
			n += len(*nets) + len(*domains)
		}
	}
	return n
}

// nextRest is the setting after this one in the order of the settings screen.
func nextRest(rest string) string {
	switch rest {
	case config.RestHome:
		return config.RestDirect
	case config.RestDirect:
		return config.RestKeep
	}
	return config.RestHome
}

// showsDirect reports whether the diagram has the DIRECT node: there are
// direct rules that apply, or the rest of the traffic goes direct.
func (m model) showsDirect() bool {
	if m.cfg == nil {
		return false
	}
	if m.cfg.Rest == config.RestDirect {
		return true
	}
	return m.hasKind(config.DestDirect) && len(m.cfg.DirectNetworks)+len(m.cfg.DirectDomains) > 0
}

// v6LeakText says in Russian why IPv6 goes past the home VPN.
func v6LeakText(e router.Env) string {
	switch {
	case !e.Home.HasV6():
		return "IPv6 идёт мимо домашнего VPN: у физического адаптера есть IPv6, у домашнего VPN нет"
	case e.V6Cap == router.V6CapV4Only:
		return "IPv6 идёт мимо домашнего VPN: его клиент забирает правилами только IPv4, у физического адаптера есть IPv6"
	}
	return "IPv6 идёт мимо домашнего VPN: направлять IPv6 в туннель на этой ОС пока не поддерживается"
}

// v6InfoText says in Russian what happens to IPv6 when it is handled.
func v6InfoText(e router.Env) string {
	switch e.V6Cap {
	case router.V6CapBoth:
		return "IPv6: через домашний VPN правилами его клиента"
	case router.V6CapUnknown:
		return "IPv6: на совести клиента домашнего VPN (не удалось определить, забирает ли он IPv6)"
	}
	return "IPv6: через домашний VPN (у него есть глобальный IPv6)"
}

// diagLines adds the section of the findings about the environment to the
// diagnostics screen: the level and code of each, what it is, and what to do.
func (m model) diagLines(out *[]string, h func(string)) {
	*out = append(*out, "")
	if len(m.diags) == 0 {
		h("Окружение")
		*out = append(*out, "  "+sGray.Render("замечаний нет"))
		return
	}
	h("Окружение: " + router.DiagSummary(m.diags, true))
	for _, d := range m.diags {
		tag := map[router.DiagLevel]lipgloss.Style{router.DiagDanger: sRed, router.DiagWarn: sYel, router.DiagInfo: sGray}[d.Level]
		*out = append(*out, "  "+tag.Render("["+diagLevelRU(d.Level)+"] "+d.Code)+" "+d.Text(true))
		if a := d.Advice(true); a != "" {
			*out = append(*out, "      "+sGray.Render("-> "+a))
		}
	}
}

// diagLevelRU names the level of a finding.
func diagLevelRU(l router.DiagLevel) string {
	switch l {
	case router.DiagDanger:
		return "опасно"
	case router.DiagWarn:
		return "внимание"
	}
	return "инфо"
}

// diagIndicator is the part of the status line that tells there are findings
// (nothing when there are none): the colour is the one of the worst level.
func (m model) diagIndicator() string {
	if len(m.diags) == 0 {
		return ""
	}
	st := sGray
	switch router.WorstDiag(m.diags) {
	case router.DiagDanger:
		st = sRed
	case router.DiagWarn:
		st = sYel
	}
	return st.Render("окружение: " + router.DiagSummary(m.diags, true) + " (см. Диагностику)")
}

// shownDiff is the comparison with the state before the start that the
// diagnostics show: the full one (DNS entries included) once it was read, the
// live one (routes and rules) before that.
func (m model) shownDiff() *router.Baseline {
	if m.fullDiff != nil {
		return m.fullDiff
	}
	return m.diff
}
