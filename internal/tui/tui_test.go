package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/router"
)

func testModel() model {
	return model{
		cfg:   &config.Config{Corp: "corp0", Home: "home0", Networks: []string{"10.0.0.0/8"}, Domains: []string{"a.example.com"}},
		ifs:   []netif.Info{{Name: "home0", Up: true, Kind: netif.KindVPN}},
		input: newInput(),
	}
}

// Every screen must render, and the menu must show the hint of the selected item.
func TestViewAllScreens(t *testing.T) {
	for _, sc := range []screen{scMenu, scBusy, scResult, scConfirm, scPick, scRules, scAdvanced, scHelp, scDiag} {
		m := testModel()
		m.sc = sc
		if v := m.View(); v == "" {
			t.Errorf("screen %d rendered nothing", sc)
		}
	}
	for i, it := range menuItems {
		m := testModel()
		m.cursor = i
		v := m.View()
		first := strings.Fields(it.Hint)[0]
		if !strings.Contains(v, first) {
			t.Errorf("menu item %d: hint not shown (looked for %q)", i, first)
		}
	}
}

// A digit starts the item with that number at once; the keys ? and q are help and exit.
func TestDigitsStartItems(t *testing.T) {
	m := testModel()
	for k, want := range map[string]screen{"2": scRules, "3": scDiag, "4": scAdvanced} {
		got, _ := m.updateKeys(keyMsg(k))
		if gm := got.(model); gm.sc != want {
			t.Errorf("key %s: screen %d, want screen %d", k, gm.sc, want)
		}
	}
	// 1 is the switch: without rights it explains and does nothing
	got, cmd := m.updateKeys(keyMsg("1"))
	if gm := got.(model); cmd != nil || gm.on || gm.sc != scMenu || gm.flash == "" {
		t.Errorf("key 1 without rights: on=%v sc=%d cmd=%v flash=%q", gm.on, gm.sc, cmd, gm.flash)
	}
	// a digit beyond the items does nothing
	if got, cmd := m.updateKeys(keyMsg("9")); cmd != nil || got.(model).sc != scMenu {
		t.Error("digit 9 must do nothing")
	}
	got, _ = m.updateKeys(keyMsg("?"))
	if got.(model).sc != scHelp {
		t.Error("? must open the help")
	}
	if _, cmd := m.updateKeys(keyMsg("q")); cmd == nil {
		t.Error("q must quit")
	}
	for _, k := range []string{"0", "8"} {
		if got, cmd := m.updateKeys(keyMsg(k)); cmd != nil || got.(model).sc != scMenu {
			t.Errorf("key %s must do nothing", k)
		}
	}
}

func keyMsg(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// Rules start with the action rows; enter on a rule asks before deleting it.
func TestRulesAddAndDelete(t *testing.T) {
	m := testModel()
	m.sc = scRules
	got, _ := m.updateKeys(keyMsg("enter"))
	if mm := got.(model); !mm.inputting || mm.purpose != "rule" {
		t.Fatalf("enter on row 0 must ask for a corp rule, got inputting=%v purpose=%q", mm.inputting, mm.purpose)
	}
	m.cursor = 1
	got, _ = m.updateKeys(keyMsg("enter"))
	if mm := got.(model); mm.purpose != "direct" {
		t.Fatalf("enter on row 1 must ask for a direct rule, got %q", mm.purpose)
	}
	m.cursor = m.ruleRows()
	got, _ = m.updateKeys(keyMsg("enter"))
	mm := got.(model)
	if !mm.delAsk || len(mm.cfg.Networks) != 1 {
		t.Fatal("enter on a rule must ask first, not delete")
	}
	got, _ = mm.updateKeys(keyMsg("n"))
	if mm = got.(model); mm.delAsk || len(mm.cfg.Networks) != 1 {
		t.Fatal("any other key must cancel the delete")
	}
}

func plain(lines []string) string { return ansi.Strip(strings.Join(lines, "\n")) }

func TestStatusWithoutRightsSaysJournalIsAdminOnly(t *testing.T) {
	m := testModel()
	m.st = &config.State{}
	m.journal = config.JournalDenied
	got := plain(m.statusLines())
	if !strings.Contains(got, "журнал доступен только с правами администратора") {
		t.Errorf("no explanation:\n%s", got)
	}
	if strings.Contains(got, "ничего — нажмите") {
		t.Errorf("claims nothing is applied:\n%s", got)
	}
}

func TestWarningsAreFlashedOnceAndListed(t *testing.T) {
	m := testModel()
	m.st = &config.State{}
	m.warns = []string{`config: domains: rule "bad domain" dropped: x`, "journal: something"}
	m.flashWarnings()
	if !strings.Contains(m.flash, "bad domain") || !strings.Contains(m.flash, "ещё 1") {
		t.Errorf("flash = %q", m.flash)
	}
	m.flash = ""
	m.flashWarnings() // the same set again: no new flash
	if m.flash != "" {
		t.Errorf("flashed twice: %q", m.flash)
	}
	got := plain(m.statusLines())
	if !strings.Contains(got, "Предупреждения") || !strings.Contains(got, "bad domain") || !strings.Contains(got, "config.json.bak") {
		t.Errorf("warnings not listed:\n%s", got)
	}
}

func TestStatusListsEnvironmentFindings(t *testing.T) {
	m := testModel()
	m.st = &config.State{}
	if m.diagIndicator() != "" {
		t.Error("an indicator without findings")
	}
	if got := plain(m.statusLines()); !strings.Contains(got, "замечаний нет") {
		t.Error("a section without findings must say there are none")
	}
	m.diags = []router.Diag{
		{Code: "GPO_NRPT", Level: router.DiagDanger, TextRU: "политика задаёт NRPT", TextEN: "x", AdviceRU: "используйте IP"},
		{Code: "CORP_ONLINK", Level: router.DiagInfo, TextRU: "нет next hop", TextEN: "y"},
	}
	got := plain(m.statusLines())
	for _, w := range []string{"Окружение: 1 опасно, 1 заметок", "[опасно] GPO_NRPT", "политика задаёт NRPT", "-> используйте IP", "[инфо] CORP_ONLINK"} {
		if !strings.Contains(got, w) {
			t.Errorf("no %q in:\n%s", w, got)
		}
	}
	if ind := ansi.Strip(m.diagIndicator()); !strings.Contains(ind, "1 опасно") {
		t.Errorf("indicator %q", ind)
	}
	if rows := plain(m.statusRows()); !strings.Contains(rows, "окружение:") {
		t.Errorf("not in the status line: %q", rows)
	}
}
