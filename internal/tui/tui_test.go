package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

func testModel() model {
	return model{
		cfg: &config.Config{Corp: "corp0", Home: "home0", HomeDefault: true, Networks: []string{"10.0.0.0/8"}, Domains: []string{"a.example.com"}},
		ifs: []netif.Info{{Name: "home0", Up: true, Kind: netif.KindVPN}},
	}
}

// Every screen must render, and the menu must show the hint of the selected item.
func TestViewAllScreens(t *testing.T) {
	for _, sc := range []screen{scMenu, scBusy, scResult, scConfirm, scPick, scRules, scSettings, scHelp} {
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

func TestDigitsMoveCursorOnly(t *testing.T) {
	m := testModel()
	for k, want := range map[string]int{"1": itemApply, "6": itemAuto, "7": itemHelp, "0": itemExit} {
		got, cmd := m.updateKeys(keyMsg(k))
		if cmd != nil || got.(model).cursor != want || got.(model).sc != scMenu {
			t.Errorf("key %s: cursor=%d sc=%d cmd=%v, want cursor %d on the menu", k, got.(model).cursor, got.(model).sc, cmd, want)
		}
	}
}

func keyMsg(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}
