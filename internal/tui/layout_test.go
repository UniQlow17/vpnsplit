package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/router"
)

const (
	longCyr  = "Беспроводная сетевая карта Intel(R) Wi-Fi 6E AX211 160MHz"
	longProv = "Корпоративный клиент удалённого доступа"
)

// richModel is a model with long Cyrillic names everywhere text is shown.
func richModel(w int) model {
	m := testModel()
	m.width, m.height = w, 50
	m.routes, m.admin, m.needApply = 12, false, true
	m.cfg.DirectNetworks = []string{"192.168.100.0/24"}
	m.cfg.DirectDomains = []string{"очень-длинный-поддомен.телеработа.банк-россии.рф"}
	m.cfg.Domains = append(m.cfg.Domains, "very-long-intranet-hostname.subdomain.company.example.com")
	m.cfg.CorpDNS = "10.200.200.200,10.200.200.201,10.200.200.202"
	m.cfg.Corp, m.cfg.Home = longProv+" corp", "Happ (happ-xray)"
	vpn := netif.Info{Name: longCyr, Provider: longProv, Up: true, Kind: netif.KindCorp,
		Addrs: []string{"10.200.200.15", "fe80::1234:5678:9abc:def0", "172.16.0.15"}}
	m.ifs = []netif.Info{vpn, {Name: "Подключение по локальной сети 12", Kind: netif.KindVPN}}
	m.env = router.Env{
		Corp: vpn, CorpOK: true,
		Home: netif.Info{Name: "happ-xray", Provider: "Happ", Up: true}, HomeOK: true,
		GW: router.Gateway{Iface: "Беспроводная сеть", Router: "192.168.100.1"}, GWOK: true,
	}
	m.st = &config.State{
		Routes: []config.Route{
			{Dest: "10.0.0.0/8", Iface: longCyr, Gateway: "10.200.200.1", Via: router.ViaCorp},
			{Dest: "192.168.100.0/24", Iface: "Беспроводная сеть", Via: router.ViaDirect},
		},
		Resolvers: []string{"very-long-intranet-hostname.subdomain.company.example.com"},
	}
	m.resTitle = "Применение маршрутов с очень длинным заголовком результата"
	m.resText = "Удалено маршрутов: 3\n  ! " + strings.Repeat("ошибка ", 20) + "\n" + strings.Repeat("x", 90)
	m.busy = "Применяю маршруты"
	return m
}

func assertFits(t *testing.T, name, view string, w int) {
	t.Helper()
	for i, l := range strings.Split(view, "\n") {
		if got := lipgloss.Width(l); got > w {
			t.Errorf("%s: width %d, line %d is %d cells wide: %q", name, w, i, got, l)
		}
	}
}

var screenNames = map[screen]string{scMenu: "menu", scBusy: "busy", scResult: "result", scConfirm: "confirm",
	scPick: "pick", scRules: "rules", scSettings: "settings", scHelp: "help", scStatus: "status"}

// No line of any screen may be wider than the terminal, which is what makes
// lines wrap and break the frame.
func TestViewFitsTerminalWidth(t *testing.T) {
	for _, w := range []int{40, 60, 80, 120} {
		for sc, name := range screenNames {
			for _, cur := range []int{0, 1, 3, 5} {
				m := richModel(w)
				m.sc, m.cursor = sc, cur
				assertFits(t, name, m.View(), w)
				m.cfg = nil
				if sc != scSettings { // settings are only reachable with a config
					assertFits(t, name+"/nocfg", m.View(), w)
				}
			}
		}
		for _, purpose := range []string{"pick", "rule", "import"} {
			m := richModel(w)
			m.sc = scRules
			m.beginInput(purpose, "~/Downloads/", "Через корп. VPN — сеть / IP / домен / AS: ")
			m.setFlash("Не прочитать файл: open " + strings.Repeat("длинный-путь\\", 12) + ": нет такого файла")
			m.input.SetValue(strings.Repeat("п", 150))
			assertFits(t, "input/"+purpose, m.View(), w)
		}
		// delete confirmation and the scrolled status screen
		m := richModel(w)
		m.sc, m.delAsk, m.cursor = scRules, true, ruleRows
		assertFits(t, "rules/delete", m.View(), w)
		m = richModel(w)
		m.sc, m.scroll = scStatus, 3
		assertFits(t, "status/scroll", m.View(), w)
	}
}

// The scheme must keep one line per node and keep its columns aligned.
func TestDiagramRowsDoNotWrap(t *testing.T) {
	for _, w := range []int{30, 40, 50, 60, 80, 120} {
		m := richModel(w)
		lines := strings.Split(m.diagram(), "\n")
		if len(lines) != 3 {
			t.Fatalf("width %d: want 3 scheme rows, got %d:\n%s", w, len(lines), m.diagram())
		}
		first := lipgloss.Width(lines[0])
		for i, l := range lines {
			if lipgloss.Width(l) != first {
				t.Errorf("width %d: row %d is %d cells, row 0 is %d (columns shifted)", w, i, lipgloss.Width(l), first)
			}
			if lipgloss.Width(l) > m.contentW() {
				t.Errorf("width %d: row %d is wider than the frame content: %d > %d", w, i, lipgloss.Width(l), m.contentW())
			}
		}
	}
	// wide terminal keeps the full scheme, a narrow one drops the tails
	if d := richModel(120).diagram(); !strings.Contains(d, "интернет") || !strings.Contains(d, "мимо VPN") {
		t.Errorf("wide scheme lost its tails:\n%s", d)
	}
	if d := richModel(40).diagram(); strings.Contains(d, "интернет") {
		t.Errorf("narrow scheme must drop the tails:\n%s", d)
	}
}

func TestFitWorksOnDisplayWidth(t *testing.T) {
	for _, c := range []struct {
		in string
		w  int
	}{{"Беспроводная сеть", 8}, {"漢字漢字漢字", 5}, {"abc", 3}, {"abc", 2}, {"абв", 1}} {
		if got := fit(c.in, c.w); lipgloss.Width(got) > c.w {
			t.Errorf("fit(%q, %d) = %q is %d cells", c.in, c.w, got, lipgloss.Width(got))
		}
	}
	if got := fit("Беспроводная сеть", 8); !strings.HasSuffix(got, "…") {
		t.Errorf("a cut label must end with an ellipsis, got %q", got)
	}
	if got := padRight("Сеть", 8); lipgloss.Width(got) != 8 {
		t.Errorf("padRight width = %d", lipgloss.Width(got))
	}
}
