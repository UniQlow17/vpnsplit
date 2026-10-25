package tui

import "strings"

// tip is the explanation shown under a list for the selected row.
type tip struct {
	Hint  string
	Cmd   string // equivalent command line, if any
	Admin bool   // needs administrator / root
}

type menuItem struct {
	Label string
	tip
}

const (
	itemApply = iota
	itemReset
	itemAdapters
	itemRules
	itemSettings
	itemAuto
	itemHelp
	itemExit
)

var menuItems = []menuItem{
	itemApply: {"Применить маршруты", tip{
		Hint: "Добавляет маршруты в таблицу маршрутов ОС: корпоративные сети и домены из «Правил» уходят в адаптер корпоративного VPN, " +
			"а весь остальной трафик (если включено в «Настройках») — в домашний VPN. Оба VPN должны быть подключены. " +
			"Прежние маршруты утилиты перед этим удаляются, поэтому повторное применение безопасно. " +
			"Системный маршрут по умолчанию и DNS не меняются.",
		Cmd: "vpnsplit apply", Admin: true}},
	itemReset: {"Сбросить к исходным настройкам", tip{
		Hint: "Удаляет все маршруты, которые добавила утилита (она ведёт журнал), и возвращает маршрутизацию к тому, что настроили ОС и VPN-клиенты. " +
			"Работает даже при повреждённом конфиге. Используйте, если пропал интернет или перестали открываться сайты. " +
			"Заодно выключает авто-режим, иначе он вернёт маршруты обратно.",
		Cmd: "vpnsplit reset", Admin: true}},
	itemAdapters: {"VPN-адаптеры", tip{
		Hint: "Укажите, какой сетевой адаптер — корпоративный VPN, а какой — домашний. " +
			"Подходящие по названию помечены ★. Выбирайте при подключённых VPN; если адаптера в списке нет, введите его точное имя вручную. " +
			"Сначала выбирается корпоративный, затем домашний.",
		Cmd: "vpnsplit init"}},
	itemRules: {"Правила", tip{
		Hint: "Что должно идти через корпоративный VPN: сети (10.0.0.0/8), отдельные IP или домены (intranet.company.com). " +
			"Домены превращаются в IP в момент применения, поэтому после любых изменений нажмите «Применить маршруты». IPv6 не поддерживается.",
		Cmd: "vpnsplit add|remove|rules"}},
	itemSettings: {"Настройки", tip{
		Hint: "Корпоративный DNS, шлюз и поведение для остального трафика. Обычно достаточно значений по умолчанию; " +
			"DNS нужен, если корпоративные домены не резолвятся снаружи.",
		Cmd: "vpnsplit set <ключ> <значение>"}},
	itemAuto: {"Авто-режим", tip{
		Hint: "Пока открыто меню, утилита следит за VPN: когда подключены оба — применяет маршруты сама, когда один отключился — снимает. " +
			"Полезно, если корпоративный VPN при переподключении сбрасывает маршруты. Для постоянной работы без меню запустите watch в отдельном окне.",
		Cmd: "vpnsplit watch", Admin: true}},
	itemHelp: {"Справка", tip{
		Hint: "Как всё устроено, порядок первой настройки и что делать, если что-то пошло не так."}},
	itemExit: {"Выход", tip{
		Hint: "Закрыть меню. Применённые маршруты остаются в силе, пока вы их не сбросите или не отключите VPN."}},
}

var settingsTips = []tip{
	{Hint: "Корпоративный DNS-сервер. Если указан, корпоративные домены из «Правил» резолвятся через него, " +
		"а маршрут к самому серверу идёт через корпоративный VPN. Пусто — используется системный DNS.",
		Cmd: "vpnsplit set corp-dns <ip|none>"},
	{Hint: "Шлюз корпоративной сети. Нужен только если у VPN-адаптера есть настоящий шлюз, а маршрут «на интерфейс» не работает. " +
		"Пусто — маршруты привязываются к самому адаптеру (on-link), это подходит в большинстве случаев.",
		Cmd: "vpnsplit set corp-gateway <ip|none>"},
	{Hint: "Да: трафик вне правил принудительно идёт через домашний VPN (добавляются маршруты 0.0.0.0/1 и 128.0.0.0/1, " +
		"маршрут по умолчанию остаётся нетронутым). Нет: остальной трафик идёт так, как решит система.",
		Cmd: "vpnsplit set home-default <true|false>"},
}

var pickTips = [2]tip{
	{Hint: "Выберите виртуальный адаптер корпоративного VPN. " +
		"Если VPN сейчас не подключён, выберите «ввести имя вручную…» и укажите точное имя адаптера."},
	{Hint: "Выберите виртуальный адаптер домашнего VPN. " +
		"Он должен отличаться от корпоративного."},
}

var rulesTip = tip{
	Hint: "a — добавить сеть, IP или домен, d — удалить выбранное. Изменения вступят в силу после «Применить маршруты».",
	Cmd:  "vpnsplit add|remove <правило>",
}

const confirmText = "Будут удалены ТОЛЬКО маршруты, добавленные vpnsplit. Настройки VPN-клиентов, DNS и системные маршруты не затрагиваются."

var helpText = []string{
	"# Как это работает",
	"Утилита управляет таблицей маршрутов ОС. Адреса из «Правил» отправляются в корпоративный VPN, остальной трафик — в домашний. " +
		"Маршрут по умолчанию, DNS и настройки VPN-клиентов не меняются.",
	"",
	"# Первая настройка",
	"1. Подключите оба VPN: корпоративный и домашний.",
	"2. «VPN-адаптеры» — выберите корпоративный и домашний.",
	"3. «Правила» — добавьте корпоративные сети и домены.",
	"4. «Применить маршруты». При желании включите «Авто-режим».",
	"",
	"# Если что-то пошло не так",
	"Выберите «Сбросить к исходным настройкам» (или vpnsplit reset в консоли). Все добавленные маршруты будут удалены. " +
		"Если проблема осталась, переподключите VPN-клиенты.",
	"",
	"# Ограничения",
	"Только IPv4. VPN-клиенты должны работать в TUN-режиме (виртуальный адаптер). " +
		"Для применения и сброса нужны права администратора (Windows) или sudo (Linux, macOS).",
}

// wrapText breaks s into lines of at most width runes, keeping explicit newlines.
func wrapText(s string, width int) []string {
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		cur := ""
		for _, w := range strings.Fields(para) {
			switch {
			case cur == "":
				cur = w
			case len([]rune(cur))+1+len([]rune(w)) <= width:
				cur += " " + w
			default:
				lines = append(lines, cur)
				cur = w
			}
		}
		lines = append(lines, cur)
	}
	return lines
}

const tipWidth = 58

// tipLines renders a tip as wrapped lines: hint, admin marker, command.
func tipLines(t tip) []string {
	lines := wrapText(t.Hint, tipWidth)
	if t.Admin {
		lines = append(lines, sYel.Render("● требует прав администратора"))
	}
	if t.Cmd != "" {
		lines = append(lines, sDim.Render("⌨ ")+sGray.Render(t.Cmd))
	}
	return lines
}

// panel renders the tip of tips[idx] under a separator, padded to the height of
// the tallest tip so the layout does not jump while moving the cursor.
func panel(tips []tip, idx int) string {
	tall := 0
	for _, t := range tips {
		n := len(wrapText(t.Hint, tipWidth))
		if t.Admin {
			n++
		}
		if t.Cmd != "" {
			n++
		}
		if n > tall {
			tall = n
		}
	}
	var lines []string
	if idx >= 0 && idx < len(tips) {
		lines = tipLines(tips[idx])
	}
	for len(lines) < tall {
		lines = append(lines, "")
	}
	return "  " + sDim.Render(strings.Repeat("─", tipWidth)) + "\n  " + strings.Join(lines, "\n  ")
}

func menuTips() []tip {
	out := make([]tip, len(menuItems))
	for i, it := range menuItems {
		out[i] = it.tip
	}
	return out
}
