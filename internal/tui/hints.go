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
	itemStatus
	itemSettings
	itemAuto
	itemHelp
	itemExit
)

var menuItems = []menuItem{
	itemApply: {"Применить маршруты", tip{
		Hint: "Корпоративные правила уходят в корпоративный VPN, правила «напрямую» — мимо любых VPN через Wi-Fi/Ethernet, " +
			"остальное — в домашний VPN. Работает с тем, что подключено сейчас, неподключённое пропускается. " +
			"Прежние маршруты утилиты перед этим удаляются, поэтому повторное применение безопасно. " +
			"Маршруты, которые уже поставил VPN-клиент, не трогаются.",
		Cmd: "vpnsplit apply", Admin: true}},
	itemReset: {"Сбросить к исходным настройкам", tip{
		Hint: "Удаляет все маршруты и DNS-записи, которые добавила утилита (она ведёт журнал), и возвращает всё к тому, что настроили ОС и VPN-клиенты. " +
			"Работает даже при повреждённом конфиге. Используйте, если пропал интернет или перестали открываться сайты. " +
			"Заодно выключает авто-режим, иначе он вернёт маршруты обратно.",
		Cmd: "vpnsplit reset", Admin: true}},
	itemAdapters: {"VPN-адаптеры", tip{
		Hint: "По умолчанию «Авто»: утилита сама находит Check Point, Cisco, Happ, BlancVPN, WireGuard и другие клиенты при каждом подключении, " +
			"даже если адаптер сменил номер. Здесь можно закрепить конкретный VPN по названию. " +
			"Сначала выбирается корпоративный, затем домашний.",
		Cmd: "vpnsplit init"}},
	itemRules: {"Правила: добавить / удалить", tip{
		Hint: "Корпоративные — что идёт через корпоративный VPN (10.0.0.0/8, intranet.company.com). " +
			"Напрямую — что идёт мимо всех VPN, например сервисы, которые не пускают с иностранных IP (telework.bank.ru). " +
			"Домены превращаются в IP в момент применения. IPv6 не поддерживается.",
		Cmd: "vpnsplit add|remove|rules"}},
	itemStatus: {"Текущее состояние", tip{
		Hint: "Что подключено, какие правила заданы и что реально применено сейчас: каждый маршрут (куда и через какой адаптер) " +
			"и DNS-записи. Видно и то, что VPN или правила изменились после последнего применения.",
		Cmd: "vpnsplit status"}},
	itemSettings: {"Настройки", tip{
		Hint: "Корпоративный DNS, шлюз и поведение для остального трафика. Обычно достаточно значений по умолчанию; " +
			"DNS нужен, если корпоративные домены не резолвятся снаружи.",
		Cmd: "vpnsplit set <ключ> <значение>"}},
	itemAuto: {"Авто-режим", tip{
		Hint: "Пока открыто меню, утилита следит за VPN: подключился — применяет маршруты, все отключились — снимает, " +
			"когда VPN переподключился на другой адаптер, сменилась сеть или правила — применяет заново. " +
			"Включается сам, если меню запущено с sudo. Для работы без меню запустите watch в отдельном окне.",
		Cmd: "vpnsplit watch", Admin: true}},
	itemHelp: {"Справка", tip{
		Hint: "Как всё устроено, порядок первой настройки и что делать, если что-то пошло не так."}},
	itemExit: {"Выход", tip{
		Hint: "Закрыть меню. Применённые маршруты остаются в силе, пока вы их не сбросите или не отключите VPN."}},
}

var settingsTips = []tip{
	{Hint: "Корпоративный DNS-сервер. Пусто — определяется автоматически: берутся DNS-серверы, которые корпоративный клиент " +
		"зарегистрировал в системе и которые доступны через корпоративный VPN. Если указан, маршрут к нему идёт через корпоративный VPN.",
		Cmd: "vpnsplit set corp-dns <ip|none>"},
	{Hint: "Шлюз корпоративной сети. Нужен только если у VPN-адаптера есть настоящий шлюз, а маршрут «на интерфейс» не работает. " +
		"Пусто — маршруты привязываются к самому адаптеру (on-link), это подходит в большинстве случаев.",
		Cmd: "vpnsplit set corp-gateway <ip|none>"},
	{Hint: "Да: трафик вне правил принудительно идёт через домашний VPN (добавляются маршруты 0.0.0.0/1 и 128.0.0.0/1, " +
		"маршрут по умолчанию остаётся нетронутым). Нет: остальной трафик идёт так, как решит система.",
		Cmd: "vpnsplit set home-default <true|false>"},
	{Hint: "Да: корпоративные домены (зоны корпоративного DNS и домены из «Правил») всегда резолвятся через корпоративный DNS, " +
		"даже если домашний VPN подменил системный DNS (так делает, например, BlancVPN). macOS — файлы в /etc/resolver, " +
		"Windows — правила NRPT, Linux — домены маршрутизации systemd-resolved. Сброс их удаляет.",
		Cmd: "vpnsplit set split-dns <true|false>"},
}

var pickTips = [2]tip{
	{Hint: "«Авто» подходит почти всегда. Выбор конкретного VPN сохраняется по названию клиента, " +
		"поэтому переживает переподключения. Если клиента нет в списке, введите его название или имя адаптера вручную."},
	{Hint: "«Авто» берёт любой подключённый домашний VPN, так что можно переключаться между Happ, BlancVPN и другими " +
		"без перенастройки. Он должен отличаться от корпоративного."},
}

var rulesTip = tip{
	Hint: "«+ Добавить…» — ввести сеть (10.0.0.0/8), IP, домен или номер AS (AS49675 — все сети организации по данным RIPE). " +
		"«Импорт» добавляет правила из файла, " +
		"который кто-то сохранил «Экспортом». Enter на правиле — удалить его. " +
		"Изменения вступят в силу после «Применить маршруты» (в авто-режиме — сами).",
	Cmd: "vpnsplit add|remove [--direct] <правило>",
}

const confirmText = "Будут удалены ТОЛЬКО маршруты и DNS-записи, добавленные vpnsplit. Настройки VPN-клиентов и системные маршруты не затрагиваются."

var helpText = []string{
	"# Как это работает",
	"Утилита управляет таблицей маршрутов ОС. Корпоративные правила идут в корпоративный VPN, правила «напрямую» — через Wi-Fi/Ethernet мимо VPN, " +
		"остальной трафик — в домашний VPN. VPN-клиенты определяются автоматически. Корпоративные домены дополнительно " +
		"резолвятся через корпоративный DNS. Маршрут по умолчанию и настройки VPN-клиентов не меняются.",
	"",
	"# Первая настройка",
	"1. Запустите меню с sudo: авто-режим включится сам.",
	"2. Подключите VPN: корпоративный и/или домашний.",
	"3. «Правила» — добавьте, что идёт напрямую (b), и при необходимости корпоративное (a).",
	"Всё. «VPN-адаптеры» трогать не нужно, если клиент определился (видно на схеме вверху).",
	"",
	"# Если что-то пошло не так",
	"Выберите «Сбросить к исходным настройкам» (или vpnsplit reset в консоли). Все добавленные маршруты будут удалены. " +
		"Если проблема осталась, переподключите VPN-клиенты.",
	"",
	"# Ограничения",
	"Только IPv4. VPN-клиенты должны работать в TUN-режиме (виртуальный адаптер). " +
		"Для применения и сброса нужны права администратора (Windows) или sudo (Linux, macOS).",
}

const tipWidth = 58

// tipLines renders a tip as wrapped lines of at most width cells: hint, admin
// marker, command.
func tipLines(t tip, width int) []string {
	lines := wrapLines(t.Hint, width)
	if t.Admin {
		for _, l := range wrapLines("● требует прав администратора", width) {
			lines = append(lines, sYel.Render(l))
		}
	}
	if t.Cmd != "" {
		// "> " instead of a keyboard emoji: its width differs between terminals
		for i, l := range wrapLines("> "+t.Cmd, width) {
			if rest, ok := strings.CutPrefix(l, "> "); ok && i == 0 {
				lines = append(lines, sDim.Render("> ")+sGray.Render(rest))
				continue
			}
			lines = append(lines, sGray.Render(l))
		}
	}
	return lines
}

// panel renders the tip of tips[idx] under a separator, padded to the height of
// the tallest tip so the layout does not jump while moving the cursor.
func panel(tips []tip, idx, width int) string {
	tall := 0
	for _, t := range tips {
		tall = max(tall, len(tipLines(t, width)))
	}
	var lines []string
	if idx >= 0 && idx < len(tips) {
		lines = tipLines(tips[idx], width)
	}
	for len(lines) < tall {
		lines = append(lines, "")
	}
	return "  " + sDim.Render(strings.Repeat("─", width)) + "\n  " + strings.Join(lines, "\n  ")
}

func menuTips() []tip {
	out := make([]tip, len(menuItems))
	for i, it := range menuItems {
		out[i] = it.tip
	}
	return out
}
