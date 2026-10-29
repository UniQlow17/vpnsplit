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

// Items of the main menu. Help and exit are keys (? and q), not items.
const (
	itemSplit = iota
	itemRules
	itemDiag
	itemAdvanced
)

var menuItems = []menuItem{
	itemSplit: {"Разделение", tip{
		Hint: "Включает и выключает разделение трафика. ВКЛ: корпоративные правила уходят в корпоративный VPN, правила «напрямую» — " +
			"мимо любых VPN через Wi-Fi/Ethernet, остальное — по выбранному в «Дополнительно» (по умолчанию в домашний VPN); " +
			"пока меню открыто, утилита следит за VPN и сама применяет маршруты заново. ВЫКЛ: сразу снимает всё, что добавила эта сессия, " +
			"и возвращает маршрутизацию, как до запуска; меню остаётся открытым. Маршруты, которые уже поставил VPN-клиент, не трогаются.",
		Cmd: "vpnsplit run", Admin: true}},
	itemRules: {"Правила: добавить / удалить", tip{
		Hint: "Корпоративные — что идёт через корпоративный VPN (10.0.0.0/8, intranet.company.com). " +
			"Напрямую — что идёт мимо всех VPN, например сервисы, которые не пускают с иностранных IP (telework.bank.ru). " +
			"Домены превращаются в IP в момент применения. IPv6 не поддерживается.",
		Cmd: "vpnsplit add|remove|rules"}},
	itemDiag: {"Диагностика", tip{
		Hint: "Что подключено, какие правила заданы и что применено сейчас; предупреждения об окружении (прокси, строгий режим клиента, fake-ip, " +
			"пересечения сетей) с советами; состояние IPv6; чем система отличается от состояния до запуска; записи журнала.",
		Cmd: "vpnsplit status | vpnsplit diff"}},
	itemAdvanced: {"Дополнительно", tip{
		Hint: "VPN-адаптеры, корпоративный DNS и шлюз, «Остальной трафик», корпоративные домены через корпоративный DNS, " +
			"импорт и экспорт правил, полный сброс. Обычно достаточно значений по умолчанию."}},
}

// Rows of the screen "Дополнительно".
const (
	advAdapters = iota
	advDNS
	advGateway
	advRest
	advSplitDNS
	advImport
	advExport
	advReset
	advCount
)

var advancedTips = [advCount]tip{
	advAdapters: {Hint: "По умолчанию «Авто»: утилита сама находит Check Point, Cisco, Happ, BlancVPN, WireGuard и другие клиенты при каждом подключении, " +
		"даже если адаптер сменил номер. Здесь можно закрепить конкретный VPN по названию. Сначала выбирается корпоративный, затем домашний.",
		Cmd: "vpnsplit init"},
	advDNS: {Hint: "Корпоративный DNS-сервер. Пусто — определяется автоматически: берутся DNS-серверы, которые корпоративный клиент " +
		"зарегистрировал в системе и которые доступны через корпоративный VPN. Если указан, маршрут к нему идёт через корпоративный VPN.",
		Cmd: "vpnsplit set corp-dns <ip|none>"},
	advGateway: {Hint: "Шлюз корпоративной сети. Нужен только если у VPN-адаптера есть настоящий шлюз, а маршрут «на интерфейс» не работает. " +
		"Пусто — маршруты привязываются к самому адаптеру (on-link), это подходит в большинстве случаев.",
		Cmd: "vpnsplit set corp-gateway <ip|none>"},
	advRest: {Hint: "Куда идёт трафик, не названный ни одним правилом. Домашний VPN: через него (0.0.0.0/1 и 128.0.0.0/1, а если у него есть " +
		"глобальный IPv6 — ещё ::/1 и 8000::/1; DNS домашнего VPN для остальных имён; на Windows отключаются Teredo/6to4/ISATAP). " +
		"Напрямую: мимо всех VPN через шлюз Wi-Fi/Ethernet; тогда появляется список «через домашний VPN». " +
		"Не трогать: как настроил VPN-клиент — ни маршрутов по умолчанию, ни DNS для остального.",
		Cmd: "vpnsplit set rest <home|direct|keep>"},
	advSplitDNS: {Hint: "Да: корпоративные домены (зоны корпоративного DNS и домены из «Правил») всегда резолвятся через корпоративный DNS, " +
		"даже если домашний VPN подменил системный DNS (так делает, например, BlancVPN). macOS — файлы в /etc/resolver, " +
		"Windows — правила NRPT, Linux — домены маршрутизации systemd-resolved. «Разделение: ВЫКЛ» их удаляет.",
		Cmd: "vpnsplit set split-dns <true|false>"},
	advImport: {Hint: "Добавляет правила из файла, который кто-то сохранил «Экспортом».",
		Cmd: "vpnsplit import <файл>"},
	advExport: {Hint: "Сохраняет правила в файл, который можно передать другому или импортировать на другом компьютере.",
		Cmd: "vpnsplit export [файл]"},
	advReset: {Hint: "Удаляет ВСЕ маршруты и DNS-записи, которые добавила утилита (она ведёт журнал), в том числе оставленные командами apply и watch, " +
		"и возвращает всё к тому, что настроили ОС и VPN-клиенты. Работает даже при повреждённом конфиге. Выключает разделение, иначе оно вернёт маршруты. " +
		"Чтобы снять только записи этой сессии, достаточно «Разделение: ВЫКЛ».",
		Cmd: "vpnsplit reset", Admin: true},
}

var pickTips = [2]tip{
	{Hint: "«Авто» подходит почти всегда. Выбор конкретного VPN сохраняется по названию клиента, " +
		"поэтому переживает переподключения. Если клиента нет в списке, введите его название или имя адаптера вручную."},
	{Hint: "«Авто» берёт любой подключённый домашний VPN, так что можно переключаться между Happ, BlancVPN и другими " +
		"без перенастройки. Он должен отличаться от корпоративного."},
}

var rulesTip = tip{
	Hint: "«+ Добавить…» — ввести сеть (10.0.0.0/8), IP, домен или номер AS (AS49675 — все сети организации по данным RIPE). " +
		"Правила «напрямую» и «домашний VPN» (в CLI --home) видны, только если нужны при выбранном «Остальном трафике». " +
		"Enter на правиле — удалить его. Импорт и экспорт — в «Дополнительно». " +
		"Изменения вступят в силу сами, если разделение включено, иначе после его включения.",
	Cmd: "vpnsplit add|remove [--direct] <правило>",
}

const confirmText = "Будут удалены ТОЛЬКО маршруты и DNS-записи, добавленные vpnsplit (в том числе командами apply и watch). Настройки VPN-клиентов и системные маршруты не затрагиваются."

var helpText = []string{
	"# Как это работает",
	"Утилита управляет таблицей маршрутов ОС. Корпоративные правила идут в корпоративный VPN, правила «напрямую» — через Wi-Fi/Ethernet мимо VPN, " +
		"остальной трафик — в домашний VPN. VPN-клиенты определяются автоматически. Корпоративные домены дополнительно " +
		"резолвятся через корпоративный DNS. Маршрут по умолчанию и настройки VPN-клиентов не меняются.",
	"",
	"# Клавиши",
	"? — эта справка, q — выход, ↑↓ — выбор, enter — запуск, цифра — сразу запустить пункт под этим номером, esc — назад.",
	"",
	"# Первая настройка",
	"1. Запустите меню с sudo (на Windows — от имени администратора): разделение включится само.",
	"2. Подключите VPN: корпоративный и/или домашний.",
	"3. «Правила» — добавьте, что идёт напрямую (b), и при необходимости корпоративное (a).",
	"Всё. «Дополнительно → VPN-адаптеры» трогать не нужно, если клиент определился (видно на схеме вверху).",
	"",
	"# Разделение ВКЛ / ВЫКЛ",
	"ВЫКЛ сразу снимает всё, что добавила эта сессия, и возвращает маршрутизацию, как до запуска. Меню остаётся открытым, " +
		"ВКЛ применяет заново. При выходе (q, Ctrl+C, закрытие окна) снимается всё, что осталось, и система сверяется с состоянием до запуска.",
	"",
	"# Если что-то пошло не так",
	"Выключите разделение. Если проблема осталась или маршруты остались от команд apply и watch — «Дополнительно → Сбросить всё» " +
		"(или vpnsplit reset в консоли). Если программа была убита, vpnsplit recover (или следующий запуск) доделает очистку. " +
		"Если проблема осталась, переподключите VPN-клиенты.",
	"",
	"# Ограничения",
	"Только IPv4 в правилах. VPN-клиенты должны работать в TUN-режиме (виртуальный адаптер). " +
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
