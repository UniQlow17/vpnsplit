# vpnsplit — карта проекта

Go (1.24), TUI на bubbletea. Утилита сплит-туннелинга для Windows, Linux и macOS.

## Что делает
Трафик делится на три направления:
- **корп. правила** (домены, IP/CIDR, AS) → адаптер корп. VPN. Корп. зоны резолвятся через корп. DNS (NRPT / resolved / /etc/resolver);
- **«напрямую»** → физический Wi-Fi/Ethernet через его шлюз, мимо VPN;
- **остальное** → домашний VPN (0/1+128/1 через его адаптер), если включено `HomeDefault`.

Режимы владения журналом:
- **session** — TUI (по умолчанию) и `vpnsplit run`. При старте Recover + применение, при выходе любым путём снимается всё и выполняется сверка со снимком «как до запуска».
- **persistent** — `apply` и `watch`. При выходе ничего не снимают. TUI такие записи не трогает, пока пользователь не нажмёт `[t]`.

## Карта пакетов
- `cmd/vpnsplit/main.go` — точка входа: `cli.Run`, recover как последняя страховка, код выхода.
- `internal/cli`:
  - `cli.go` — команды: menu (по умолчанию), list, init, add/remove [--direct], rules, import/export, set, apply, watch, run, reset [--force|--purge], status, diff, version;
  - `session.go` — цикл `run`/`watch`, захват журнала, бюджеты очистки.
- `internal/tui`:
  - `tui.go` — модель, меню, авто-режим (опрос раз в 2 с);
  - `run.go` — запуск с `tea.WithoutSignalHandler`, сигналы, `finish`/Cleanup;
  - `layout.go`, `render.go`, `view.go`, `menu.go`, `hints.go` — вёрстка;
  - `paste.go`, `undo.go`.
- `internal/config`:
  - `config.go` — пользовательский конфиг, `Sanitize` при загрузке;
  - `validate.go` — все валидаторы;
  - `rules.go`, `rulesfile.go`;
  - `state.go` + `state_load.go` — журнал v2 (Owner PID/Start/Boot, Mode) и перенос старого `state.json` из профиля;
  - `snapshot.go` — `snapshot.json` и `plan.json`;
  - `lock*.go` — эксклюзивная блокировка;
  - `paths*.go` — защищённый каталог;
  - `fsutil*.go` — безопасная запись;
  - `userdir_*.go` — профиль пользователя через SUDO_USER/PKEXEC_UID.
- `internal/router` — ядро:
  - `manager.go` — `Manager`/`Session`: `Acquire` (lock + recover + снимок), `Apply`, `Reset`, `Cleanup`/`CleanupUntil`, `Report`;
  - `backend.go` — интерфейс `Backend` (маршруты, правила, DNS, чтение таблиц), `osBackend`;
  - `router.go` — `applyEnv`, Sig (имя + индекс + хеш адресов + признак v6), детект;
  - `tun6.go` + `tun6_windows.go` — Teredo/6to4/ISATAP (Windows): прежнее состояние в журнал до смены, откат в Cleanup/Recover;
  - `v6.go` — `V6Status` (подсветка v6 мимо дом. VPN);
  - `plan.go` — желаемое состояние: маршруты, правила, пины (endpoints), `policyFor`, `pickOwnTable`;
  - `reconcile.go` — diff и согласование: write-ahead pending, add→del, replace, `Drifted`;
  - `table.go` — `OSRoute`/`OSRule`, метки владения;
  - `baseline.go` + `snapshot.go` — сверка со снимком, `sweep`, атрибуция «чьё», `vpnsplit diff`;
  - `iphlpapi_windows.go` — ручные структуры iphlpapi (MIB_IPFORWARD_ROW2 = 104 байта);
  - `router_windows.go`;
  - `nl_msg.go` (чистые сборка и разбор netlink, тесты на всех ОС) + `nl_linux.go`;
  - `router_linux.go`;
  - `router_darwin.go` + `route_get.go`;
  - `dns_windows.go` (NRPT через PowerShell), `dns_linux.go` (resolvectl); DNS на macOS — в `router_darwin.go`;
  - `routertest/` — фейки для cli/tui;
  - `standhook_*.go` — хук медленного удаления, только с тегом `vpnsplit_stand`.
- `internal/netif` — детект адаптеров:
  - `providers.go` — известные VPN-клиенты;
  - `owners_*.go`, `descriptions_windows.go`.
- `internal/ripe` — префиксы AS из RIPE, кэш с санитизацией.
- `internal/sysexec` — единственный способ запускать системные утилиты: абсолютные пути, урезанное env, `sysexec.PowerShell(script, env)`.
- `internal/sysproc` — `Alive`/`AliveExact(pid, start)`, `BootID`, `SameBoot`.
- `internal/lifecycle` — `Notifier` (SIGINT/SIGTERM/SIGHUP; на Windows CTRL_CLOSE/LOGOFF/SHUTDOWN = SIGTERM), `CleanupDeadline`, `SafeGo`, `ForceExit`.
- `test/stand/` — Docker-стенд Linux (`Dockerfile`, `stand.sh`, `run.ps1`, `tuirun.py`, `README.md`).

## Сборка и проверки
- Windows: `powershell -File .\build.ps1 fmt|vet|test|build`. Есть также Makefile (`make build`).
- Кросс-проверка (GOOS задавать только на команду):
  - `GOOS=linux go vet ./...` и `GOOS=darwin go vet ./...`;
  - `go test -c` по пакетам для обеих ОС.
- `-race` недоступен: на хосте нет cgo.
- Docker-стенд: `powershell -File test\stand\run.ps1 [-HomeVariant a|b|c] [-Only S<n>]`.
  - Контейнер `--privileged`, внутри netns client/isp/inet/corp-gw/home-gw, WireGuard wgcorp/wghome, dnsmasq.
  - Адрес 203.0.113.x отвечает именем сети, так curl показывает путь трафика.
  - Варианты домашнего VPN: a — 0/1+128/1 в main; b — `ip rule` + table 2022 (как sing-box); c — wg-quick `suppress_prefixlength 0`.
  - Сценарии S0–S26:
    - сигналы и выход TUI (S1/S2/S6);
    - kill -9 → Recover (S3);
    - persistent (S4/S7);
    - вторая копия (S5);
    - бюджет и второй сигнал (S8);
    - переподключение адаптера (S9/S13);
    - 2000 префиксов (S10);
    - утечка при падении корп. VPN (S11);
    - endpoint (S12);
    - истёкший бюджет (S14);
    - старая версия (S15);
    - маршруты «клиента» не трогаются (S16–S18);
    - пути DNS, fake-ip, `~.` и его восстановление, IPv6, «Остальной трафик» = напрямую / не трогать (S19–S23; в контейнере нет resolved, на эти сценарии ставится заглушка `fake-resolvectl.sh`, она же считает вызовы);
    - DNS провайдера пересекается с DNS дом. VPN (S24), чужая `~.` не флапает (S25), клиент b/c забрал только v4 — подсветка v6 (S26).
  - Критерий: после выхода `ip route show table all` + `ip rule` совпадают со снимком.
- Linux-тесты можно запускать внутри контейнера стенда (`go test -c` под linux).

## Инварианты (не ломать)
- **PowerShell:** данные никогда не подставляются в текст скрипта, только через `$env:VS_*`. Скрипты — константы. Запуск только через `sysexec`.
- **Валидация** трижды: на вводе, при загрузке (`Sanitize` конфига, журнала, снимка, кэша) и перед выполнением (`ValidateRoute` и т.п.).
- **Журнал:**
  - лежит в защищённом каталоге: `%ProgramData%\vpnsplit` (DACL только SY+BA), `/var/lib/vpnsplit` или `/Library/Application Support/vpnsplit` (0700 root);
  - пишется ДО изменения в ОС;
  - один владелец под lock.
- **Метки владения:**
  - Windows: metric 3 + NETMGMT + Manual — только кандидат; удаление требует записи в журнале или плане;
  - Linux: proto 247 и своя таблица 247–250 + одно правило `lookup <table>` (только когда клиент уводит весь трафик);
  - macOS: `route add -proto2` и проверка через `route -n get`.
- **Чужое не удалять никогда:** маршруты VPN-клиентов вне журнала, /0, чужие префиксы /1 и короче, NRPT без Comment `vpnsplit`. При сомнении оставить и показать в отчёте.
- **Порядок:**
  - очистка: DNS → правила → маршруты;
  - изменения: сначала add, потом del (на Linux replace, на Windows `SetIpForwardEntry2` при смене только метрики).
- **Бюджет очистки:** SIGTERM/закрытие окна — дедлайн t_signal+4,5 с; при штатном выходе до 60 с. Что не снято, остаётся в журнале, Recover доделает при следующем старте.
- **Сеть хоста:** в тестах и при разработке не менять сеть хоста и ProgramData; сетевые эксперименты только в стенде. Чтение таблиц допустимо.

## Решения пользователя
- IPv6 не блокировать, а заметно подсвечивать. Туннелировать v6 в домашний VPN, если у него есть v6.
- NRPT «.» → DNS домашнего VPN.
- Настройка «Остальной трафик» (enum) вместо `HomeDefault`:
  - «Домашний VPN» / «Напрямую»; при «Напрямую» появляется список правил «через дом. VPN»;
  - показывать только релевантные категории правил;
  - нужна миграция старого `HomeDefault`.
- Kill-switch и службу не делать. Трей нужен (Windows обязательно), без поломки очистки при выходе.
- Режим «Прокси» клиента: предупреждать. ProxyOverride — только если надёжно и с откатом через журнал.
- Авторесайз окна на всех ОС, где невозможно — подсказка.
- Переделка меню: «Разделение ВКЛ/ВЫКЛ» (снимает сразу, без выхода), Справка/Выход — клавиши `?`/`q`, редкое — в «Дополнительно».
- Задача планировщика для recover — не ставить автоматически: `vpnsplit recover` + необязательная `install-recover`.

## Статус
- Готово:
  - `2c49109` — build.ps1 и TUI;
  - `342dfd9` — этап 0, безопасность;
  - `119570f` — этап 1, жизненный цикл;
  - `a7f9f7c` — этап 2, нативные маршруты, согласование, «как до запуска».
- Открыто: третий раунд reviewer + security по `a7f9f7c`. Windows-бэкенд вживую не проверялся, macOS — только компиляция.
- Этап 3 — DNS и утечки: готов. «Напрямую» через DNS провайдера + /32 (`directServers`, `physicalDNS`; единый фильтр адресов `badAddr`/`avoid`: loopback, link-local, multicast, fake-ip, корп. префиксы, DNS корп./дом. VPN, endpoint), /32 до корп. DNS, зоны direct-доменов → DNS провайдера при `rest=home` (`plan.direct`), NRPT «.» / `~.` на линке дом. VPN (`plan.rest`, `restDNS`; не ставится при `apply` без `watch` (`SetOneShot`), без корп. зон при корп. VPN, macOS не делается; чужая запись — «выполнено, не наше», без флапа), IPv6 (`::/1`+`8000::/1` через дом. VPN при его глобальном v6; на macOS пока не планируются; `V6Status` с признаком `Env.V6Cap`: на Linux читаются v6-правила), Windows Teredo/6to4/ISATAP (`tun6.go`, `State.Tun6`, повторное отключение, предупреждение о незнакомом значении), enum `Config.Rest` (`home`/`direct`/`keep`, миграция `home_default`), правила `--home`. Старый журнал из профиля: `Tun6` и зона «.» отбрасываются. Стенд S19–S26. Не проверено вживую: Windows (NRPT, Tun6, SOCKADDR_INET v6, scope_id link-local next hop), macOS (`-inet6`), настоящий systemd-resolved.
- Этап 4 — детект и предупреждения: Прокси, strict_route, fake-ip, WG 0/0, block-outside-dns, GPO NRPT, full-tunnel корп., пересечения подсетей.
- Этап 5 — меню, «Дополнительно», авторесайз окна.
- Трей — отдельный поздний этап.

## Процесс
- Ветка `fix/windows_connection`, один коммит на этап, без пуша.
- Сообщения коммитов — по-английски, в конце строка `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Цикл этапа: developer-go → reviewer + security (параллельно) → фиксы → build.ps1 + кросс-проверка + стенд → коммит. Координация через teamlead.
- Навигация по коду — через Serena (`mcp__serena__*`), если доступна; иначе точечный Grep/Read по карте выше.
