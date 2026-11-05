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
  - `cli.go` — команды: menu [--no-resize] (по умолчанию), list, init, add/remove [--direct|--home], rules, import/export, set, apply, watch, run, recover, install-recover [--remove], reset [--force|--purge], status, diff, version;
  - `recover.go` — `recover` (захват lock + Recover + Settle, без применения; persistent-записи не трогает) и `install-recover`;
  - `session.go` — цикл `run`/`watch`, захват журнала, бюджеты очистки.
- `internal/tui`:
  - `tui.go` — модель, переключатель «Разделение ВКЛ/ВЫКЛ» (`model.on`: ВКЛ = apply + опрос раз в 2 с, ВЫКЛ = `Manager.Disable`), экраны «Дополнительно» (`scAdvanced`) и «Диагностика» (`scDiag`, полный `Diff` с DNS при входе и по `r`), цифра сразу запускает пункт, `?` справка, `q` выход;
  - `run.go` — запуск с `tea.WithoutSignalHandler`, сигналы, `finish`/Cleanup;
  - `layout.go`, `render.go`, `view.go`, `menu.go` (лесенка раскладок, `wantSize`), `hints.go` (пункты меню, строки «Дополнительно», справка) — вёрстка;
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
  - `machineprog*.go`, `acl_*.go` — фиксированный каталог копии для задачи recover (`MachineProgramDir`: `%ProgramFiles%\vpnsplit` через KnownFolder, `/usr/local/libexec/vpnsplit`, на macOS `/Library/PrivilegedHelperTools/vpnsplit`), `EnsureProgramDir`/`CheckProgramDir` (создание root/SY+BA, без ссылок и reparse point, не на /media, /run/media, /mnt), `VerifyInstalledProgram` (ProtectedExe + GetFinalPathNameByHandle на Windows); `noExtendedACL` на macOS (через `ls -lde`, при сомнении отказ) входит в `trustedOwner`;
  - `machinepath*.go` — `ProtectedExe`/`ProtectedDir`: файл и вся цепочка каталогов принадлежат системе и недоступны чужим для записи (Windows: DACL файла и каталога строго, предков — без права переименовывать/удалять/менять DACL; корень диска даёт всем создавать подкаталоги, это допустимо);
  - `userfiles*.go` — `ReadRegularMax`, `ReadUserFile`/`ListUserDir` (через `os.Root` профиля, без ссылок, владелец — пользователь/root), `ReadMachineFile`/`ListMachineDir` (только владелец SYSTEM/Administrators/TrustedInstaller или root; файл открывается без ссылок, владелец и права проверяются на дескрипторе, вся цепочка каталогов вверх до корня; на Windows ещё DACL файла и каталога без записи для чужих), `RealUserHome`/`RealUserConfigDir`/`RealUser`.
- `internal/router` — ядро:
  - `manager.go` — `Manager`/`Session`: `Acquire` (lock + recover + снимок), `Apply`, `Reset`, `Disable` (снять записи сессии, не выходя: lock, снимок и право применять остаются; чужие persistent-записи не трогает), `Cleanup`/`CleanupUntil`, `Report`;
  - `backend.go` — интерфейс `Backend` (маршруты, правила, DNS, чтение таблиц), `osBackend`;
  - `router.go` — `applyEnv`, Sig (имя + индекс + хеш адресов + признак v6), детект;
  - `tun6.go` + `tun6_windows.go` — Teredo/6to4/ISATAP (Windows): прежнее состояние в журнал до смены, откат в Cleanup/Recover;
  - `v6.go` — `V6Status` (подсветка v6 мимо дом. VPN);
  - `diag.go` + `diag_detect.go` — `Diagnose`/`Diag`, детекторы этапа 4; `fakeip.go` — диапазоны fake-ip из конфигов только запущенных клиентов (`fakeRangesFor`), `isFakeIP` только для ответов DNS (для серверов — `badServer`); `dns_entry.go` — `ownDNSEntry`;
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
- `internal/clientcfg` — чтение настроек клиентов и ОС для предупреждений (прокси, sing-box/Hiddify/Mihomo, GPO NRPT, OpenVPN, Cisco); ничего не меняет.
- `internal/ripe` — префиксы AS из RIPE, кэш с санитизацией.
- `internal/sysexec` — единственный способ запускать системные утилиты: абсолютные пути, урезанное env, `sysexec.PowerShell(script, env)`.
- `internal/sysproc` — `Alive`/`AliveExact(pid, start)`, `BootID`, `SameBoot`.
- `internal/termsize` — авторесайз окна под меню: `Detect` (conhost → консольный API, xterm/iTerm2/Terminal.app → `CSI 8;rows;cols t`, Windows Terminal/tmux/screen/VTE/Konsole/неизвестные → подсказка), `Fit` растит окно (никогда не уменьшает) и возвращает `Restore` (один раз, из любой горутины). Отключается `--no-resize` или `VPNSPLIT_NO_RESIZE=1`.
- `internal/autorecover` — `Install`/`Remove` задачи «при старте → vpnsplit recover»: Task Scheduler (SYSTEM, PowerShell с `$env:VS_*`), systemd unit oneshot, LaunchDaemon. Только по явной команде. `install-recover` КОПИРУЕТ текущий бинарь (`program.go`: tmp + O_EXCL + rename, только регулярный файл) в защищённый каталог системы (см. `config.MachineProgramDir`) и регистрирует задачу на копию; после записи `VerifyInstalledProgram`, `ValidExePath` (белый список символов). Каталог и копия помечены `vpnsplit.managed`, `--remove` удаляет задачу, копию и пустой каталог только с меткой. После обновления vpnsplit нужно запустить install-recover снова. Windows: задача только в `\`, ровно одна, SYSTEM (S-1-5-18) и метка в описании, перед регистрацией своя удаляется, чужая с тем же именем — отказ. Метка `vpnsplit-managed` — удаляется только своё.
- `internal/lifecycle` — `Notifier` (SIGINT/SIGTERM/SIGHUP; на Windows CTRL_CLOSE/LOGOFF/SHUTDOWN = SIGTERM; `Inject` — тот же once для WM_ENDSESSION, не считается повтором), `CleanupDeadline`, `SafeGo`, `ForceExit`, `AtExit`/`RunAtExit` (страховка: значок трея и окно консоли при ForceExit и последнем recover в main).
- `internal/tray` — трей: `tray.go` (State -> значок/подсказка, `Items`, `Commands.Dispatch`, `Disabled`, `ConsoleEligible`), `icon.go` (значки рисуются в рантайме), `tray_windows.go` (Shell_NotifyIconW v4, скрытое окно верхнего уровня в потоке с LockOSThread, TaskbarCreated, WM_QUERYENDSESSION/WM_ENDSESSION, TrackPopupMenu), `console_windows.go` (`ConsoleCanHide/Hide/Show`: SW_HIDE только для одиночного conhost), `tray_other.go` (Linux/macOS: `ErrUnsupported`). `internal/tui/traylink.go` — связь меню и значка (`trayLink`, `startTray`, `endSession`, `trayToggleMsg`); клавиша `m` — спрятать окно.
- `test/stand/` — Docker-стенд Linux (`Dockerfile`, `stand.sh`, `run.ps1`, `tuirun.py` — режимы q/tq/ctrlc/sigterm/sighup/hangup/offon/key1q, эмулятор `CSI 8;r;c t`, `README.md`).

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
  - Сценарии S0–S39 (S28–S35 — этап 4: детект, `vpnsplit status`; S36–S39 — этап 5: S36 переключатель ВЫКЛ/ВКЛ в TUI, S37 `recover` после kill -9, S38 `install-recover` с заглушкой systemctl и копией в /usr/local/libexec/vpnsplit, S39 авторесайз xterm):
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
    - DNS провайдера пересекается с DNS дом. VPN (S24), чужая `~.` не флапает (S25), клиент b/c забрал только v4 — подсветка v6 (S26), resolvectl не отвечает при чтении — ничего не стёрто (S27).
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
- Этап 4 — детект и предупреждения: готов. `router.Diagnose(cfg, env, st)` → `[]Diag{Code, Level info/warn/danger, TextRU/EN, AdviceRU/EN}` (`diag.go` кэш 20 с по `Sig`+журналу; `diag_detect.go` чистые детекторы `diagnose(diagIn)`). Находки: `PROXY_ON`, `STRICT_ROUTE`, `FAKE_IP`, `WG_FULL_TUNNEL`, `CORP_FULL_TUNNEL`, `CORP_LOCKDOWN` (профиль Cisco), `BLOCK_OUTSIDE_DNS` (эвристика по конфигу/логу OpenVPN, info), `GPO_NRPT` (danger), `OVERLAP_LAN`/`OVERLAP_ADAPTER`/`OVERLAP_WELLKNOWN`/`OVERLAP_VPN_LAN`, `ENDPOINT_COVERED`, `DIRECT_CDN_AS`/`DIRECT_BIG` (> /10 в сумме), `HYPERV_UPLINK`, `CORP_ONLINK`. Показ: `vpnsplit status` (блок `diagnostics:`), TUI — индикатор в строке статуса и раздел «Окружение» на экране «Диагностика»; экран «Диагностика» — этап 5 (готов). `internal/clientcfg` читает (только чтение, лимит 4 МиБ, без ссылок: `config.ReadRegularMax`) конфиги sing-box/Hiddify/Mihomo (узкий разбор YAML без зависимостей), прокси (WinINET из реестра реального пользователя сессии, `scutil --proxy`, `gsettings` через `runuser`), GPO NRPT, OpenVPN, профили Cisco; кэш 30 с с single-flight без мьютекса на время скана (`Cached` ждёт ≤2 с, `Files` для apply не ждёт; запуск утилит — `runLimited`: таймаут, `WaitDelay`, kill группы процессов на unix). Машинные пути (`/etc`, `/usr/local/etc`, `%ProgramData%`, Cisco) читаются только при владельце SYSTEM/Administrators/TrustedInstaller или root. Диапазоны fake-ip из конфигов (`fake-ip-range`, `inet4_range`) сужают фильтр ответов DNS (IPv4, не короче /8, без частных/loopback/multicast/CGNAT/документационных; mihomo — только при `dns.enable: true`; применяются только к ответам системного резолвера: к ответам явно спрошенных серверов (провайдер, корп. DNS) и к адресам DNS-серверов (`avoid.whyServer`) — нет; для правил corp и `--home` дают только предупреждение, маршрут ставится; 198.18/15 отбрасывается везде; в отчёте apply — диапазон и клиент, без пути). ProxyOverride НЕ делается (см. отчёт этапа). Linux `dns <link>`: запись, которую мы сами поставили (индекс и серверы совпали с журналом), продолжает планироваться (`ownDNSEntry`), а при смене желаемых серверов заменяется. Windows: `IfMetric` заполняется в `listRoutes` для всех потребителей. Стенд S28–S35. Не проверено вживую: Windows (WTS-сессия, реестр других пользователей, GPO, vEthernet), macOS (`scutil --proxy`), Hiddify (пути данных предположительные).
- Этап 5 — меню, «Дополнительно», `recover`/`install-recover`, «Диагностика», авторесайз: готов. Решения:
  - Главное меню из четырёх пунктов: «Разделение: ВКЛ/ВЫКЛ», «Правила», «Диагностика», «Дополнительно»; `?` справка, `q` выход (не пункты). «Дополнительно»: VPN-адаптеры, корп. DNS, шлюз, «Остальной трафик», split_dns, импорт, экспорт правил, полный сброс (`reset` с подтверждением: единственный способ снять persistent-записи `apply`/`watch` без `[t]`).
  - ВЫКЛ = `Manager.Disable` (тот же путь снятия, что Cleanup: DNS → правила → маршруты, Tun6; без `settle`, без закрытия сессии). Выход после ВЫКЛ — обычная очистка (no-op) и сверка со снимком. Пока висят persistent-записи (`Foreign`), переключатель отказывает и называет `[t]`; во второй копии (только просмотр) и без прав — тоже отказ.
  - Состояние переключателя — в строке статуса («Разделение ВКЛ · активно», «ВЫКЛ»).
  - `recover`: `NoSnapshot` + `Acquire(persistent)` + `Settle` (сверка со снимком мёртвого запуска, снятие остатков, снимок удаляется, шапка журнала без владельца очищается); persistent-записи остаются («left in place»). Код 1, если что-то не снято.
  - `install-recover [--remove]` (один флаг, а не отдельный `uninstall-recover`: ставится и снимается одной командой, как `reset --force`). Задача не запускается при установке, только при старте. Windows — `Register-ScheduledTask` через PowerShell (константный скрипт, `$env:VS_EXE/TASK/MARK`, описание с меткой), Linux — unit в `/etc/systemd/system` (запись через temp + rename, чужой файл/ссылка/каталог — отказ), macOS — plist в `/Library/LaunchDaemons` (chown 0:0, `launchctl bootstrap system`).
  - Терминал: `WT_SESSION`, `TMUX`, `STY`, `VTE_VERSION`, `KONSOLE_VERSION` проверяются первыми → только подсказка; потом Windows → консольный API, но только если нет `TERM`/`TERM_PROGRAM`/`ConEmuPID`/`WEZTERM_PANE`/`ALACRITTY_SOCKET` (VS Code, mintty, Git Bash сидят на ConPTY и своё окно не отдают — подсказка; если `GetConsoleScreenBufferInfo` откажет — тоже подсказка), `XTERM_VERSION` или `TERM_PROGRAM` = iTerm.app / Apple_Terminal → CSI, иначе подсказка. Подсказка («увеличьте окно до N×M») — строка подвала (`busyFlashLines`), пока окно меньше `wantSize()` (`model.small`); пропадает только на последних ступенях лесенки меню (окно ниже ~10 строк). Восстановление размера — `defer`, зарегистрированный первым в `tui.Run` (после Cleanup), плюс вызов перед `ForceExit` при втором сигнале; при убийстве процесса без шансов (kill -9, `os.Exit`) размер не вернуть.
  - Тесты cli и TUI изолированы от профиля (`main_test.go`: APPDATA/LOCALAPPDATA/HOME/USERPROFILE во временный каталог, panic, если `config.Dir()` вне его); тесты config тоже задают все эти переменные.
  - Авторесайз повторяется один раз после первого статуса (меню стало длиннее), restore остаётся от первого вызова (`windowRestore`); `consoleFit` работает, только если stdout — консоль. `Session.Journal` читает под семафором операций. «Диагностика»: запросы Diff нумеруются, устаревшие игнорируются, во время применения помечается «может быть неполным».
- Трей: готов (Windows; Linux/macOS не делаются: нужны D-Bus/purego, новые зависимости). Значок только при правах и не `readOnly`; отключается `--no-tray`, `VPNSPLIT_NO_TRAY`, SSH, сессией 0, отсутствием Shell_TrayWnd. Команды значка идут через `program.Send` (toggle -> `toggleSplit`, выход -> `tea.QuitMsg`), удаление значка (NIM_DELETE) параллельно с очисткой в defer `Run`, плюс `lifecycle.AtExit`. WM_ENDSESSION -> `Notifier.Inject(SIGTERM)` и ожидание очистки до t+4,5 с. Защита: `Inject` + настоящий CTRL_SHUTDOWN в пределах AbruptBudget — одно событие (не повтор, ForceExit не срабатывает); события значка принимаются только при совпадении ID, курсоре/якоре внутри `Shell_NotifyIconGetRect` (`iconevent.go`, чистая логика) и выборе пункта позже 300 мс после показа меню; для TaskbarCreated снят фильтр UIPI, при неудаче возврата значка — 5 повторов по таймеру, затем окно консоли показывается; AtExit ждёт удаления значка до 650 мс. Не проверено вживую: меню значка, WM_ENDSESSION при реальном выходе из сеанса, перезапуск explorer (TaskbarCreated), скрытие окна conhost.

## Процесс
- Ветка `fix/windows_connection`, один коммит на этап, без пуша.
- Сообщения коммитов — по-английски, без трейлеров `Co-Authored-By` и прочей атрибуции.
- Цикл этапа: developer-go → reviewer + security (параллельно) → фиксы → build.ps1 + кросс-проверка + стенд → коммит. Координация через teamlead.
- Навигация по коду — через Serena (`mcp__serena__*`), если доступна; иначе точечный Grep/Read по карте выше.
