# Сетевой стенд (Linux, Docker)

Один `docker run --rm --privileged` контейнер, внутри network namespaces:
`client` (где работает vpnsplit) - `isp` (NAT) - `inet` (1.1.1.1 с DNS, интернет),
`corp` (WireGuard-сервер wgcorp, 10.10.0.0/16, DNS corp.example),
`home` (WireGuard-сервер wghome, NAT в inet). Адреса 203.0.113.10-13 есть в
inet, corp и home, и каждый отвечает по HTTP своим именем: `curl` показывает путь пакета.

Запуск с Windows (хост сеть не меняется, всё внутри контейнера):

```
powershell -File test\stand\run.ps1              # все сценарии
powershell -File test\stand\run.ps1 -Only S3     # один сценарий
powershell -File test\stand\run.ps1 -HomeVariant b
```

`run.ps1` собирает Linux-бинарь (`GOOS=linux go build`), один раз собирает образ
`vpnsplit-stand` (alpine + iproute2, wireguard-tools, dnsmasq, python3, iptables;
нужен интернет) и запускает `stand.sh`. Нужно ядро с модулем wireguard (Docker
Desktop / WSL2 его имеет). Код возврата 1, если любая проверка не прошла.

Сценарии этапа 1 (маршруты проверяются `ip route get` и `curl`, чистота - сравнением
таблицы маршрутов и правил client со снимком до запуска):

| id | что |
|----|-----|
| S0 | без vpnsplit всё идёт в inet |
| S1 | `run`, правила применены (corp / direct / остальное), SIGTERM, таблица = снимок |
| S2 | то же для SIGINT и SIGHUP |
| S3 | `run`, `kill -9`, остались маршруты, повторный `run` (или `reset`) убирает их, SIGTERM, таблица = снимок |
| S4 | `apply` (persistent) оставляет маршруты, `run` забирает их, SIGTERM, чисто |
| S5 | вторая копия (`run`, `reset`, `apply`) при живой первой ничего не меняет |
| S6 | меню на псевдотерминале закрывается `q`, Ctrl+C, SIGTERM, SIGHUP, закрытием терминала: чисто; меню второй копии только показывает |
| S7 | меню при persistent-журнале (после `apply`): `q` выходит, ничего не снимая и сообщая об этом; затем `t` (забрать в сессию) и `q` снимают всё, итог записан в `last-session.log` |
| S8 | медленный `ip route del` (8 с): второй SIGINT во время снятия завершает процесс сразу (код 130), журнал хранит остаток, следующий запуск доделывает; SIGTERM при медленном снятии: выход через ~4,5 с от сигнала с ненулевым кодом, остаток в журнале, итог в `last-session.log` и в `status` |

`-HomeVariant`: `a` (по умолчанию) - домашний VPN как 0/1 + 128/1 в main;
`b` - как wg-quick (`ip rule not fwmark ... table`, `suppress_prefixlength 0`);
`c` - свой `ip rule` + таблица. Варианты b и c только строят топологию и печатают
таблицу: vpnsplit пока их не поддерживает (этапы 2/3), сценарии не гоняются.

Заметки: split DNS на Linux работает только с systemd-resolved; в контейнере его нет,
поэтому DNS-часть (NRPT/resolver-записи) здесь no-op. Корпоративные домены
резолвятся через `corp-dns` и превращаются в маршруты.
