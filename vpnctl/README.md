# vpnctl

`vpnctl` — утилита управления VPN из [архитектурного плана](../docs/ARCHITECTURE_PLAN.md)
(этап 5). Реализованы **строгий контракт конфигурации**, команда его проверки,
**read-only Telegram-бот** `vpnctl bot` (см. [TELEGRAM_BOT.md](../docs/TELEGRAM_BOT.md)),
авторизованная `probe ladder` и консервативный `diagnose`
([PROBES.md](../docs/PROBES.md)), а также **read-only `panel plan/show`** для
существующего renderer bundle ([PANEL_WRITE.md](../docs/PANEL_WRITE.md)).
Запись в панель и rollback заблокированы: закреплённый API не поддерживает
атомарные write-preconditions. Воркера, mTLS probe-агента и команд изменения
инфраструктуры нет.

## Чего утилита не делает

- Не меняет панель: у клиента панели только GET-запросы.
- `config validate` не открывает сетевых соединений; `probe ladder` делает
  только явно запрошенные bounded пробы по внешнему файлу, а `diagnose` читает
  локальное evidence и ничего не запускает на узлах.
- Токены бота/панели читает только из переменных окружения при `vpnctl bot`
  или read-only `vpnctl panel`; client credentials для ladder — из приватного
  файла принятого renderer вне Git.
- Не меняет production, DNS, firewall или сертификаты.

`config validate` проверяет только сам файл: успешный результат не означает, что
панель или узлы существуют и доступны.

## Команды

| Команда | Результат | Код выхода |
| --- | --- | --- |
| `vpnctl version` | Одна строка `vpnctl <версия>`; версия из build info модуля, иначе `dev`. | 0 |
| `vpnctl config validate --config PATH` | `config OK: PATH` в stdout. | 0 |
| | При ошибках — `config invalid: PATH` и **все** найденные ошибки в stderr. | 1 |
| `vpnctl bot --config PATH` | Long-polling бот; до остановки пишет логи в stderr, при `SIGINT`/`SIGTERM` — `bot stopped` в stdout. | 0 |
| | Ошибка конфигурации, окружения, `getMe`, панели или типизированная ошибка Telegram — `bot failed`/`bot stopped` в stderr. | 1 |
| `vpnctl probe ladder --node NAME [--family ipv4|ipv6] --inputs PATH --store PATH --xray PATH` | TCP → verified TLS/cover → REALITY/VLESS/XHTTP → exact 1 MiB → exact 20 MiB; text или `--format json`/`--json`. | 0 — все пять этапов успешны; 4 — выполненный этап отказал |
| `vpnctl diagnose --node NAME --inputs PATH --store PATH [--family ipv4|ipv6]` | Pure scoped verdict с confidence/missing_evidence; никакой remediation. | 0 — supported hypothesis; 3 — insufficient evidence / `unknown` |
| Ошибка external inputs, pinned core, store, private cleanup или output | Короткий secret-safe code; не успех сетевой пробы. | 1 |
| `vpnctl panel [plan] --config PATH --bundle MANIFEST --objects PATH` | Проверка bundle и безопасный JSON-diff; только GET. `apply` без `--apply` выполняет тот же plan. | 0 |
| `vpnctl panel show --config PATH --bundle MANIFEST --objects PATH` | Только текущие объявленные identities и наличие effective fields. | 0 |
| `vpnctl panel apply --apply` | Отказ до чтения файлов/токена, сети и SQLite: атомарной защиты в API нет. | 3 |
| `panel`: stale UUID, ownership-конфликт, потенциально lossy update | Безопасный отказ; панель не меняется. | 3 |
| `panel`: неверные inputs, token/TLS/HTTP/response ошибки | Значения и сырые diagnostics не выводятся. | 1 |
| Неизвестная команда, лишние аргументы, нет `--config` | Описание использования в stderr. | 2 |


Ladder не зависит от panel adapter, токена панели или YAML-конфигурации бота.
Внешний JSON содержит targets, budgets и реальные vantage labels, а credentials
остаются в `clients/{direct,relay}-N.json`, произведённом immutable profiles
renderer. В файле inputs можно указать `profile_file_env` — **имя** переменной
с абсолютным путём к этому client file, не UUID/key/shortId.

`VPNCTL_PROBE_INPUTS`, `VPNCTL_STATE_DB`, `VPNCTL_XRAY_PATH` — необязательные
значения по умолчанию для `--inputs`, `--store`, `--xray`. Credentials нет среди
аргументов CLI. `--vantage` выбирает объявленную actual точку; без него используется
`local_vantage`. `--globalping-file` явно импортирует typed HTTP-only observations
принятого Globalping client в отдельный scope, без provider API request/poll/retry.
Полный формат внешнего JSON, пороги, бюджеты и границы доказательств —
[PROBES.md](../docs/PROBES.md).

Успех ladder не означает supported verdict: одна сеть всегда даёт `unknown`.
Код 4 сообщает наблюдаемый отказ этапа, а не «IP заблокирован»; код 3 относится
к недостаточности evidence в `diagnose`. Ошибочные key/shortId/UUID не переводятся
в TCP block. Ни одна из команд не пишет в панель, не вращает IP и не меняет
DNS/firewall/services.
## Схема конфигурации

Полный синтетический пример — [config.example.yaml](config.example.yaml).

```yaml
panel:
  url: https://panel.example.com
  token_env: VPNCTL_PANEL_TOKEN
nodes:
  - name: exit-01
    role: exit
    address: 192.0.2.10
    port: 443
probe:
  timeout: 5s
  interval: 60s
log_level: info
bot:
  token_env: VPNCTL_BOT_TOKEN
  state_db: state.db
  operators:
    - id: 100000001
      role: admin
    - id: 100000002
      role: viewer
  chat_ids: [-1000000000001]
```

## Правила проверки

Разбор строгий:

- неизвестные поля, повторяющиеся ключи и неверные типы — ошибка;
- пустой файл (или только комментарии) — ошибка;
- файл должен содержать ровно один YAML-документ.

Ошибки содержимого сообщаются с путём к полю, например `nodes[1].port`, и
перечисляются все сразу.

| Поле | Правило |
| --- | --- |
| `panel` | Обязательно. |
| `panel.url` | Обязательно; схема `https`, есть хост, нет userinfo (`user:pass@`). |
| `panel.token_env` | Обязательно; имя переменной окружения по `^[A-Z_][A-Z0-9_]*$`. |
| `nodes` | Обязательно, хотя бы один узел. |
| `nodes[].name` | Обязательно, непустое, уникальное среди узлов. |
| `nodes[].role` | `exit`, `relay` или `cp`. |
| `nodes[].address` | IPv4, IPv6 (без zone, `%eth0`) или DNS-имя. |
| `nodes[].port` | Целое от 1 до 65535. |
| `probe.timeout`, `probe.interval` | Обязательны; положительная длительность Go (`5s`, `1m30s`); число без единицы — ошибка. |
| `log_level` | `debug`, `info`, `warn` или `error`. |
| `bot` | Обязательно. |
| `bot.token_env` | Обязательно; имя переменной окружения с токеном бота. |
| `bot.api_base` | Необязательно; `https`-хост или loopback `http` (self-hosted/fake Bot API). |
| `bot.state_db` | Обязательно; путь к SQLite-базе с offset и обработанными `update_id`. |
| `bot.operators` | Непустой список; `id` — положительный уникальный числовой Telegram user ID, `role` — `admin` или `viewer`. |
| `bot.chat_ids` | Необязательно; ненулевые уникальные chat ID, которым разрешены ответы в не-private чатах. |

## Почему в конфигурации только имена переменных токенов

Конфигурация должна быть безопасна для хранения, ревью и передачи: в ней нет
секретов. Поэтому `panel.token_env` и `bot.token_env` содержат **имена**
переменных окружения (например, `VPNCTL_PANEL_TOKEN`, `VPNCTL_BOT_TOKEN`), а не
значения токенов. Шаблон имени отвергает типичные значения токенов (строчные
буквы, `-`, `.`), а поля `token` в схеме нет, и оно отклоняется как неизвестное.
Userinfo в `panel.url` и `bot.api_base` запрещено по той же причине и не
повторяется в сообщении об ошибке. Значения токенов читает из окружения
`vpnctl bot` и read-only `vpnctl panel`; они не печатаются и не сохраняются.

## Локальная проверка

Нужен Go версии из [go.mod](go.mod) (директива `go`). Тесты используют stdlib
`testing`, временные каталоги, in-memory pipes и fake Bot API/панель/TCP/TLS на
loopback; реальный Telegram, реальные credentials и внешняя сеть не нужны.
Pinned Xray и настоящий авторизованный путь проверяет только одноразовый
[Relay probe ladder workflow](../.github/workflows/probe-ladder.yml), а не unit mocks.
Первая сборка загружает зависимости через Go module proxy.

```sh
make vpnctl-test     # gofmt -l, go vet ./..., go test ./...
make vpnctl-build    # бинарник vpnctl/bin/vpnctl

cd vpnctl
go test ./... && go vet ./... && go build ./cmd/vpnctl
./vpnctl config validate --config config.example.yaml
```

Go-проверки не входят в `make check`: участникам, работающим только с Python, Go
не нужен. В CI их выполняет отдельный workflow `Go checks`
([.github/workflows/go.yml](../.github/workflows/go.yml)).
