# vpnctl

`vpnctl` — утилита управления VPN из [архитектурного плана](../docs/ARCHITECTURE_PLAN.md)
(этап 5). Реализованы **строгий контракт конфигурации**, команда его проверки и
**read-only Telegram-бот** `vpnctl bot` (задачи 5.3/5.4; см.
[TELEGRAM_BOT.md](../docs/TELEGRAM_BOT.md)). Воркера, probe-агента, миграции и
команд изменения здесь нет; команды из плана, кроме перечисленных ниже, не
существуют.

## Чего утилита не делает

- Не меняет панель: у клиента панели только GET-запросы.
- Не проверяет доступность узлов (никаких probe) и не подключается к серверам.
- Не читает токены из файлов: только из переменных окружения, названных в
  конфигурации, и только при запуске `vpnctl bot`.
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
| Неизвестная команда, лишние аргументы, нет `--config` | Описание использования в stderr. | 2 |

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
повторяется в сообщении об ошибке. Значения токенов читает из окружения только
`vpnctl bot`; они не печатаются и не попадают в логи или ошибки.

## Локальная проверка

Нужен Go версии из [go.mod](go.mod) (директива `go`). Тесты используют stdlib
`testing`, временные каталоги и fake Bot API/панель на loopback; реальный
Telegram, реальный токен и внешняя сеть не нужны. Первая сборка загружает
зависимости через Go module proxy.

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
