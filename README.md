# vpn

Публичный репозиторий архитектурного плана VPN и инструментов работы с
репозиторием. **VPN здесь не реализован и не развёрнут.** Наличие плана, hooks
или успешного CI не означает готовности VPN или проверки рабочей инфраструктуры.

## Документация

- [Исходный архитектурный план](docs/ARCHITECTURE_PLAN.md) — целевая система;
  документ сохраняется без изменений. Упомянутые в нём команды и компоненты
  нельзя считать реализованными инструментами этого репозитория.
- [Реестр решений](docs/DECISIONS.md) — краткая таблица решений из плана;
  источник истины — план, реализацией реестр не является.
- [Противодействие активному пробингу](docs/ACTIVE_PROBING.md) — исследование
  российских практик, сравнение вариантов и ТЗ на реализацию; защита не развёрнута
  и не гарантирует отсутствие блокировки IP.
- [Операционные инварианты](docs/INVARIANTS.md) — правила работы, их причины и
  способы проверки.
- [Ansible: контракт inventory](docs/ANSIBLE.md) — синтетическая топология и её
  проверка (`make -C ansible validate`); развёртывание не реализовано.
- [Source ACL в роли base](docs/BASE_ROLE.md) — публичные и source-restricted
  порты, SSH/IPv6 и транзакционная собственная таблица nftables.
- [Приватный TLS cover-site](docs/COVER_SITE.md) — nginx на host-loopback,
  операторский контент и Certbot; не публичный альтернативный backend.
- [RemnaNode](docs/REMNAWAVE_NODE.md) — закреплённый контейнер, приватный
  management-путь с mTLS/JWT и source ACL роли base.
- [VictoriaMetrics](docs/METRICS_ROLE.md) — закреплённый single-node store
  метрик со скрейпом node_exporter и панели, retention 30 дней и query API
  только на loopback или по source ACL; не алертинг и не production-стек.
- [Exit/relay bundles](docs/PROFILES.md) — локальный рендер согласованных
  серверных и клиентских конфигураций; не публикация через панель.
- [vpnctl](vpnctl/README.md) — строгий контракт конфигурации и CLI на Go,
  read-only Telegram-бот ([TELEGRAM_BOT.md](docs/TELEGRAM_BOT.md)),
  [probe ladder / diagnose](docs/PROBES.md) и [panel plan/show](docs/PANEL_WRITE.md).
  Публикация и rollback заблокированы отсутствующим CAS в закреплённой панели;
  узлы не изменяются.
- [Probe ladder и классификатор](docs/PROBES.md) — bounded REALITY/VLESS/XHTTP,
  отдельные family/vantage controls, `unknown` при недостаточном evidence;
  не детектор конкретной системы цензуры и не автоматическая remediation.
- [Участие и управление репозиторием](CONTRIBUTING.md) — ветки, PR, проверки,
  условия слияния и откат.
- [Безопасность](SECURITY.md) — приватное сообщение об уязвимости.
- [Правила для автоматизированных помощников](AGENTS.md) — границы работы,
  публикации и production-действий.
- [Владение файлами](.github/CODEOWNERS) — ответственный `@juvenileslave`.

## Локальные инструменты

Нужны Python 3.11 или новее с `venv`/`pip`, Git, `make` и доступ к PyPI/GitHub
для подготовки окружения. Go и Docker для `make bootstrap`, `make hooks` и
`make check` не требуются; Go нужен только для `make vpnctl-test|vpnctl-build`.

```sh
make bootstrap
make hooks
make check
```

| Команда | Назначение |
| --- | --- |
| `make bootstrap` | Устанавливает инструменты закреплённых версий в локальную `.venv`. |
| `make hooks` | Устанавливает локальные commit hooks после подготовки окружения. |
| `make check` | Проверяет публичные tracked/staged-файлы репозитория; работает и на `master`. |
| `make vpnctl-test` | gofmt, `go vet` и `go test` для [vpnctl](vpnctl/README.md); нужен Go, в `make check` не входит. |
| `make vpnctl-build` | Собирает `vpnctl/bin/vpnctl`; нужен Go. |

Новые публичные файлы добавляйте в индекс перед `make check`; приватные локальные
материалы не добавляйте. Проверка охватывает правила публикации, YAML/JSON,
конфликтные маркеры, приватные ключи, размер файлов, whitespace/EOF и GitHub
Actions. Whitespace/EOF hooks могут исправлять файлы, кроме архитектурного плана:
просмотрите исправления, повторите проверку и обновите индекс.

Локальный commit hook запрещает коммиты в `master` и `main`. Hooks не заменяют
защиту GitHub. `make check` **не сканирует всю историю Git** и не заменяет
отдельный обязательный CI job `Secret scan`, который использует gitleaks для
доступной истории Git.

Runtime-сценарии [base](.github/workflows/base.yml), [cover-site](.github/workflows/cover-site.yml), [RemnaNode](.github/workflows/remnawave-node.yml), [profiles](.github/workflows/profiles.yml) и [probe ladder](.github/workflows/probe-ladder.yml) запускаются только на
одноразовом GitHub-hosted Linux guest. Команды и prerequisites — в документации
компонента, фактические результаты — в его PR. Production-rollout и российский
пилот этим не выполняются.

## Управление изменениями

Разработка, коммиты, push, issues и PR выполняются только под основным аккаунтом
`juvenileslave` в [juvenileslave/vpn](https://github.com/juvenileslave/vpn).
`origin` — основной репозиторий. Feature-ветка от `origin/master` → PR в `master` →
успешные `Repository checks` и `Secret scan` →
squash merge владельцем. Рабочий аккаунт `popularhono` и его форк не используются.

В целевой политике review рекомендован, но не является обязательным merge-gate.
PR, актуальная база и успешные обязательные проверки сохраняются.

Неблокирующий review применён в ruleset `master` 2026-11-12: approvals,
CODEOWNER-review и разрешение review threads не обязательны; обязательные
`Repository checks`, `Secret scan`, strict base и защита ветки сохранены. Правка
`.github/rulesets/master.json` сама по себе сервер не меняет.

[Защита master активна в GitHub](https://github.com/juvenileslave/vpn/rules/26988307),
без bypass, force-push и удаления ветки. Подробности — в
[CONTRIBUTING.md](CONTRIBUTING.md).

Не публикуйте секреты, рабочие конфигурации, реальные серверные идентификаторы,
дампы и приватные обсуждения. Изменение репозитория не даёт разрешения на
развёртывание или любые production-действия.
