# Маршрутизация через exit-узел (issue #72)

Документ описывает топологию маршрутизации клиентского трафика через выделенный
exit-узел, ожидаемый внешний адрес, сетевые ограничения, путь публикации,
границы проверки и откат. **VPN не развёрнут**, production-хосты, DNS, firewall
и панель не изменялись; runtime acceptance в этом срезе **не выполнялся**.

Детальные контракты отдельных компонентов не дублируются — источники истины
находятся в [PROFILES.md](PROFILES.md), [REMNAWAVE_NODE.md](REMNAWAVE_NODE.md),
[BASE_ROLE.md](BASE_ROLE.md), [COVER_SITE.md](COVER_SITE.md),
[ANSIBLE.md](ANSIBLE.md), [DEPLOYMENT.md](DEPLOYMENT.md) и
[PANEL_WRITE.md](PANEL_WRITE.md).

## Топология relay → exit

Клиент подключается к RU relay по публичному IPv4 (`public_ipv4` relay) на
фиксированный порт своего слота из `relay_slot_ports` (`slot_fanout: ports`,
inbounds `slot-N-v4` / `slot-N-v6`). Relay служит только входным узлом и не
выпускает пользовательский трафик в интернет напрямую:

- Для каждого слота `N` (`0…egress_slots−1`) рендер создаёт пару VLESS + XHTTP +
  REALITY outbounds `slot-N-v6` и `slot-N-v4`, нацеленных на объявленные
  `public_ipv6` и `public_ipv4` exit-узла и его порт `transit_port` со
  служебным UUID `transit_client_ids[N]`.
- На exit этот трафик принимают inbounds `transit-v4` и `transit-v6` того же
  единого `exit.json`.
- Балансировщик слота `slot-N` использует `s2s_family: v6_prefer` и стратегию
  `leastPing` по `slot-N-v6` с `fallbackTag: slot-N-v4`; `observatory` проверяет
  доступность через `profiles_probe_url` каждые 2 s. При отказе IPv6 новые
  соединения переходят на IPv4 того же exit; при отказе обеих семей соединение
  завершается ошибкой.
- В `relay.json` отсутствует outbound с протоколом `freedom`, нет прямого
  fallback, а завершающее правило маршрутизации — `block` (`blackhole`).

## Exit как единственный egress

- `egress-0` (`protocol: freedom`) — единственный `freedom` outbound во всём
  bundle; он существует только в `exit.json`.
- Прямые inbounds exit (`direct-v4`, `direct-v6`) и служебный пользователь
  транзита `egress-0` маршрутизируются в `egress-0`.
- Любой слот `N > 0` без явно настроенного внешнего proxy в `profiles_upstreams`
  маршрутизируется в `block` (`blackhole`) и не может попасть в `egress-0` или
  иной `freedom` outbound. Завершающее правило `exit.json` — `block`.
- `egress-0` блокирует приватные адреса (`geoip:private`) и `bittorrent`, а
  также применяет `finalRules` после DNS.
- Обе адресные семьи сохраняются и управляются `egress_family`:
  `v4_prefer` (`UseIPv4v6`), `v6_prefer` (`UseIPv6v4`), `v4_only` (`ForceIPv4`
  с блокировкой `::/0` в `finalRules`).

## Ожидаемый внешний адрес

- Для пользовательского трафика слота 0 внешние сайты видят объявленный
  `public_ipv4` или `public_ipv6` exit-узла — никогда `public_ipv*` или
  `relay_egress_ipv*` relay.
- Фактические исходящие адреса второго хопа (`relay_egress_ipv4`,
  `relay_egress_ipv6`) объявляются в inventory явно и не выводятся из
  `public_ipv*`; публичные адреса exit и relay обязаны различаться
  ([ANSIBLE.md](ANSIBLE.md)).
- Отдельный клиентский профиль direct (`clients/direct-N.json`, используется
  только при отдельном разрешении) также выходит через `egress-0` exit-узла.
  Согласно инварианту № 7 ([INVARIANTS.md](INVARIANTS.md)), совпадение
  внешнего IP само по себе не различает direct и relay-путь: доказательством
  служат наблюдения/счётчики inbound и outbound.
- Для клиентского имени exit AAAA-запись не публикуется; единственным
  потребителем транзитного адреса exit остаются outbounds `slot-N-v6`/`slot-N-v4`
  relay.

## Закрытый транзитный и management-путь

- **Транзит (`transit_port`):** в `base_firewall_source_ports` exit-узла TCP на
  `transit_port` разрешён строго с `relay_egress_ipv4/32` и
  `relay_egress_ipv6/128`. Публикация TCP `transit_port` в
  `base_firewall_vpn_ports` запрещена валидатором inventory и рендерером.
- **Node API (`node_api_port`):** порт объявляется явно (без неявного fallback
  `2222`), запрещён в `base_firewall_vpn_ports` и допускается в
  `base_firewall_source_ports` строго от `node_port_allow`.
- RemnaNode работает с `network_mode: host` без публикации портов Docker и
  слушает wildcard (`app.listen(NODE_PORT)`), поэтому единственным сетевым
  ограничителем является действующая таблица `base` (`inet vpn_base/input`,
  `base_firewall_enabled: true`, без `base_firewall_bootstrap_exception`).
  Подробности и live `nft -j` preflight — в [REMNAWAVE_NODE.md](REMNAWAVE_NODE.md).
- Приватная overlay-сеть в этом срезе не реализуется; задача #71 остаётся
  отдельной.

## Публикация профиля

- Единственный источник серверных и клиентских JSON-конфигураций — принятая
  роль `profiles` (`ansible/playbooks/profiles.yml`). Создавать второй рендерер
  или публиковать ad-hoc профили/Host вручную запрещено.
- `profiles.yml` работает полностью локально, не подключается к хостам и не
  вызывает API панели: он атомарно пишет immutable-версию и ссылку `candidate`
  с пометкой `candidate-not-runtime-validated` ([PROFILES.md](PROFILES.md)).
- Запись профилей/Host в панель и панельный откат остаются заблокированными
  отсутствием CAS в закреплённом Remnawave 3.4.10 (issue #53,
  [PANEL_WRITE.md](PANEL_WRITE.md)); `vpnctl panel plan/show` работает только
  на чтение.
- `receipts/<bundle_id>.json` и ссылка `current` не создаются offline-рендером
  и могут появляться только после фактического прохождения runtime gates.

## Предусловия и границы среза

- Закреплённый образ RemnaNode `3.4.5`
  (`ghcr.io/remnawave/node:3.4.5@sha256:8f5a41708dfa86acc2561a520c9b40e2ff30812a16c28cf6bba6c365ca0f7d65`)
  со stock Xray `v26.11.9` и совместимой панелью `3.4.10`
  ([REMNAWAVE_NODE.md](REMNAWAVE_NODE.md)).
- Порядок rollout: сначала действующий source ACL роли `base`, затем проверка
  management-пути с CP, и только после этого запуск `remnawave_node` и приватный
  TLS cover origin на `127.0.0.1:<cover_tls_port>` ([COVER_SITE.md](COVER_SITE.md),
  [DEPLOYMENT.md](DEPLOYMENT.md)).
- Секреты (panel PKI `SECRET_KEY`, management credentials, vault-входы
  `profiles`) хранятся строго вне Git checkout.
- Вне области задачи: автоматизация/отбор upstream (#58), запись в панель (#53),
  приватный overlay (#71), production DNS/ACME и неавторизованный direct
  fallback.

## Проверки: статические и runtime acceptance

**Статические проверки (offline, без сети и хостов):**

- `BundlePolicyTest.test_relay_targets_exit_transit_without_relay_freedom_fallback`
  в `ansible/roles/profiles/tests/test_bundle_policy.py` проверяет вывод
  `bundle.render()`: каждый `slot-N-v6`/`slot-N-v4` relay нацелен на
  `public_ipv6`/`public_ipv4` exit и `transit_port` (никогда на адреса relay),
  relay не содержит `freedom` и маршрутизирует только в слотовые балансировщики
  или завершающий `block`, а exit содержит единственный `freedom` outbound
  `egress-0` с маршрутом direct → `egress-0` и `block` для не настроенных
  слотов `N > 0`.
- `make -C ansible validate test` и unit-тесты роли `profiles` проверяют
  контракт inventory, source ACL и неизменность кандидата без обращений к
  панели и узлам.

**Одноразовый runtime acceptance (в этом изменении НЕ выполнялся):**

- Guarded-драйвер `ansible/roles/profiles/tests/runtime_vm.sh` (только свежий
  GitHub-hosted Ubuntu guest; публичный отчёт
  `artifacts/active-probing/profiles-runtime.json`) проверяет реальный
  двухузловой стенд: прохождение клиентского трафика до exit sink с
  подтверждением пути и отсутствием утечек через relay/direct, отказ IPv6 с
  переходом на IPv4 и восстановлением, fail-closed при недоступности обеих
  семей и для пустых слотов, `xray -test` / read-back effective-конфигурации и
  закрытость transit/API по source ACL ([PROFILES.md](PROFILES.md)).
- В рамках текущего изменения одноразовый runtime acceptance **не запускался**,
  реальные контейнеры, сеть, firewall, DNS, панель и production-хосты не
  затрагивались.

## Откат

- **Репозиторий:** отдельный revert PR для squash-коммита без переписывания
  истории `master`. Откат Git сам по себе не возвращает состояние хостов.
- **Хосты (только при отдельном разрешении оператора):** сначала восстановить
  прежнюю таблицу firewall роли `base` (сохраняя закрытый `node_api_port` и
  `base_firewall_enabled: true`, без открытия публичного management API), затем
  выполнить штатный откат узла (`remnawave_node_state: rollback` с текущими
  credentials и повторным CP management gate, [REMNAWAVE_NODE.md](REMNAWAVE_NODE.md))
  и восстановить прежние входы cover/bundle с обязательным повторным наложением
  текущего списка `profiles_revoked_client_ids` до переключения активного
  указателя ([PROFILES.md](PROFILES.md)).
