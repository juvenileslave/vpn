# ADR-0001: Приватный L3 overlay для entrance, exit и control plane

- **Статус:** черновик, требует одобрения владельца.
- **Дата:** 2026-11-21.
- **Задача:** #71.
- **Связь с исходным планом:** архитектурное дополнение к
  [исходному плану](../ARCHITECTURE_PLAN.md) и
  [реестру решений](../DECISIONS.md). Файл `docs/ARCHITECTURE_PLAN.md`
  сохраняется без изменений (побайтово).
- **Состояние реализации:** не реализовано и не развёрнуто; документ
  фиксирует проектируемый контракт до добавления схемы inventory, роли
  Ansible и тестов. Runtime acceptance этим PR не выполняется.

## Контекст

В топологии проекта (D-001, D-003, D-005) работают три роли узлов: RU
entrance (`relay`), зарубежный `exit` и control plane (`cp` в режиме
`cp_placement: dedicated` либо совмещённый с `exit` при
`cp_placement: exit`). Между ними ходят два вида межузлового трафика:
пользовательский transit (`relay` → `exit`) и управление
`CP → node` (Remnawave node API и административный доступ к панели).

Требуется единый приватный L3 overlay между объявленными пирами
entrance, exit и control plane, чтобы:

- пользовательский transit и управление `CP → node` использовали один
  приватный сетевой слой;
- Remnawave node API и панель управления не были доступны из публичного
  интернета;
- существующие инварианты ролей (`base`, `remnawave_node`, `panel_proxy`)
  и отдельный break-glass SSH-доступ сохранялись без ослабления.

## Решение

Использовать **WireGuard** как единый приватный L3 overlay между
объявленными пирами (`relay`, `exit`, `cp`), управляемый отдельной
ролью Ansible с декларативным описанием пиров и ключей (ключи хранятся
только вне публичного inventory — в SOPS или controller-side файлах вне
checkout).

### Обоснование выбора WireGuard

- Встроен в штатное ядро Linux (Debian/Ubuntu), имеет малую поверхность
  атаки и минимальные накладные расходы для transit-трафика.
- Модель Cryptokey Routing (`AllowedIPs` на каждого пира) напрямую
  выражает принцип наименьших привилегий на уровне L3 без динамических
  протоколов маршрутизации.
- Статическая декларативная конфигурация совместима со статическим
  валидатором inventory (`ansible/scripts/validate_inventory.py`),
  `--check --diff` и идемпотентным применением Ansible.
- Не требует внешнего SaaS или дополнительного coordination server в
  контуре управления.

### Рассмотренные и не выбранные альтернативы

| Вариант | Причина отказа |
| --- | --- |
| IPsec (strongSwan/Libreswan) | Избыточная сложность стека IKE/XFRM, выше риск непрозрачной конфигурации политик и дрейфа маршрутов для статической топологии из трёх узлов. |
| Tailscale / Headscale | Вводит сторонний SaaS или дополнительный критический coordination server со своей моделью ACL и вмешательством в маршруты/DNS. |
| Постоянные SSH-туннели | Деградация TCP-over-TCP под потерями для пользовательского transit, хрупкое восстановление сессий и смешение транспорта со служебным break-glass SSH. |

## Адресация

- **IPv6 ULA предпочтительна:** внутренние адреса пиров выделяются из
  явно объявленного приватного префикса ULA в диапазоне `fc00::/7`
  (локально назначаемый `fd00::/8` по RFC 4193). В синтетических
  примерах используется только документационный/ULA-диапазон, например
  `fd00:db8:1::/64` (`fd00:db8:1::10/128` для `exit`,
  `fd00:db8:1::20/128` для `relay`, `fd00:db8:1::30/128` для `cp`).
- **IPv4 fallback:** при отсутствии рабочего IPv6 у одного из хостов
  используется явно объявленная приватная IPv4-подсеть (RFC 1918, без
  пересечения с сетями хоста и Docker) с тем же набором политик доступа
  и маршрутизации.
- **Внешний транспортный endpoint:** предпочтителен `public_ipv6`
  (в примерах RFC 3849 — `2001:db8:10::10`, `2001:db8:20::20`,
  `2001:db8:30::30`) с явным fallback на `public_ipv4` (в примерах
  RFC 5737 — `192.0.2.10`, `198.51.100.20`, `203.0.113.30`).
- Оба семейства адресов объявляются в inventory явно и проверяются
  статическим валидатором; неявный вывод overlay-адресов из публичных
  IP запрещён.

### Схема переменных inventory и проверка

| Переменная | Слой | Контракт |
| --- | --- | --- |
| `overlay_backend` | `group_vars/all` | Authority; только `wireguard`. |
| `overlay_interface` | `group_vars/all` | Authority; имя Linux-интерфейса (до 15 символов, не `lo`), в примере `wg0`. |
| `overlay_port` | `group_vars/all` | Authority; целочисленный UDP-порт `1…65535`, ровно один раз объявлен как `udp` в `base_firewall_vpn_ports` на каждом пире, не пересекается с SSH, `node_api_port`, cover и VLESS-портами. |
| `overlay_ipv6_prefix` | `group_vars/all` | Authority; строгий IPv6-префикс внутри ULA `fc00::/7` (`/48…/120`). |
| `overlay_ipv4_fallback` | `group_vars/all` | Authority; boolean (`true`/`false`), явное включение IPv4 fallback. |
| `overlay_ipv4_prefix` | `group_vars/all` | Authority; строгий RFC 1918 префикс (`/16…/29`), обязателен при `overlay_ipv4_fallback: true` и запрещён при `false`. |
| `overlay_ipv6` | хост | Уникальный `/128` host CIDR внутри `overlay_ipv6_prefix` (обязателен для каждого пира). |
| `overlay_ipv4` | хост | Уникальный рабочий `/32` host CIDR внутри `overlay_ipv4_prefix` (обязателен для всех пиров при `overlay_ipv4_fallback: true`, запрещён при `false`). |
| `overlay_allowed_ips` | `host_vars` | Authority; необязательный список узких приватных CIDR пира (минимум `/64` ULA и `/24` RFC 1918), включающий адреса пира, без `0.0.0.0/0`, `::/0`, публичных диапазонов и пересечений между пирами. |
| `overlay_private_key_file` | `host_vars` | Authority; необязательный абсолютный controller-side путь вне checkout и каталога inventory. Inline-ключи (`overlay_private_key`, `overlay_preshared_key`, `wireguard_*`) в inventory запрещены. |

Связанные authority-проверки: `node_port_allow` и единственная запись
`base_firewall_source_ports` для `node_api_port` при `cp_placement: dedicated`
обязаны включать overlay-адреса CP (обе семьи при включённом fallback) и не
содержать публичные IP CP; `base_ssh_trusted_cidrs` обязан быть непустым и
не пересекаться с префиксами overlay.

Схема проверяется статически в `ansible/scripts/validate_inventory.py` и
покрыта unit-тестами в `ansible/scripts/tests/test_validate_inventory.py`
(`make -C ansible validate test`); синтетический пример объявлен в
`ansible/inventories/example/`.

## Маршрутизация least-privilege

- **Без default route через overlay:** `0.0.0.0/0` и `::/0` в
  `AllowedIPs` запрещены схемой inventory и preflight-проверкой роли.
- **Per-peer `AllowedIPs`:** каждому пиру назначаются только его точные
  хостовые маршруты (`/128` для IPv6 ULA и `/32` для IPv4 fallback)
  либо явно объявленные узкие подсети управления/узлов, нужные для
  конкретной связи.
- **Изоляция клиентов:** клиентские сессии VLESS на entrance (`relay`)
  и `exit` не получают маршрутов и доступа к control plane и
  management-интерфейсам узлов.
- **Независимость клиентского пути:** перезапуск overlay или отказ
  одного пира не меняет системный default route, клиентский VLESS
  ingress и внешний egress-путь на `exit`.

## Политика firewall и bind-контракт

- Роль [`base`](../BASE_ROLE.md) остаётся **единственным firewall
  authority** на хосте (`table inet vpn_base`; ровно одно объявление
  `AUTHORITY_KEYS` на хост без перекрытия между слоями inventory). Роль
  overlay не создаёт собственные таблицы пакетного фильтра.
- **UDP-порт overlay** объявляется в `base_firewall_vpn_ports` как
  публичный `udp`-listener и не пересекается с SSH, `node_api_port`,
  cover и VLESS-портами.
- **Remnawave node API (`node_api_port`):**
  - контейнер [`remnawave_node`](../REMNAWAVE_NODE.md) сохраняет
    wildcard-listener в `host` network; bind-политика выражается через
    live source ACL роли `base`;
  - в `base_firewall_source_ports` сохраняется ровно одна `tcp`-запись
    для `node_api_port`, чей `source_cidrs` в точности равен
    `node_port_allow`; публичное объявление `node_api_port` запрещено;
  - в качестве источника управления в `node_port_allow` и
    `remnawave_node_management_source` (а также адреса назначения
    `remnawave_node_management_address`) используются overlay-адреса CP
    и узла, а не их публичные IP; для `cp_placement: dedicated`
    loopback-only источники по-прежнему запрещены;
  - внешний скан публичного IPv4/IPv6 узла не может подключиться к
    `node_api_port`.
- **Preflight-отказ небезопасных комбинаций:** до мутации хоста
  валидатор и preflight роли отклоняют `0.0.0.0/0`/`::/0` в
  `AllowedIPs`, конфликты портов, публичное открытие `node_api_port`,
  отсутствие UDP-порта overlay в `base_firewall_vpn_ports` и
  несоответствие `node_port_allow` overlay-адресу CP.

## Доступ к панели управления

- Панель Remnawave и [`panel_proxy`](../PANEL_PROXY.md) остаются
  привязанными к loopback/приватному адресу на хосте control plane и не
  публикуются напрямую в публичный интернет.
- Административный доступ к панели проходит через entrance (`relay`) и
  приватный overlay вместо прямого публичного пути к `exit` или
  публичного порта на CP.
- Контракт публикации подписок (`subscription_public_host`,
  `subscription_public_path`) остаётся единственной authority
  ([DEPLOYMENT.md](../DEPLOYMENT.md)) и не смешивается с администрированием.

## Break-glass: прямой SSH

- Прямой SSH-доступ к каждому объявленному хосту (`ansible_host`,
  `base_ssh_port`, `base_ssh_trusted_cidrs`) сохраняется как отдельный
  независимый путь.
- Overlay **не является** единственным способом достичь узел; роль
  overlay не изменяет конфигурацию `sshd` и правила SSH в `base`.
- При отключённом entrance (`relay`) или остановленном overlay прямой
  SSH к каждому узлу остаётся работоспособным.

## Последствия, риски и откат

### Последствия и риски

- **Риск потери управления CP/узлом:** ошибка в ключах, endpoint,
  `AllowedIPs` или преждевременное переключение `node_port_allow` на
  overlay может прервать связь `CP → node`.
- **Риск деградации IPv6 / MTU:** отсутствие связности IPv6 без
  проверенного IPv4 fallback или завышенный MTU способны нарушить
  transit и управление.
- **Смягчение — поэтапное применение пиров:** сначала поднимается
  overlay и проверяется связность пиров (IPv6 и IPv4 fallback) при
  сохранённом прямом SSH, и только после этого `node_port_allow` и
  `remnawave_node_management_*` переводятся на overlay-адреса с
  живой проверкой CP-пути до фиксации.

### Откат

- Откат на хосте переводит роль overlay в состояние отключения:
  останавливает и отключает systemd-юнит overlay, удаляет интерфейс,
  конфигурацию и созданные overlay-маршруты, после чего обновляет
  правила `base` (удаляя UDP-порт overlay и возвращая согласованные
  `node_port_allow`). Прямой SSH-путь при откате не затрагивается.
- **Откат в репозитории (`git revert`) не изменяет хосты:** для
  фактического снятия конфигурации на узлах требуется явный запуск
  rollback-сценария Ansible или восстановление через break-glass SSH.

## Что не входит (Non-goals)

- Production rollout, изменение реальных хостов, DNS или firewall вне
  одноразовых тестовых VM.
- Замена mTLS/TLS 1.3 и RS256 JWT для Remnawave node API.
- Обещание обхода DPI или работы при блокировке публичного IP.
- Открытие публичного listener для Remnawave node API или панели.
- Автоматизация сторонних апстримов и реализация write adapter панели.
- Изменение `docs/ARCHITECTURE_PLAN.md` и пересмотр решений D-001…D-012.

## План проверки

1. **Статические проверки (локально и в CI):**
   - `make check` (отсутствие секретов, реальных адресов и ключей,
     корректность YAML и форматирования);
   - `make -C ansible validate test` (строгая схема overlay в
     `ansible/scripts/validate_inventory.py` и unit-тесты на отказ
     default route, конфликтов портов, несогласованного
     `node_port_allow` и невалидных адресов).
2. **Проверки на одноразовых VM (disposable VM, отдельный guarded
   запуск в последующих срезах):**
   - установление пиров по IPv6 ULA и принудительный IPv4 fallback с
     той же объявленной политикой;
   - доступ `CP → node API` только через overlay и отказ при внешнем
     сканировании публичного адреса;
   - доступ к панели через entrance/overlay при сохранении
     loopback/private привязки панели на своём хосте;
   - рабочий прямой break-glass SSH к каждому узлу при остановленном
     entrance;
   - независимость клиентского VLESS ingress и egress-пути от
     перезапуска overlay или отказа одного пира;
   - `--check --diff`, повторное идемпотентное применение и откат без
     попадания реальных ключей или адресов в вывод репозитория.

**Граница acceptance:** этот PR добавляет только черновик ADR для
одобрения владельцем; runtime acceptance и развёртывание на хостах
этим PR не выполняются.
