# Воспроизводимое развёртывание: panel, node, cover и подписка

Документ описывает срез issue #77: единый упорядоченный entrypoint, объявленные
роли-владельцы и offline drift detection. **VPN не развёрнут**, production-хосты
не изменялись. Наличие playbook, inventory и проверок не является runtime
acceptance; граница «что доказано статически / что требует чистого одноразового
набора хостов» приведена ниже.

## Один entrypoint

```sh
cd ansible
../.venv/bin/ansible-playbook -i /путь/к/приватному/inventory/hosts.yml \
  playbooks/site.yml
```

`playbooks/site.yml` — цепочка принятых playbook'ов и один служебный play,
который переносит проверенную bootstrap-ом admin-личность на последующие фазы.
Собственной инфраструктурной логики (Docker/nginx/panel mutation) в нём нет:

| Порядок | Playbook | Что создаёт |
| --- | --- | --- |
| 1 | `bootstrap.yml` | Linux-администратор, SSH/firewall, Docker, приватная панель Remnawave на выбранном CP-хосте. |
| 2 | `remnawave_node.yml` | Host-network RemnaNode с закрытым management API и действующим base ACL. |
| 3 | `cover_site.yml` | Приватный TLS origin (`127.0.0.1:<cover_tls_port>`) на exit и relay. |
| 4 | `cp_proxy.yml` | Публичный vhost подписки на panel-хосте. |
| 5 | `panel_proxy.yml` | Loopback browser-endpoint панели; доступ только через `ssh -L`. |
| 6 | `profiles.yml` | Локальный coherent candidate bundle exit/relay/client. |

Повторный запуск той же команды — проверка идемпотентности. После фазы
bootstrap `site.yml` фиксирует проверенную key-only личность администратора
(`bootstrap_admin_selected`) для последующих фаз, поэтому inventory-подключение
не обязано заранее указывать администратора. Сам переход connection-переменных
доказывается только реальным запуском (runtime acceptance). Ручные `docker run`,
правки nginx, SQL/API-мутации панели и host-specific файлы в принятом пути
отсутствуют.
`--check --diff` выполняет проверки и рендер, но не заменяет runtime: проверка
SSH/панели в check mode честно падает на неподготовленном хосте.

Порядок 1–2 сохраняет контракт #73/#80: сначала действующий firewall и
доказанный management path, только потом API узла. Публичного `2222`/неявного
fallback в принятом контракте нет.

## Одна authority подписки

Публичный subscription endpoint объявлен **двумя** значениями в
`group_vars/all.yml`:

```yaml
subscription_public_host: sub.example.com
subscription_public_path: /sub/
```

Из них выводятся:

| Объект | Значение | Владелец |
| --- | --- | --- |
| `SUB_PUBLIC_DOMAIN` панели | `<host><path без завершающего />`, т.е. `sub.example.com/sub` | `remnawave_panel` (default) |
| `server_name` vhost | `<host>` | `cp_proxy` (default) |
| `cp_proxy_path_prefix` | `<path>` | `cp_proxy` (default) |
| `cp_proxy_upstream` | `panel_bind:panel_port` (IPv6 — `[::1]:port`) | `cp_proxy` (default) |

Отдельные `remnawave_panel_sub_public_domain`, `cp_proxy_server_name`,
`cp_proxy_path_prefix` и `cp_proxy_upstream` в inventory **запрещены**
`validate_inventory.py`: это был бы второй источник публикации. Рабочий
inventory мигрируется один раз: удалить эти переменные и объявить
`subscription_public_host/path`. DNS, ACME и сертификаты не настраиваются;
`cp_proxy_acme*` остаются явными входами роли.

### Выбор panel-хоста

Play-level `hosts` вычисляется до применения `group_vars`, поэтому
`{{ cp_placement }}` в нём не виден. Все playbook'и, чей target — panel-хост
(`cp_proxy`, `panel_proxy`, `remnawave_panel`, `backup`, `victoriametrics`),
выбирают inventory-visible группу:

```yaml
hosts: "{{ cp_proxy_hosts | default(groups.get('cp', []) if groups.get('cp', []) | length else groups.get('exit', [])) }}"
```

`cp_proxy_hosts`/`panel_proxy_hosts`/`remnawave_panel_hosts` (и аналогичные)
по-прежнему переопределяют группу. Перед ролями общий `pre_tasks` guard
`playbooks/tasks/require_panel_host.yml` сверяет фактический
`inventory_hostname` с `cp_placement`: `exit` требует пустую cp-группу и
exit-хост, `dedicated` — ровно один cp-хост. Несоответствие останавливает
запуск, а не превращается в `skipping: no hosts matched`. Явный `*_hosts`
override пропускает guard: согласованность выбора проверяет оператор; без
override `cp_placement` обязателен. Проверка выбора:
`ansible-playbook -i <inventory> playbooks/cp_proxy.yml --list-hosts` для
exit-placement показывает exit-хост.

## Объявленные входы

| Переменная | Контракт |
| --- | --- |
| `subscription_public_host` | Lowercase DNS-имя с точкой; без wildcard/IP/порта. В example — суффикс `.example.com`. |
| `subscription_public_path` | `/…/` (начинается и заканчивается `/`); запрещены dot-сегменты и `/api/`, `/admin/`, `/.well-known/`. |
| `node_api_port` | Обязательный явный integer; ровно одна TCP-запись `base_firewall_source_ports` с `source_cidrs`, равными `node_port_allow`. Example больше не использует upstream-значение `2222`. |
| `panel_bind`, `panel_port` | Loopback панели; их же использует `cp_proxy_upstream`. |
| `cover_tls_port`, `reality_sni` | Приватный host-loopback origin и единственное имя cover/REALITY. |
| `base_firewall_enabled`, `base_firewall_vpn_ports`, `base_firewall_source_ports` | Действующая политика base; API не публикуется. |
| `image_tags`, секреты панели/узла, `profiles_*` | По контрактам `PANEL.md`, `REMNAWAVE_NODE.md`, `PROFILES.md`; секреты — только вне checkout. |

## Удалённые и помеченные ручные отклонения

| Ручное отклонение | Состояние в этом срезе |
| --- | --- |
| Неявный `node_api_port: 2222` | Удалён ещё в #73; example теперь объявляет другой явный порт, а example-validator отказывает `2222`. ACL остаётся обязательным. |
| Публичный subscription base как отдельная настройка панели | Заменён одной authority `subscription_public_host/path`, из которой выводится `SUB_PUBLIC_DOMAIN`. |
| Сгенерированный вручную nginx-vhost | Рендерится ролью `cp_proxy` из той же authority; upstream выводится из panel bind/port. |
| Ручной контейнер узла | Роль `remnawave_node` с immutable image, PKI/mTLS/JWT gates и lifecycle. |
| Ad-hoc профиль/Host | Единственный renderer — роль `profiles`; публикация в панель не обходится вручную. |
| TCP/REALITY fallback | Не входит в принятый профиль: renderer и VLESS-parser принимают только XHTTP+REALITY, `tcp+reality` отвергается. |
| `base_firewall_bootstrap_exception` | Единственное временное исключение: `temporary: true`, причина — первичный root/администраторский доступ до применения hardening (#73), ACL-граница — `source_cidrs` обязан в точности равняться `node_port_allow`, удаление — до node rollout (preflight `remnawave_node` отказывает). Постоянного owner-approved исключения нет. |

Профили/Host в панели **не публикуются**: закреплённый Remnawave 3.4.10 не даёт
атомарного write-precondition (issue #53, `PANEL_WRITE.md`). `site.yml` создаёт
только offline `candidate` bundle; запись остаётся заблокированной. Это
contract decision, а не недоделанный шаг: добавлять второй panel writer в этом
срезе запрещено. Объявленный (несекретный) набор profiles/snippets/hosts для
read-only `vpnctl panel plan/show` остаётся отдельным operator-owned входом по
контракту [PANEL_WRITE.md](PANEL_WRITE.md); автоматической публикации из
`site.yml` нет.

## Drift detection

Ожидаемое состояние выводится из inventory тем же валидатором, без второго
рендерера:

```sh
make -C ansible state STATE_INVENTORY=/abs/outside-checkout/hosts.yml
make -C ansible drift STATE_INVENTORY=/abs/outside-checkout/hosts.yml \
  STATE=/abs/outside-checkout/observed.json
```

`STATE_INVENTORY` обязателен: пример inventory не является drift-базой и не
подставляется молча. Без него рецепт завершается кодом `64` (usage), но make
вернёт `2`. Snapshot
собирается оператором read-only; путь к нему и значения не публикуются.

`--state` принимает YAML/JSON snapshot со `schema: 1`:

```yaml
schema: 1
panel_host: cp-example
subscription:
  host: sub.example.com
  path: /sub/
  server_name: sub.example.com
  path_prefix: /sub/
  sub_public_domain: sub.example.com/sub
nodes:
  exit-example:
    api_port: 2223
    node_port_allow: [127.0.0.1/32, "::1/128", 203.0.113.30/32, "2001:db8:30::30/128"]
    base_firewall_vpn_ports: [tcp/80, tcp/8443]
    cover_tls_port: 9443
    reality_sni: www.example.com
  # relay-example: те же поля, что у exit-example
```

Сравнение каноническое: expected CIDR нормализуются, списки сортируются,
порядок не значим; неканоническая запись в snapshot считается drift. Отчёт
детерминирован и содержит **только пути** `missing`, `extra`, `mismatch`, без
значений (snapshot может содержать приватные адреса). Коды:
`0` — drift отсутствует, `1` — drift или неверный inventory, `2` — неверный
schema snapshot, `64` — не задан обязательный `STATE_INVENTORY`/`STATE`.

Эти коды относятся к **прямому** вызову `scripts/validate_inventory.py`.
GNU make схлопывает любой неуспешный рецепт в код `2`, поэтому через
`make -C ansible state|drift` коды `1`/`64` не наблюдаются: успех — `0`, любой
провал — `2`. Для точной диагностики вызывайте валидатор напрямую.

Snapshot — это наблюдаемое/объявленное состояние managed объектов, а не
результат второго рендера; сбор живого snapshot на хостах относится к runtime
acceptance ниже.

## Что воспроизводимо сейчас

- Состав и порядок развёртывания: `playbooks/site.yml`.
- Валидируемый контракт inventory: `make -C ansible validate`.
- Единственная authority подписки и выводимые panel/cp_proxy значения.
- Стабильный expected state и отказ на drift: `make -C ansible state|drift`
  с обязательным `STATE_INVENTORY`.
- Offline-тесты композиции, drift refusal, порядка списков и role-defaults:
  `make -C ansible test`.

## Проверки

На ревизии до этого review-fix фактически выполнено: `make -C ansible test` —
83 scripts-теста, node — 17, profiles — 32; pre-commit — all Passed;
`playbooks/site.yml --syntax-check` — OK. После review-fix интегратор
перепроверяет полный набор.

## Что остаётся runtime acceptance

Статические проверки **не доказывают** следующее; нужен чистый одноразовый
набор хостов (exit, relay, cp) и отдельное разрешение владельца:

1. Развёртывание с пустого состояния через `site.yml`: base/firewall, Docker,
   панель, node, cover, subscription vhost, panel_proxy, candidate bundle.
2. Второй запуск той же команды: `changed=0` для base, Docker, панели, node,
   cover, vhost и bundle; контейнеры и тома сохраняются.
3. Сквозная проверка подписки/туннеля: `SUB_PUBLIC_DOMAIN` от панели совпадает
   с vhost, `GET` subscription prefix отвечает через публичный TLS, client
   bundle проходит реальный туннель; отдельный revoked UUID отвергается.
4. Живой drift: снять наблюдаемое состояние управляемых объектов (read-only
   операторский шаг; автоматического collector в этом срезе нет), намеренно
   изменить объект (порт API, `server_name` vhost, `SUB_PUBLIC_DOMAIN`) и
   получить отказ `make -C ansible drift` на этом snapshot.
5. Rollback: revert-PR для роли/inventory, затем `remnawave_node_state:
   rollback`/`cover-site/lifecycle.py rollback` и восстановление прежнего
   firewall; Git revert не возвращает хосты.
6. Публикация профилей/Host в панель остаётся заблокированной (#53); её
   acceptance нельзя объявлять по offline bundle.

## Откат

- Репозиторий: revert squash-коммита отдельным PR; `master` не переписывается.
- Хосты: предыдущие роли/inventory, затем штатные role-level rollback'и выше.
  Этот документ не выполняет и не доказывает откат.
- Публичные DNS/ACME, production firewall и существующие сервисы не меняются
  этим срезом.
