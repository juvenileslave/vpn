# Ansible: общий inventory и безопасная интеграция

`ansible/inventories/example/` — только синтетическая топология, не описание
работающих серверов. `make -C ansible validate test` и `profiles.yml` работают
локально. Роли base/cover/node имеют реальные opt-in entrypoints; их наличие
не означает production deployment. [PROFILES.md](PROFILES.md) отделяет offline
candidate от проверенного runtime и panel publication.

## Bootstrap чистого хоста до приватной панели

[BOOTSTRAP.md](BOOTSTRAP.md) описывает отдельный guarded entrypoint
`playbooks/bootstrap.yml`: первоначальный root-доступ (ключ или интерактивный
`--ask-pass`) → Linux-администратор через `base` → новое key-only SSH-подключение
с проверкой UID/`sudo -n` → hardening/firewall → `docker` → приватная панель
`remnawave_panel` на правильном control-plane хосте. Playbook переиспользует
существующие роли; небольшая роль `bootstrap` добавляет только подготовку
минимального хоста и gates переподключения. Пример inventory не является
bootstrap-ready: в нём нет администратора, hardening-переключателей,
panel-пинов/доменов и источника секретов.

## Файлы и топология

```text
ansible/
  ansible.cfg
  playbooks/
    site.yml, bootstrap.yml, base.yml, cover_site.yml, cp_proxy.yml,
    panel_proxy.yml, remnawave_node.yml, remnawave_panel.yml, profiles.yml
  inventories/example/
    hosts.yml
    group_vars/{all,exit,relay,cp}.yml
    host_vars/{exit,relay,cp}-example.yml
  roles/{base,bootstrap,cover_site,cp_proxy,panel_proxy,
         remnawave_node,remnawave_panel,profiles}/
  scripts/validate_inventory.py
  scripts/tests/{test_validate_inventory,test_deployment_state,test_render_profiles}.py
```

`playbooks/site.yml` — единственный упорядоченный entrypoint принятого набора:
`bootstrap` → `remnawave_node` → `cover_site` → `cp_proxy` → `panel_proxy` →
`profiles`. Он только импортирует существующие playbook'и; порядок, переменные
и граница «воспроизводимо / runtime acceptance» описаны в
[DEPLOYMENT.md](DEPLOYMENT.md).

> Примечание: помимо перечисленного, каталог содержит playbook'и и роли
> (`playbooks/`, `roles/`) принятых компонентов; их контракты описаны в
> документации соответствующих ролей (см. README).

`hosts.yml` содержит только `all.children.{exit,relay,cp}`. В exit/relay ровно
по одному хосту. `cp_placement: dedicated` требует один отдельный cp;
`cp_placement: exit` — пустую cp группу и явный реальный путь от bridge-networked
colocated panel к разрешённому приватному host gateway, не только self-probe.
Хост не принадлежит двум группам. `node_role`: `exit`, `relay`, `control_plane`.
`ansible_host`, `public_ipv4`, `public_ipv6` обязательны и адреса уникальны.

`group_vars/<group>.yml`, `host_vars/<host>.yml` — mappings; вложенные каталоги
и неизвестные группы валидатор не принимает. Precedence: inventory group vars,
`group_vars/all`, `group_vars/<group>`, inline host vars, `host_vars/<host>`.
Несовпадение inline host и host_vars — ошибка. `cp_placement` только all.
SSH host key verification включена; неизвестный inventory фатален. YAML output
использует встроенный `ansible.builtin.default`, не внешний callback plugin.

## Общие поля

| Переменная | Контракт |
| --- | --- |
| `cp_placement` | `exit` или `dedicated`, только all |
| `client_family` | `v4`, `dual` |
| `s2s_family` | общий enum; self-steal bundle требует `v6_prefer` |
| `egress_family` | `v4_prefer`, `v6_prefer`, `v4_only` |
| `egress_slots` | integer 1…6; fixed `egress-0…egress-5` |
| `slot_fanout` | self-steal требует явно `ports`; неработающий `sni` не становится ports автоматически |
| `reality_sni` | одно точное DNS-имя cover/server/client; lowercase в профиле |
| `xhttp_path` | `/…`, без whitespace/query/fragment для renderer |
| `xhttp_mode` | self-steal требует `stream-one`, фиксированные padding/fingerprint |
| `image_tags` | публичный mapping строк; не заменяет immutable digest authority роли Node |

## Per-node cover, ports, source ACL

Роли вроде `node_exporter` и `victoriametrics` используют собственные
переменные (`node_exporter_listen_address`, `victoriametrics_listen_address`
и другие); они не являются частью контракта inventory и описаны в документации
ролей ([NODE_EXPORTER.md](NODE_EXPORTER.md), [METRICS_ROLE.md](METRICS_ROLE.md)).
Пример inventory задаёт для `victoriametrics` loopback-адрес и порт `8428`
в `group_vars/cp`.

Для exit и relay нужны `cover_tls_port`, абсолютный `cover_site_source`,
`cover_acme_email`, положительный integer `reality_max_time_diff_ms` (300000),
`remnawave_node_network_mode: host`. Cover additionally требует TOS и явное
подтверждение HTTP-01 DNS/TCP80 prerequisites; это не автоматическая DNS mutation.
`reality_target` не обязателен; если указан, должен **в точности** совпадать с
производным `127.0.0.1:<cover_tls_port>`. В server JSON используется только `dest`.

Exit: `exit_direct_port`, `transit_port`. Relay: `relay_slot_ports` с одним
портом на fixed slot, `relay_egress_ipv4`, `relay_egress_ipv6` с явно объявленным
фактическим источником второго hop. Не выводите NAT egress из `public_ipv*`.
Один общий validator renderer/inventory нормализует валидные IPv4/IPv6 нужной
семьи, запрещает loopback/link-local/multicast/unspecified/IPv4-mapped и
сопоставляет exact transit source `/32`/`/128`. Ограничение documentation ranges
остаётся отдельным example-only правилом, не вторым вариантом валидатора.

Единственные firewall authority (ровно одно объявление на хост; повтор в
`group_vars`/`host_vars` — ошибка, а не молчаливый precedence):

Для `exit`/`relay` `base_firewall_vpn_ports` и `base_firewall_source_ports`
обязательны к явному объявлению: role default `[]` не разрешает оставить
политику пустой. `base_firewall_enabled: true` проверяют validator и preflight
`remnawave_node`; role default `false` сохранён для bootstrap-совместимости.

- `base_firewall_enabled`: для production-like inventory обязателен `true`.
  `false` допустим только с явным временным
  `base_firewall_bootstrap_exception: {temporary: true, source_cidrs: […]}`,
  где список совпадает с `node_port_allow`; node-роль такое исключение
  отвергает.
- `base_firewall_vpn_ports`: список `{proto: tcp|udp, port: integer}` публичных
  ports; direct и relay TCP listeners обязательны. Не transit/API/private origin.
- `base_firewall_source_ports`: список строгих mappings
  `{proto, port, source_cidrs}`. Safe strict CIDRs, nonempty list, no bool/string
  ports, duplicate/conflicting public/SSH rule или wide/invalid CIDR.
- Для transit TCP source list **в точности** relay egress `/32` и `/128`.
  Semantics проверяет profiles/inventory; generic base разрешает safe management
  subnets и не выводит transit sources самостоятельно.
- `node_api_port`: обязательный явный порт. Неявного fallback `2222` нет;
  source TCP rule должен в точности совпадать с `node_port_allow`, а публичное
  объявление этого порта запрещено. Example объявляет другой явный порт:
  `2222` — только upstream-пример, и example-validator его отвергает. Удалённый
  (`dedicated`) CP не может иметь loopback-only `node_port_allow`.
- `node_port_allow`: safe CIDRs; допустимы также только exact management
  loopback `127.0.0.1/32`, `::1/128`. SSH trust policy этим не ослабляется.
  Пустой список, `0.0.0.0/0`, `::/0` и `any` отвергаются. Для colocated panel —
  реальный bridge → private host-gateway путь с явно разрешённой подсетью.
  Dedicated CP — реально объявленный source/path; локальный служебный probe
  дополнительно требует явного loopback разрешения.
- SSH, API, direct/transit/relay и cover listener ports не пересекаются. Origin
  host-loopback не имеет ни public, ни source-exposed alternate port.

См. [BASE_ROLE.md](BASE_ROLE.md), [COVER_SITE.md](COVER_SITE.md),
[REMNAWAVE_NODE.md](REMNAWAVE_NODE.md). Node source ACL проверяется **live** до
старта wildcard API; Docker host network не является firewall restriction.
Management address/source/delegate — обязательный реальный CP path, не
предполагаемый localhost. SECRET_KEY — panel PKI export, а не случайный пароль;
management probe использует mTLS/TLS1.3 + RS256 JWT. Секреты не входят в inventory.

`profiles_probe_url` — explicit credential-free HTTP(S) endpoint через exit slot0;
явно указанный port должен быть целым 1…65535. Некорректный, нулевой, пустой
или out-of-range port отвергается до записи/активации candidate. Synthetic
`probe.example.com` в example не является работающим сервисом. Offline schema
не подтверждает DNS, ACME issuance, SAN/chain/expiry, H2, namespace или client
transfer: это отдельные real runtime gates.

## Публикация подписки и drift

`subscription_public_host` и `subscription_public_path` — одна authority
публичного subscription endpoint. Из неё выводятся `SUB_PUBLIC_DOMAIN` панели и
`server_name`/`path_prefix` vhost `cp_proxy`; upstream выводится из
`panel_bind:panel_port`. Отдельные `remnawave_panel_sub_public_domain`,
`cp_proxy_server_name`, `cp_proxy_path_prefix` и `cp_proxy_upstream` в inventory
отвергаются как второй источник. Детали — [DEPLOYMENT.md](DEPLOYMENT.md).

Drift использует тот же валидатор и не рендерит второй конфиг:

```sh
make -C ansible state STATE_INVENTORY=/abs/outside-checkout/hosts.yml
make -C ansible drift STATE_INVENTORY=/abs/outside-checkout/hosts.yml \
  STATE=/abs/outside-checkout/observed.json
```

`STATE_INVENTORY` обязателен; без него рецепт завершается кодом `64`, а make
возвращает `2`.

`state` пишет канонический expected state из inventory; `drift` сравнивает его с
observed snapshot (`schema: 1`) и печатает только пути `missing`/`extra`/
`mismatch` без значений. Exit codes прямого вызова
`scripts/validate_inventory.py`: `0` — чисто, `1` — drift или неверный
inventory, `2` — неверный snapshot, `64` — не задан обязательный
`STATE_INVENTORY`/`STATE`. **Через make** любой провал рецепта схлопывается в
`2`, поэтому `0`/`1`/`64` наблюдаемы только при прямом вызове валидатора.
Сбор живого snapshot и сквозная проверка остаются runtime acceptance, а не
статическим доказательством.

## Синтетический пример и приватный inventory

Для example public IP только RFC5737 `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24` и `2001:db8::/32`; `ansible_host` равен synthetic public IPv4;
SNI заканчивается `.example.com`. Management CIDRs — documentation/private
ranges или exact standard loopback. Public example не содержит keys, UUID,
node PKI, real domains/server IDs или client links.

Рабочий inventory держится только в ignored
`ansible/inventories/production/`, credentials — Vault/файлы **вне checkout**.
`make check` запрещает publication production/prod/live inventory; `.gitignore`
не защищает уже tracked secrets. Проверять локально без подключения:

```sh
.venv/bin/python ansible/scripts/validate_inventory.py \
  --inventory ansible/inventories/production/hosts.yml
```

Валидатор показывает location/constraint, не секретные значения. Приватные пути
и inventory output всё равно не публикуйте. Inventory не даёт разрешения менять
production, firewall, certificates, DNS или существующую VM.

## Проверки и guarded acceptance

Python 3.11+, одна `.venv` в repository root:

```sh
make -C ansible bootstrap
make -C ansible validate
make -C ansible test
.venv/bin/python -m unittest discover -s ansible/roles/profiles/tests -p 'test_*.py' -v
```

`validate`: настоящий `ansible-inventory --list`, затем static cross-role schema.
`test`: temporary synthetic YAML плюс actual local profile playbook, generated
credentials, invalid-before-write/idempotence/redaction. Нет network calls к
панели или узлам. Эти тесты не заменяют runtime и не обещают работающий VPN.

Полный #47 entry и prerequisites — [PROFILES.md](PROFILES.md):

```sh
sudo env PATH="$PATH" HOME="$HOME" GITHUB_ACTIONS=true \
  RUNNER_ENVIRONMENT=github-hosted VPN_PROFILES_DISPOSABLE_GUEST=yes \
  bash ansible/roles/profiles/tests/runtime_vm.sh
```

Только explicitly guarded свежий GitHub-hosted Ubuntu guest: real pinned
RemnaNode/core, private cover/local ACME, base ACL, generated credentials,
synthetic isolated netns, visitor/adversarial/replay/slot/failover/load/rollback.
Не production/panel/DNS/public ACME. Unavailable runtime prerequisite — ошибка,
не silent skip и не fake static equivalence. CI jobs/entrypoints описывают
проверки; actual результаты интегратор публикует отдельно. Финальный `make check`
не заменяет runtime, Secret scan или отдельно разрешённый российский AC-12 pilot.

Profiles runtime требует принятых PR #50/#51 и source ACL из #49. Отсутствие
их файлов — явный FAIL на `accepted-runtime-role-contracts` с required PR,
не статическая замена runtime. При проверке parent применяет роли с их
daemon-wide resource ownership и реальным CP probe/commit; profiles не вызывает
внутренний `deploy` в обход registry lock. Test-only access-log overlay отдельно
привязан к исходному bundle и effective-config SHA256 в receipt (см. PROFILES.md).
