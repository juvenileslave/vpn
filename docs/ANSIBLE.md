# Ansible: общий inventory и безопасная интеграция

`ansible/inventories/example/` — только синтетическая топология, не описание
работающих серверов. `make -C ansible validate test` и `profiles.yml` работают
локально. Роли base/cover/node имеют реальные opt-in entrypoints; их наличие
не означает production deployment. [PROFILES.md](PROFILES.md) отделяет offline
candidate от проверенного runtime и panel publication.

## Файлы и топология

```text
ansible/
  ansible.cfg
  playbooks/{base,cover_site,remnawave_node,profiles}.yml
  inventories/example/
    hosts.yml
    group_vars/{all,exit,relay,cp}.yml
    host_vars/{exit,relay,cp}-example.yml
  roles/{base,cover_site,remnawave_node,profiles}/
  scripts/validate_inventory.py
  scripts/tests/{test_validate_inventory,test_render_profiles}.py
```

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

Единственные firewall authority:

- `base_firewall_vpn_ports`: список `{proto: tcp|udp, port: integer}` публичных
  ports; direct и relay TCP listeners обязательны. Не transit/API/private origin.
- `base_firewall_source_ports`: список строгих mappings
  `{proto, port, source_cidrs}`. Safe strict CIDRs, nonempty list, no bool/string
  ports, duplicate/conflicting public/SSH rule или wide/invalid CIDR.
- Для transit TCP source list **в точности** relay egress `/32` и `/128`.
  Semantics проверяет profiles/inventory; generic base разрешает safe management
  subnets и не выводит transit sources самостоятельно.
- `node_api_port`: официальный default **2222**. Роль Node потребляет этот порт;
  source TCP rule должен в точности совпадать с `node_port_allow`.
- `node_port_allow`: safe CIDRs; допустимы также только exact management
  loopback `127.0.0.1/32`, `::1/128`. SSH trust policy этим не ослабляется.
  Для colocated panel — реальный bridge → private host-gateway путь с явно
  разрешённой подсетью. Dedicated CP — реально объявленный source/path;
  локальный служебный probe дополнительно требует явного loopback разрешения.
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
