# RemnaNode: закреплённый узел и закрытый management API

Роль `ansible/roles/remnawave_node` реализует задачу #46. Она не создаёт узел в
реальной панели, не публикует Host/Profile и не меняет подписки. Перед запуском
оператор должен отдельно разрешить изменение конкретного сервера. Репозиторий
и наличие runtime-сценариев не являются доказательством production-развёртывания.

## Проверенные официальные факты

Срез первичных источников: 2026-11-12.

| Компонент | Проверенная версия / контракт |
| --- | --- |
| RemnaNode | `3.4.5`, исходный commit `4009f09de377cd1011fdfd798d6cc9b690637fb8` |
| Образ | `ghcr.io/remnawave/node:3.4.5@sha256:8f5a41708dfa86acc2561a520c9b40e2ff30812a16c28cf6bba6c365ca0f7d65` |
| Платформы manifest index | Linux amd64 и arm64 |
| Встроенный Xray | Tagged Dockerfile задаёт `v26.11.9`; healthcheck проверяет реальный `/usr/local/bin/xray version` и API `xrayVersion` |
| Совместимая панель | Официальный backend `3.4.10` зависит от `@remnawave/node-contract: 3.4.5` |
| Порт | Официальный пример `NODE_PORT=2222`; отдельный от клиентских listeners |
| Authentication | TLS 1.3, обязательный CA-проверенный клиентский сертификат и JWT RS256 в `Authorization: Bearer …` |

Для amd64 stock executable извлечён из проверенного GHCR layer
`sha256:528c0e0fe2094c58a0dcc8dc26927e0c9fcfc71d680313dbcd858cfc6924655c`:
SHA256 `/usr/local/bin/xray` —
`e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d`.
Он побайтно совпадает с executable официального
[Xray v26.11.9 amd64 release](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9);
SHA256 release ZIP проверен по upstream `.dgst`. Это execution-free registry
inspection, а не запуск Linux-container или runtime acceptance.

Manifest и config blob прочитаны непосредственно из GHCR. Роль разрешает только
этот проверенный immutable образ: ни `latest`, ни произвольные теги, ни
`CUSTOM_CORE_URL`/`geodata.core` не допускаются. Обновление образа требует новой
проверки официального API/core и обновления роли, а не замены тега в inventory.
Совместимость здесь означает совпадение официального protocol dependency; это
не проверка или обновление существующей панели. Её роль остаётся неизменной.

Источники:

- [Официальная установка, host network и firewall Node Port](https://docs.rw/install/remnawave-node).
- [Release 3.4.5](https://github.com/remnawave/node/releases/tag/3.4.5).
- [Dockerfile, stock core и s6](https://github.com/remnawave/node/blob/3.4.5/docker/Dockerfile).
- [HTTPS/mTLS listener](https://github.com/remnawave/node/blob/3.4.5/src/main.ts).
- [Структура SECRET_KEY и проверка PKI](https://github.com/remnawave/node/tree/3.4.5/src/common/utils/decode-node-payload).
- [JWT strategy RS256](https://github.com/remnawave/node/blob/3.4.5/src/common/guards/jwt-guards/strategies/validate-token.ts).
- [Реальные route constants](https://github.com/remnawave/node/blob/3.4.5/libs/contract/api/controllers/xray.ts).
- [Start schema](https://github.com/remnawave/node/blob/3.4.5/libs/contract/commands/xray/start.command.ts).
- [Health schema](https://github.com/remnawave/node/blob/3.4.5/libs/contract/commands/xray/get-node-health-check.command.ts).
- [Backend dependency 3.4.10](https://github.com/remnawave/backend/blob/3.4.10/package.json).
- [Официальная генерация сертификатов без IP SAN](https://github.com/remnawave/backend/blob/3.4.10/src/common/utils/certs/generate-certs.util.ts).
- [Операторы nft JSON, включая обязательный `match.op`](https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html#MATCH).
- [Docker: отдельные IPv4/IPv6 bridge-сети и gateway](https://docs.docker.com/engine/network/drivers/bridge/).

## Сеть: сначала действующий base ACL

Compose использует `network_mode: host`, без `ports`, Docker bridge, privileged
и `NET_ADMIN`. Embedded Xray и host-loopback cover находятся в одном network
namespace. В исходниках Node нет переменной bind address: `app.listen(NODE_PORT)`
слушает wildcard. Поэтому нельзя подменять source ACL loopback-публикацией Docker.

До активации роль проверяет:

1. `node_port_allow` — единственный authority для permitted management sources.
2. Ровно одна запись `base_firewall_source_ports` с `proto: tcp`, API-портом и
   тем же набором `source_cidrs`.
3. API-порт отсутствует в public/client/SSH-port declarations. Порт строго
   целочисленный, не boolean; пустые, дублирующиеся, неканонические, multicast,
   unspecified, link-local и широкие CIDR отклоняются.
4. **Действующий**, а не только отрендеренный `inet vpn_base/input`: INPUT-hook,
   filter/drop policy, безусловный loopback invariant, точные source accept для
   API и отсутствие широкого accept-пути для этого TCP-порта. Проверка выполняется
   через `nft -j`; `match.op` обязателен. Поддерживаются equality `==` и реальный
   conntrack bitmask lookup `in` только для established/related. Инвертированные
   `tcp dport != 2223`, `iif != lo`, `ct state != established`, неизвестные
   operands/expressions и jump/goto/verdict-map paths отклоняются даже при наличии
   правильных source rules. Это отказ до rollout, не создание второй firewall.
5. Явный management source входит в `node_port_allow`; source и destination
   одной IP-family. `cp_placement` поддерживает `exit` и `dedicated`.

Firewall создаёт только роль base. Node не добавляет собственные правила, не
перезагружает Docker и не меняет forwarding/output, чужие tables, сети, volumes
или containers. Base всегда разрешает интерфейс `lo`; локальные health probes
пользуются этим инвариантом, а не второй source allowlist. Сетевой ACL не отменяет
mTLS/JWT даже на loopback.

### Панель на exit

Предпочтительный путь — настоящий host-loopback с источником `127.0.0.1` либо
`::1`; generic source-port schema разрешает только точные `/32` и `/128` для
loopback. Пример authority: `node_port_allow: [127.0.0.1/32, '::1/128']`.

**Accepted panel Compose работает в Docker bridge. Его `127.0.0.1` — не host.**
Нельзя указывать loopback и объявлять такой путь рабочим. Для bridged CP нужен
явно заданный private host address и фиксированный private исходящий адрес CP,
включённый в `node_port_allow`; management probe должен выполняться из реального
CP namespace. Роль поддерживает такой private colocated path, но не меняет panel
networking или её API endpoints автоматически. `management_delegate` обязан
указывать inventory host/connection, действительно исполняющий probe в этом
namespace. Обычный delegate на host не доказывает доступ из bridge-контейнера.

### Выделенный CP

Укажите private node address и явный CP source `/32` и/или `/128` в
`node_port_allow` и соответствующей source-port записи base. Management delegate
должен быть настоящим CP, не exit с подставленным адресом. Роль bind-ит исходящий
socket к объявленному source и выполняет подлинную API operation с этого CP.
Loopback source/destination для dedicated placement отвергаются.

## Входы и секреты

Применяется convention существующей panel роли: controller-side file вне checkout
либо секретная переменная из encrypted vars; `no_log: true`, `diff: false`,
root-only files. Не записывайте реальные credentials в examples, Git или CI.

| Переменная | Значение |
| --- | --- |
| `remnawave_node_image` | Единственный проверенный полный tag + digest выше |
| `node_api_port` / `remnawave_node_api_port` | Общий API-порт / role-local consumer, default 2222 |
| `node_port_allow` | Единственный source authority |
| `base_firewall_source_ports` | Действующая matching TCP запись base |
| `remnawave_node_dir` | Owned project directory, default `/opt/remnanode`, допустим `/opt/<name>` |
| `remnawave_node_secret_key_file` **или** `remnawave_node_secret_key` | Ровно один источник настоящего encoded PKI payload |
| `remnawave_node_management_credentials_file` | Обязательный абсолютный controller-side JSON path вне checkout |
| `remnawave_node_management_delegate` | Обязательный inventory CP host/namespace connection |
| `remnawave_node_management_address` | Обязательный реальный IP destination |
| `remnawave_node_management_source` | Обязательный реальный исходящий IP CP |
| `remnawave_node_xray_config_file` **или** `remnawave_node_xray_config` | Необязательный operator-owned bootstrap config; mapping по умолчанию пуст |
| `remnawave_node_state` | `present`, `restarted` (force recreate), `rollback` |
| `remnawave_node_timeout` | Не менее 30 секунд; default 120 |

`SECRET_KEY` — **не случайный пароль**. Это base64 JSON с четырьмя PEM strings:
`caCertPem`, `nodeCertPem`, `nodeKeyPem`, `jwtPublicKey`, экспортируемый панелью.
Management credential JSON содержит `clientCertPem`, `clientKeyPem`,
`jwtPrivateKeyPem`. Предварительно проверяются CA/self-signature/сроки,
server/client EKU, подпись сертификатов CA и соответствие обеих cert/key пар,
а также настоящий RSA JWT public/private keypair.

Роль не извлекает эти credentials из real panel и не генерирует production PKI.
Оператор предоставляет их через разрешённый secret channel. Privileged JWT key
нужен для health-gated management, не является пользовательским токеном.
Постоянный health bundle на узле доступен только root и смонтирован read-only;
временная копия на CP удаляется `always`-блоком. Docker-root имеет доступ к secret
как и в существующей env-file convention; Docker socket нельзя выдавать клиентам.

Официальные node cert имеют random CN без IP SAN. Клиент не отключает проверку
цепочки TLS: `CERT_REQUIRED`/`rejectUnauthorized: true`, trusted CA, TLS1.3 и
**точное совпадение peer DER с экспортированным node certificate**. Это
certificate pinning вместо выдуманной hostname-проверки; `curl -k` не применяется.
`SNI_VERIFICATION=false` — явная официальная поддерживаемая настройка, не обход
mTLS/JWT. Производная SNI-опция не нужна для закрытого private management path.

## Транзакция, идемпотентность и откат

1. Контроллер проверяет input/ACL/network-path до изменения owned deployment.
2. Кандидат создаётся в private `/run` directory. OpenSSL проверяет PKI,
   `docker compose config --quiet` и нормализованная Compose policy — точную
   host-network модель. В check mode не стартует и не pull-ится контейнер.
3. До активации optional bootstrap config проверяется **stock Xray из того же
   реального immutable образа**, с `--network=none` и `xray run -test -config`.
   Ошибки транспорта/config не меняют active deployment.
4. Root-only content-addressed release сохраняет точные image/Compose/config/env.
   Existing directory/container принимается только с собственным marker/labels;
   Compose working directory должен быть release именно этого `/opt/<name>`,
   а read-only probe/health mounts — принадлежать тому же release. Чужие ресурсы
   никогда не adoption-ятся и не удаляются через remove-orphans. Singleton
   `vpn-remnanode` закреплён за одной directory на конкретном Docker daemon.
5. Compose запускается `up --detach --wait`. Настоящий authenticated healthcheck
   проверяет Node `3.4.5`, stock Xray `26.11.9` и `GET /node/xray/healthcheck`.
6. При bootstrap config роль вызывает `POST /node/xray/start` с официальной
   `internals.hashes` schema. Проверяются `isStarted`, отсутствие `error` и
   `xrayInternalStatusCached`. `forceRestart` используется после изменения/
   потери core/recreate, но не на каждое неизменившееся применение. Это bootstrap
   ownership, не реализация panel hashed-set reconciliation.
7. Затем delegated CP выполняет тот же настоящий health GET с mTLS/JWT из
   объявленного source. Только после этого pending release становится checked.
   Ошибка любого gate завершает rollout ошибкой, даже если восстановление успешно.
8. Неизменившийся healthy контейнер сохраняет ID и не recreate-ится. Restart или
   lost Xray восстанавливает bootstrap config и проходит те же gates.

Для host rollback повторно примените роль с `remnawave_node_state: rollback` и
текущими credentials. Она восстанавливает предыдущий **checked** immutable image,
Compose и config, снова проверяет node/core и CP management. В данном срезе оба
checked release используют единственный проверенный image digest; произвольные
исторические образы не поддерживаются. Это не Docker downgrade по guessed tag.

При автоматическом abort старый SECRET_KEY восстанавливается только если его PKI
identity совпадает с текущим input. Текущие management credentials, source authority
и timeout остаются авторитетными; независимая ротация/revocation CA/JWT/cert не
откатывается. Port и `require_xray` берутся из **фактически выбранного checked
release**, а не из отклонённого candidate. Поэтому API-only release с пустым
bootstrap config не обязан запускать Xray; его прежний порт должен иметь
действующий base ACL с текущими разрешёнными sources.

Автоматический abort сохраняет `pending`, owner и `restoration` outcome до
завершения CP gate. Повторный owner abort возвращает тот же восстановленный release,
не скрывает его за `restored:false`. Delegated CP всегда проверяет восстановление
текущими credentials из объявленного namespace. Только успешный реальный CP probe
разрешает `finish-abort`; restoration нельзя `commit`-ить как failed candidate.
Если старый PKI уже невалиден, локальная health проверка или CP gate не проходят,
executor явно останавливает только pending-owned node и остаётся failed. Pending
очищается после остановки либо успешного завершения восстановительного CP gate.

Все non-probe операции сериализуются неблокирующим daemon-specific `flock`:
`/run/vpn-remnanode/<sha256-Docker-ID>.lock`. Docker ID получен из реально выбранного
daemon (`docker info`), не из пути CLI socket или project directory. Persistent
root-only `/var/lib/vpn-remnanode/<sha256-Docker-ID>.json` закрепляет singleton за
directory; другой `/opt/<name>` не может захватить его даже между deploy и CP commit.
Два независимых lab daemon для host и relay имеют разные ID и не блокируют друг друга.
Смена directory существующего singleton не является поддерживаемой миграцией.

`state.json` хранит checked/previous/pending и outcome незавершённого восстановления.
Concurrent/uncommitted rollout отклоняется: чужой stage не может abort/commit/stop
pending другого owner. Если executor прерван, сохраните исходный private transaction
input и выполните `lifecycle.py abort <transaction-directory>` на том же разрешённом
host/daemon. Затем выполните настоящий CP probe с возвращёнными `probe.port` и
`probe.require_xray` и текущими credentials/source/address; после успеха выполните
`lifecycle.py finish-abort <transaction-directory>`. При отказе используйте
`lifecycle.py stop <transaction-directory>`, не оставляйте восстановленный node без
CP gate. Не удаляйте pending или daemon ownership record вручную вместо recovery.
Для репозитория откат — отдельный revert PR; Git revert не откатывает контейнер.

## Запуск и проверки

На отдельно разрешённом target должны уже работать accepted Docker/Compose role,
base firewall и `openssl`, Python 3, `nft`. На delegated CP нужны Python 3/OpenSSL
и реально доступный private/loopback path. Эта node playbook **не устанавливает**
новый Docker/firewall вместо отсутствующих prerequisites.

```sh
.venv/bin/ansible-playbook -i /outside-checkout/inventory.yml \
  ansible/playbooks/remnawave_node.yml \
  -e @/outside-checkout/encrypted-node-vars.yml --check

.venv/bin/ansible-playbook -i /outside-checkout/inventory.yml \
  ansible/playbooks/remnawave_node.yml \
  -e @/outside-checkout/encrypted-node-vars.yml
```

После интеграции parent запускает, не параллельно с редактированием:

```sh
.venv/bin/ansible-playbook -i ansible/inventories/example/hosts.yml \
  ansible/playbooks/remnawave_node.yml --syntax-check
.venv/bin/python -m unittest discover \
  -s ansible/roles/remnawave_node/tests -p 'test_*.py' -v
make -C ansible validate test
make check
```

Role-specific disposable acceptance entrypoint:

```sh
sudo env PATH="$PATH" HOME="$HOME" \
  GITHUB_ACTIONS="$GITHUB_ACTIONS" RUNNER_ENVIRONMENT="$RUNNER_ENVIRONMENT" \
  VPN_REMNAWAVE_NODE_DISPOSABLE_GUEST=yes \
  bash ansible/roles/remnawave_node/tests/runtime_vm.sh
```

Драйвер отказывается работать вне explicitly guarded GitHub-hosted Linux guest.
Он использует accepted pinned Docker роль, устанавливает только публичные
runtime prerequisites, генерирует временную CA/RSA PKI, применяет **реальную base
firewall роль**, стартует **реальный закреплённый Node**, а не mock server.

Prerequisite #49 — именно accepted source-port base role, а не её копия внутри
Node PR. До первого startup драйвер проверяет реальный active INPUT/source ACL;
при отсутствии prerequisite завершает сценарий с безопасным constraint label.
При неожиданном отказе Ansible выдаются только известные имена failed tasks и
числовой recap. Credentials, raw stdout/stderr/API/config и неизвестные task names
не печатаются; прежний отказ check-mode не превращается в искусственный success.

Сценарии включают оба `cp_placement`: для exit создаются настоящие dual-stack
Docker bridge CP-client containers с фиксированными private IPv4/IPv6 и явными
host gateways. Python/OpenSSL на host исполняют probe через `nsenter --net` именно
в namespace CP-контейнера: filesystem инструментов остаётся host-owned, исходящий
socket реально принадлежит bridge CP. Проверяются разные namespace IDs, реальные
Docker bridge addresses, разрешённые mTLS/JWT GET, wrong-JWT/no-cert отказ и
TCP-denial других bridge sources. Это network-client fixture, не развёртывание
панели и не запись в её API; port publishing и публичного обхода private cover нет.

Dedicated CP использует отдельный реальный namespace и IPv4/IPv6 source ACL.
Также проверяются private loopback TLS через embedded Xray, observations
namespace/socket, check-mode/unchanged ID, preactivation rejection, inverted live
nft accept rules, concurrent daemon lock и mismatched-directory rejection.
Checked rollback включает переход configured TCP/2222 → API-only TCP/2224 с
проверкой effective port/config. Unhealthy-start restoration и rescue после CP
ошибки проходят настоящий restored CP gate; оба CP-inaccessible варианта должны
остановить только owned node. Independent credential revocation не допускает revival.
Unrelated container ID/start time/network и forwarding sysctls сравниваются до/
после node operations. Драйвер удаляет только созданные им fixture resources;
pre-existing/mismatched singleton не удаляется. Real panel/cloud/DNS/ACME не используются.
Отчёт не печатает keys, certs, API tokens или secret config.

Повторно используемые lab helpers: `tests/runtime_vm.py:fixture(Path)` и
`files/lifecycle.py:api/health/start`. Две host-network ноды в одном интеграционном
lab требуют отдельных Docker daemon network namespaces/data-root/socket:
`ip netns exec ... docker` меняет namespace **CLI**, не namespace Docker daemon.
Полная protected REALITY/XHTTP client acceptance принадлежит profile-сценариям
#47; node-сценарий изолированно доказывает embedded-core host-loopback TLS path.

Runtime acceptance подтверждается только успешным запуском entrypoint в указанном
Linux guest и приложенными фактическими результатами. Статические тесты не заменяют
Docker/API/IPv6/rollback evidence; disposable guest не доказывает production pilot
или сохранение поведения после перезагрузки host kernel.
