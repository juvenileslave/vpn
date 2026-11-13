# Self-steal: один bundle exit / relay / client

Роль `profiles` — единственный **локальный** renderer принятого профиля VLESS +
XHTTP + REALITY. Она заменяет два самостоятельных exit/transit-конфига одним
`exit.json`: direct-v4/v6 и transit-v4/v6 нельзя активировать поверх друг друга.
Рендер не выполняет SSH, не меняет firewall/сервисы и не публикует Host/Profile
через панель. Синтаксический `xray -test` не доказывает работающий туннель.

## Входы и постоянные ограничения

Публичный контракт берётся из [ANSIBLE.md](ANSIBLE.md), а cover/node — из
[COVER_SITE.md](COVER_SITE.md) и [REMNAWAVE_NODE.md](REMNAWAVE_NODE.md).
Для exit и relay обязательны собственные `reality_sni`, `cover_tls_port`,
`cover_site_source`, `cover_acme_email`, `reality_max_time_diff_ms`,
`remnawave_node_network_mode: host`, адреса, порт node API и его source ACL.
`reality_sni` — ровно одно точное DNS-имя; оно же определяет сертификат cover и
клиентский `serverName`. Второй hostname/target authority отсутствует.

| Вход | Требование |
| --- | --- |
| `exit_direct_port`, `transit_port` | разные целые порты; без bool/строк; не SSH/API/origin |
| `relay_slot_ports` | ровно `egress_slots` разных целых портов; индекс — постоянный слот |
| `cover_tls_port` | отдельный порт приватного host-loopback origin |
| `reality_target` | необязательная проверка совместимости входа: только производное `127.0.0.1:<cover_tls_port>`; внешний/другой target отвергается |
| `reality_max_time_diff_ms` | положительное целое; исходная политика — **300000** |
| `relay_egress_ipv4`, `relay_egress_ipv6` | явно объявленный фактический адрес выхода relay; валидный IP нужной семьи, нормализуемый для сравнения, без loopback/link-local/multicast/unspecified/IPv4-mapped; NAT-адрес не выводится из public IP |
| `base_firewall_vpn_ports` | публичные TCP-listeners direct/relay; не transit/API/origin |
| `base_firewall_source_ports` | transit TCP только от **точно** relay `/32` и `/128`; API TCP в точности `node_port_allow` |
| `profiles_probe_url` | явный URL HTTP(S), доступный через exit slot0; без credentials; явно заданный порт — целое 1…65535, не пустой/некорректный |
| `slot_fanout` | **явно `ports`**; `sni` отвергается, не переключается автоматически |
| `s2s_family` | `v6_prefer` для этого фиксированного профиля |
| `egress_family` | `v4_prefer`, `v6_prefer`, `v4_only` — внешний выход exit |

Секретный extra-vars/Vault файл, **вне checkout**, содержит:

- `profiles_credentials: {exit: {private_key, public_key, short_ids}, relay: ...}`:
  две разные X25519-идентичности; canonical base64url, проверка соответствия пары;
  unique nonempty `short_ids`, каждый ровно 16 lowercase hex (8 random bytes).
- `exit_direct_client_ids`: UUID пользователей отдельного direct;
  `transit_client_ids`: ровно один отдельный служебный UUID на слот;
  `relay_client_ids`: UUID клиентов relay, без пересечения с transit.
- `profiles_user_slots`: один integer 0…N−1 на каждый relay UUID.
- `profiles_upstreams`: mapping третьего слота → **настоящий proxy outbound**.
  Тег renderer задаёт сам. Нет acquisition/selection, freedom, loopback или
  неявного chained outbound. Отсутствующий слот — blackhole, не exit freedom.
  Проверка до записи запрещает также IPv4-mapped loopback, числовые loopback
  формы системного dialer и `localhost`/`.localhost`/локальные имена loopback.
  DNS-имя настоящего upstream не резолвится offline: его фактический адрес и
  proxy authentication остаются отдельным runtime gate, без freedom fallback.
- `profiles_revoked_client_ids`: текущий независимый список отозванных UUID;
  его накладывают и при восстановлении старого bundle. Renderer не вращает keys.

Старые одиночные `reality_private_key`/`reality_short_ids` не являются API роли.
Секреты, UUID и client links не входят в публичный manifest/Ansible diff.

Постоянная политика: `stream-one`, padding `100-1000`, клиентский fingerprint
`firefox`, без `flow` и Vision/raw-TCP fallback. Сервер пишет только `dest`,
`xver: 0`, `show: false`, `maxTimeDiff`. Fallback upload/download fingerprint
limits, mux switches и `mux.cool` не добавляются.

## Версия и семантика XMUX

Фактический runtime — immutable RemnaNode **3.4.5**, stock Xray **26.11.9**;
проверенная protocol pairing панели — backend **3.4.10** (не установка панели).
Image digest и проверка API/binary version описаны в REMNAWAVE_NODE.md.

В pinned [transport_method.go](https://github.com/XTLS/Xray-core/blob/v26.11.9/infra/conf/transport_method.go)
пустой `xmux` превращается в `maxConnections: 3`, `hMaxRequestTimes: 600-900`,
`hMaxReusableSecs: 1800-3000`; остальные нулевые range-поля остаются runtime
sentinels. **Отсутствие xmux не означает отсутствие multiplexing.** Роль эти
defaults не переопределяет и не обещает отключённый H2/XMUX.

## Рендер, кандидат и сохранение рабочего результата

```sh
make -C ansible bootstrap
.venv/bin/ansible-playbook -i /путь/к/inventory/hosts.yml \
  ansible/playbooks/profiles.yml \
  -e @/путь/вне/checkout/profiles-vault.yml --ask-vault-pass
```

Default output — ignored `artifacts/profiles/`, другой абсолютный путь задаётся
`profiles_output_dir`. Каталоги имеют `0700`, файлы `0600`; secret tasks скрыты.
До файловых изменений проверяются ports/SNI/target/credentials/slot/ACL/declared
namespace. Ключ вычисляется и проверяется локально, без вызова панели.

```text
profiles/
  versions/<bundle_id>/
    exit.json                 # coherent direct + transit, обе семьи
    relay.json                # per-user fixed-slot routing, без freedom
    clients/{direct,relay}-N.json
    firewall.json             # тот же source/public контракт
    manifest.json             # opaque identity, адреса/SNI/runtime pin, без UUID/key
    inputs.private.json       # только root/operator: входы для восстановления
  candidate -> versions/<bundle_id>
```

Файлы версии immutable; изменение уже записанной версии отвергается. Новая
полная версия и `candidate` публикуются atomic rename. Повтор идентичных входов
без mode drift не меняет bytes/link и даёт `changed=0`. Если права каталогов
или файлов стали шире/уже `0700`/`0600`, reapply восстанавливает именно эти
права с `changed=1`, не переписывая bytes/usable pointer; `--check` только
сообщает drift. Следующий reapply снова `changed=0`. Небезопасные symlink-пути
и content tampering отвергаются. Ошибка не заменяет ранее usable output.
`current` и runtime receipt **не создаются offline playbook**: manifest прямо
помечен `candidate-not-runtime-validated`. Driver одноразового стенда создаёт
`receipts/<bundle_id>.json` и атомарный `current` только после реальных gates.
На production эти gates и установка требуют отдельного разрешения оператора.

## Маршрутизация и source ACL

`egress-0` — freedom **только exit** с приватными адресами/BitTorrent в block и
`finalRules` после DNS. Direct явно выбирается отдельным клиентским файлом.
Третий слот без настроенного outbound маршрутизируется в `block`; пользователь
не может предъявить UUID соседнего слота на другом relay listener.

Каждый relay slot имеет VLESS outbounds на конкретные IPv6/IPv4 **того же exit**.
[leastPing](https://github.com/XTLS/Xray-core/blob/v26.11.9/app/router/strategy_leastping.go)
выбирает только свой IPv6 selector; `fallbackTag` — его same-exit IPv4.
Observatory проверяет реальную доступность через служебные credentials каждые
2 s. Нездоровый IPv6 переходит на IPv4; недоступный IPv4 даёт dial failure,
никакого relay freedom/direct rescue. Восстановление IPv6 возвращает preferred
path. Это переключение **новых** потоков, не бесшовная миграция старого TCP/H2;
задержка обнаружения включает probe/transport timeout и интервал. Пустые слоты
не превращаются в probe freedom: probe также упирается в exit blackhole.

## Почему `sni` не объявлен работающим

`nginx stream ssl_preread` не расшифровывает REALITY. При единственном принятом
`reality_sni` все slot ClientHello имеют одинаковый SNI; encrypted VLESS UUID
ещё недоступен nginx. Runtime scenario проверяет **реальный** passthrough:
slot0 работает через SNI map, slot1 с тем же SNI попадает на чужой фиксированный
listener и не получает tunnel; его прямой explicit port работает через
настоящий disposable SOCKS upstream. Это воспроизводимый feasibility gate,
не статическая проверка map и не TLS termination. Результат сохраняется в
runtime report; только явный `ports` mode имеет положительную demonstration.

## Полный одноразовый runtime

**Только свежий GitHub-hosted Ubuntu 24.04 guest** с root/systemd,
CAP_NET_ADMIN/netns, IPv6, публичной загрузкой pinned packages/image/toolchain.
Не existing VM, сервер, real panel, owner secrets, публичные DNS/ACME.

Для protocol helper закреплён полный minimum Go `1.27.1` в его `go.mod`;
`GOTOOLCHAIN=auto` получает реальную patch-version, а не недоступное имя
language-only `go1.27`. Build выполняется с `-mod=readonly`, без изменения
checkout/dependency checksums и без owner credentials.

```sh
make -C ansible bootstrap
sudo env PATH="$PATH" HOME="$HOME" \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  VPN_PROFILES_DISPOSABLE_GUEST=yes \
  bash ansible/roles/profiles/tests/runtime_vm.sh
```

Entry устанавливает public prerequisites и вызывает actual playbook. Exit Node
использует host Docker daemon; relay Node — **другой daemon в relay netns** с
собственными socket/data/exec roots. `docker --network host` относится к
namespace daemon, не CLI. API использует настоящие generated PKI, mTLS/TLS1.3
и RS256 JWT, без выдуманной health endpoint. Stock core извлекается из
проверенного image и служит также real client/upstream runtime.

Relay использует также собственный containerd: отдельные address/root/state,
без общего host `/run/containerd/containerd.sock`. Оба процесса входят в net
namespace через `nsenter --net`, не `ip netns exec`, чтобы сохранить видимость
реального cgroup mount. Driver сравнивает inode net namespace dockerd/containerd
с relay и требует отличия от exit до запуска Node.

Cover выдаётся настоящим Certbot HTTP-01 через pinned local Pebble, без
challenge bypass; relay запускает тот же role-generated origin snapshot в
своём host network. Проверяются chain/SAN/expiry, H2, actual namespaces,
visitor TLS1.2/1.3 + H1/H2, actual origin baseline для unknown/missing SNI,
Host/path, разрешённый direct/relay tunnel, source ACL v4/v6 и закрытые API/origin.

Сеть — synthetic bridge/netns без default routes. Только в fixture подставляется
**конкретный geoip.dat**: документационные test endpoints исключены из PRIVATE,
RFC1918/ULA/link-local/loopback остаются blocked. Production routing/finalRules
не ослабляются; geodata/core SHA256 записываются. Это предел fixture, а не
доказательство всех stock reserved-IP правил production. Core не заменяется.

Для наблюдений driver добавляет **только в одноразовую effective-конфигурацию**
`log.access: /dev/stdout`. Immutable `exit.json`/`relay.json`, production logging,
routing и `finalRules` не меняются. Receipt содержит исходный file SHA256,
canonical effective-config SHA256 и точное описание overlay для каждого
bundle/node; instrumented config отдельно проходит настоящий `xray -test`.
Route gate связывает один случайный flow ID с измеренными sink bytes/SHA256,
реальными access observations `[inbound → outbound]` к application port 18080
на обоих stock cores и уникальными TCP payload sequence bytes того же
второго hop. HTTP204 observatory использует отдельный порт 18081. Победитель
должен нести ≥1 MiB в каждом направлении на socket, реально `ESTABLISHED`
и у relay, и у принимающего exit; альтернативная семья ограничена <64 KiB
probe-трафика. SYN, повторные пакеты, простое наличие адреса в pcap и один
external IP этот gate не проходят. Ограничение 64 KiB относится к доказательству
одноразового сценария, не добавляет production timeout или fallback cutoff.

Scenario включает wrong keys/shortIds/VLESS, malformed и TCP-fragmented
handshake, timestamp ±301 s, fresh/expired replay (реальный wait 302 s),
same-exit failover/recovery/dual-down с коррелированными application/core/socket/pcap observations, configured и
empty slots, 20 пользователей × четыре concurrent flow, bidirectional 1 MiB
на пользователя, отдельные 20 MiB, idle/reconnect/data integrity, отсутствие
relay/direct leaks, idempotence и actual prior-site/profile/ACL restoration
с текущим независимым revocation overlay. Public-safe report:
`artifacts/active-probing/profiles-runtime.json` (ignored); latency/throughput
вычисляются по реальным передачам. Raw captures/configs/keys удаляются.

Fresh replay без TLS Finished/VLESS может получить ответ и характерный timing.
`maxTimeDiff` — time budget, **не полный replay cache** и не обещание отсутствия
blacklisting. Отдельный generated uTLS Firefox helper сохраняет exact Hello и
необходимые ephemeral X25519/ML-KEM secrets только в guarded временных `0600`
файлах под настоящим `0700` каталогом. Replay создаёт новую uTLS connection
через публичные parser/key-share APIs: нет unsafe-копирования TLS state,
самодельного TLS decryptor или обхода CertificateVerify/Finished. Сначала
тот же записанный Hello обязан дать положительное REALITY authentication и
завершённый TLS; после реального ожидания 302 s он обязан дать отрицательное
REALITY authentication и проверенный chain/SAN/expiry настоящего cover origin.
Hello и TLS record SHA256 обязаны совпасть с original capture в обоих случаях.
Timeout, ошибка handshake, длина ответа или hardcoded `application_transfer`
не являются отрицательным authentication verdict. Helper не отправляет VLESS
или application payload; реальные туннели/load использует stock embedded core.
Unknown runtime результат не объявляется PASS.

## Проверки и публикация в панели

```sh
make -C ansible validate test
.venv/bin/python -m unittest discover -s ansible/roles/profiles/tests -p 'test_*.py' -v
# Затем guarded runtime entry выше; интегратор выполняет make check один раз.
```

Unit/consumer tests проверяют контракт, atomic сохранение кандидата, secret
redaction и idempotence actual playbook, но **не runtime equivalence**. Driver
явно вызывает real `xray run -test` и Node API start/health; отсутствие image,
CA, core, H2, namespace или разрешённого path — ошибка, не `skipped`/mock.

Обязательные внешние gates — принятые [PR #50](https://github.com/juvenileslave/vpn/pull/50)
(cover) и [PR #51](https://github.com/juvenileslave/vpn/pull/51) (Node), причём Node
требует [PR #49](https://github.com/juvenileslave/vpn/pull/49) с реальным source ACL.
Их реализации не копируются в profiles PR. Отсутствующий prerequisite даёт
ошибку на `accepted-runtime-role-contracts` с номером обязательного PR **до**
установки пакетов/изменения сети; прямой Python entry сохраняет этот gate в
FAIL report. Успешный offline render или сборка helper не снимают runtime gate.


Позднейшая разрешённая публикация требует coherent exit/relay Config Profiles,
действительных inbound tags, отдельного Host direct и Host на каждый fixed
relay port, одного serverName/path/fingerprint/public key/shortId/UUID набора из
того же bundle, service users с slot binding, уже применённого base ACL и
проверенного cover origin. `vpnctl` Remnawave client read-only; никаких
предполагаемых write методов renderer не вызывает. Публикация/выдача links
пользователям и production cutover здесь не выполнены.

Откат: восстановить прежние inputs/site/ACL, **наложить текущие revocations**,
сгенерировать новую consistent identity, повторить actual gates и только затем
переключить usable pointer. Нельзя копировать старый credential snapshot поверх
отдельного отзыва. Repository revert не равен host restoration. Linux guest
не заменяет разрешённый семидневный российский home/mobile pilot AC-12.
