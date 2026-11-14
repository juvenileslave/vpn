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
| `cover_tls_port` | отдельный порт приватного host-loopback origin; при отсутствии **9443**, явное значение проверяется |
| `reality_target` | необязательная проверка совместимости входа: только производное `127.0.0.1:<cover_tls_port>`; внешний/другой target отвергается |
| `reality_max_time_diff_ms` | положительное целое; при отсутствии **300000**, явное значение проверяется |
| `relay_egress_ipv4`, `relay_egress_ipv6` | явно объявленный фактический адрес выхода relay; валидный IP нужной семьи, нормализуемый для сравнения, без loopback/link-local/multicast/unspecified/IPv4-mapped; NAT-адрес не выводится из public IP |
| `base_firewall_vpn_ports` | публичные TCP-listeners direct/relay; не transit/API/origin |
| `base_firewall_source_ports` | transit TCP только от **точно** relay `/32` и `/128`; API TCP в точности `node_port_allow` |
| `profiles_probe_url` | явный URL HTTP(S), доступный через exit slot0; без credentials; явно заданный порт — целое 1…65535, не пустой/некорректный |
| `slot_fanout` | **явно `ports`**; `sni` отвергается, не переключается автоматически |
| `s2s_family` | `v6_prefer` для этого фиксированного профиля |
| `egress_family` | `v4_prefer`, `v6_prefer`, `v4_only` — внешний выход exit |

Defaults разрешаются один раз в общем `validate_host`, который используют
inventory и renderer. Эффективные значения входят в bundle identity; явные
per-host overrides сохраняются.

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
  WireGuard требует 32-байтовые `secretKey`/`peers[].publicKey` (hex либо
  standard/URL-safe base64), непустой список peers и точный `endpoint` с портом,
  без userinfo. Необязательный `preSharedKey` может отсутствовать или быть пустым.
  Hysteria использует pinned v2 shape: `settings.version/address/port`, TLS и
  transport `hysteria`, `hysteriaSettings.version=2` с непустым `auth`.
  Недостающие/некорректные credentials и устаревшие формы отвергаются до записи.
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

Driver и каждый child CLI сначала проверяют root/Linux/hosted-guest identity;
refusal возвращает exit 2 до чтения private input или сетевых действий. Проверка
отсутствия owned state применяется только к начальному запуску lab.
Startup-логи остаются private; публичный report содержит категории и exit codes,
не сырые diagnostics.
Этот же guard применяется к `traffic.py serve|load|transfer`, включая прямой
запуск child. Compiler/transfer stderr не входит в report: только exit code и
авторское failure constraint, без усечения или публикации raw diagnostics.
Итоговый `result: PASS` записывается и печатается **после** lab cleanup и
удаления private temporary directory; `behavioral_result` отдельно описывает
функциональные сценарии. Cleanup failure делает итоговый result `FAIL` и сохраняет
только phase/stage/type/errno и авторские constraints, без raw exception text.
Полный JSON на операцию печатается после cleanup с flush; ошибки вне этого
report отдельно дают короткий `operation: runner-error` с type/errno. Ошибка
cleanup больше не может разорвать или следовать за преждевременным PASS.
Проверка файлов использует `lstat`: только `FileNotFoundError` означает отсутствие;
permission/lookup errors не превращаются в false absence. Уникальное имя
extractor фиксируется до `docker create`, чтобы cleanup учитывал и неоднозначный
исход создания (timeout/потеря ответа) и проверял его фактическое отсутствие.
Cleanup пытается обработать все owned ресурсы даже после ошибки. Успех требует
подтверждённого отсутствия containers, tracked processes, namespace names, bridge,
owned table и файлов, а также inactive/not-found service state. Уже отсутствующий
ресурс допустим; ошибка запроса/удаления или оставшийся ресурс попадает в
`cleanup_failures`, оставляет `lab_completed: false` и запрещает итоговый PASS.
Ошибки directory removal не скрываются через `ignore_errors`.
Перед удалением private temporary directory читается `/proc/self/mountinfo`:
driver выбирает только canonical mount targets внутри собственного lab root,
декодирует kernel octal escapes и вызывает обычный `umount` от deepest targets
к родителям. Соседние каталоги и системные Docker mounts не затрагиваются;
force/lazy unmount не используется. Ошибка query/unmount или оставшийся owned
mount запрещает cleanup PASS, а temporary-directory removal остаётся отдельной
обязательной проверкой.
Перед полной проверкой wrapper отдельно проверяет cleanup частично подготовленного
стенда: реальные namespaces, pinned image, containerd и Docker daemon, без
туннелей/cover/нагрузки. Это `operation: cleanup-smoke`, не полный VPN acceptance;
report `profiles-cleanup-smoke.json` не заменяет `profiles-runtime.json`.

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

Pinned Node image попадает в приватный daemon одним `docker pull` через
локальный CONNECT-прокси на synthetic bridge в exit namespace **до** сценария: классический Docker
image store не сохраняет repo digest после `docker save`/`load`, а compose с
digest-pinned reference иначе пытался бы скачать образ без маршрута. После
pull прокси останавливается, relay по-прежнему без default route; драйвер
проверяет и публикует отсутствие default routes и точное разрешение pinned
reference.

Cover проверяет полный общий nginx config с compiled prefix: относительные
`load_module` сохраняют штатное разрешение путей. Другие nginx sites не меняются.

Cover выдаётся настоящим Certbot HTTP-01 через pinned local Pebble, без
challenge bypass; relay запускает тот же role-generated origin snapshot в
своём host network. Проверяются chain/SAN/expiry, H2, actual namespaces,
visitor TLS1.2/1.3 + H1/H2 + GET/HEAD, actual origin baseline для unknown/missing
SNI/Host/path, разрешённый direct/relay tunnel, source ACL v4/v6 и закрытые API/origin.
Report содержит 16 method/protocol cases и 144 node-attributed origin/public
baseline cases; HEAD сравнивает status/representation headers и отсутствие body.

Сеть — synthetic bridge/netns без default routes. В fixture подставляется
**конкретный geoip.dat**: документационные test endpoints исключены из PRIVATE.
Дополнительное встроенное private-IP правило stock Xray применяется после VLESS
независимо от geodata; для синтетического sink одноразовая effective-конфигурация
добавляет `allow` только к `egress-0`, TCP `192.0.2.100/32:18080-18081`.
RFC1918/ULA/link-local/loopback остаются blocked. Production routing/finalRules
не ослабляются; geodata/core SHA256 записываются. Это предел fixture, а не
доказательство всех stock reserved-IP правил production. Core не заменяется.

Для наблюдений driver добавляет **только в одноразовую effective-конфигурацию**
`log.access: /proc/1/fd/1` и указанное точечное разрешение sink. Worker stdout
перехватывается s6; init stream даёт actual access observations в `docker logs`. Immutable
`exit.json`/`relay.json` и production-конфигурация не меняются. Receipt содержит
исходный file SHA256, canonical effective-config SHA256 и точное описание обеих
дельт для каждого bundle/node; effective config отдельно проходит настоящий
`xray -test`. Проверка private-IP denial остаётся отдельным runtime gate.
Перед deny-проверкой driver подтверждает TCP-доступность RFC1918 sink из exit,
чтобы недоступная тестовая цель не могла дать ложный положительный результат.
Route gate связывает один случайный flow ID с измеренными sink bytes/SHA256,
реальными access observations `[inbound → outbound]` к application port 18080
на обоих stock cores и уникальными TCP payload sequence bytes того же
второго hop. HTTP204 observatory использует отдельный порт 18081. Победитель
должен нести ≥1 MiB в каждом направлении на socket, реально `ESTABLISHED`
и у relay, и у принимающего exit; альтернативная семья ограничена <64 KiB
probe-трафика. SYN, повторные пакеты, простое наличие адреса в pcap и один
external IP этот gate не проходят. Ограничение 64 KiB относится к доказательству
одноразового сценария, не добавляет production timeout или fallback cutoff.
Socket endpoints сравниваются как IP/port tuples: IPv4-mapped IPv6 из `ss`
нормализуется к тому же wire IPv4, без ослабления проверки адреса или порта.
После успешной передачи driver снимает завершающий `ss` snapshot обоих peers
до остановки фонового sampler: новый быстрый IPv4 fallback socket не должен
потеряться между последовательными начальными snapshots. Это реальное
наблюдение тех же IP/port tuples, не подмена отсутствующего socket предположением.
Семейство нельзя выводить из имени inbound: pinned
[`system_listener.go`](https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/system_listener.go)
передаёт wildcard `0.0.0.0` в Go `ListenConfig` с network `tcp`, который может
принимать IPv6. Реальный IPv6 flow дал `[transit-v4 -> egress-0]` на exit.
Access gate сначала считает **все** accepted records для точного application
адреса/порта и требует ровно один; затем проверяет его фактические inbound/outbound
tags. Правильный record вместе с дополнительным direct/чужим slot/egress record
не проходит. Rejected и отдельный observatory record не считаются application.
У exit допускается фактический `transit-v4` или `transit-v6`. Адресная семья
по-прежнему доказывается payload и accepted socket на обоих концах second hop,
а не именем listener. Рендер и production-конфигурация ради этого не меняются.
Граница access-log window снимается непосредственно перед текущей передачей,
после запуска capture/sampler: `time.time_ns()` передаётся в
[`docker logs --since`](https://github.com/docker/cli/blob/master/docs/reference/commandline/container_logs.md)
как Unix `seconds.nanoseconds` с девятью fractional digits. Предыдущий flow в
той же секунде не входит в окно; дополнительный accepted route внутри окна
по-прежнему приводит к отказу gate.
PCAP собирает только second-hop TCP/18444 на synthetic bridge с
`--immediate-mode -U`, snaplen 256 и буфером 32 MiB. Для sequence-byte accounting
нужны IP/TCP headers; полная payload integrity измеряется отдельно на sink.
Kernel-drop statistics записываются числами; отсутствие подтверждения zero drops
отвергает route proof.
Даже при отказе gate report хранит measured family bytes, признаки accepted
socket, fixture endpoints и все accepted application routes с whitelist tags.
Неизвестный detour учитывается, но его tags публикуются как `null`, и gate не
проходит. Raw log lines и credentials не публикуются.
Это measurements неуспешной попытки, не доказательство принятого маршрута.

Scenario включает wrong keys/shortIds/VLESS, malformed и TCP-fragmented
handshake, timestamp ±301 s, fresh/expired replay (реальный wait 302 s),
same-exit failover/recovery/dual-down с коррелированными application/core/socket/pcap observations, configured и
empty slots, 20 пользователей × четыре concurrent flow, bidirectional 1 MiB
на пользователя, отдельные 20 MiB, idle/reconnect/data integrity, отсутствие
relay/direct leaks, idempotence и actual prior-site/profile/ACL restoration
с текущим независимым revocation overlay. Public-safe report:
`artifacts/active-probing/profiles-runtime.json` (ignored); latency/throughput
вычисляются по реальным передачам. Raw captures/configs/keys удаляются.
Rollback перед публикацией restored receipt/current повторяет **авторизованные**
relay и explicit-direct transfers с клиентами restored bundle. Оба measured
flow ID/bytes/SHA256 остаются в `idempotence_rollback`; HTTPS visitor не заменяет
проверку direct tunnel. Независимый revoked relay UUID всё ещё обязан отказать.

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

Полный captured ClientHello отдельно отправляется без ephemeral keys,
TLS Finished и VLESS до и после expiry. `fresh_unauthenticated_replay` и
`expired_unauthenticated_replay` содержат точные request hashes, response
bytes/SHA256, последовательность полных TLS record types, trailing bytes,
first-response timing от записи Hello и terminal state. Наблюдение ограничено
3 s/64 KiB; EOF/deadline/read error остаются наблюдениями, не authentication
verdict. `replay_response_difference` описывает измеренные различия byte count,
first response, record types и terminal state того же Hello.
У authenticated fresh/expired uTLS controls также измеряются
`first_response_seconds`, `handshake_seconds`, `server_response_bytes`;
CertificateVerify/Finished и chain/SAN/expiry не обходятся. Raw window и
завершённый TLS имеют разные конечные milestones; это диагностика остаточного
response/timing риска, не доказательство неотличимости на ТСПУ.

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
проверенного cover origin. `vpnctl panel plan/show` читает этот bundle и
проверяет только явно объявленные profiles/snippets/hosts; renderer API не вызывает.
Запись и rollback заблокированы отсутствующим CAS в закреплённой панели
(см. [PANEL_WRITE.md](PANEL_WRITE.md)). Публикация/выдача links пользователям
и production cutover здесь не выполнены.

Откат: восстановить прежние inputs/site/ACL, **наложить текущие revocations**,
сгенерировать новую consistent identity, повторить actual gates и только затем
переключить usable pointer. Нельзя копировать старый credential snapshot поверх
отдельного отзыва. Repository revert не равен host restoration. Linux guest
не заменяет разрешённый семидневный российский home/mobile pilot AC-12.

## Потребление client bundle в probe ladder

`vpnctl probe ladder` из [PROBES.md](PROBES.md) потребляет приватный client JSON
этого renderer, а не строит второй VLESS/XHTTP/REALITY профиль. Временная копия
меняет только local listener, явно выбранный literal адрес семьи и log sink;
credentials, fingerprint, stream-one/padding, routing и server bundle immutable.
Explicit `--xray` проверяется на accepted core version; normal probe ничего не
скачивает. Никаких panel writes/rollback, новых SNI или deployment ролей нет.

Отдельный [Relay probe ladder workflow](../.github/workflows/probe-ladder.yml)
запускает `runtime_vm.sh probe-ladder` только в НОВОМ GitHub-hosted guest.
Он переиспользует accepted network/cover/base/Node/profile setup и cleanup,
после настоящего baseline запускает actual `vpnctl` text/JSON, проверяет
authorized 1/20 MiB byte/hash receipts и SQLite facts, wrong credentials,
IPv6 direct-exit listener down без family fallback, 17 KiB close, slow stream,
deadline/SIGTERM и независимые synthetic controls/outage. Client → node family
не подменяется внутренней same-exit s2s failover policy.

Это narrow acceptance probe, не повтор 5-minute replay/load/rollback matrix
полного profiles workflow. Его public report `probe-ladder-runtime.json` получает
PASS только после всех behavioral gates и удаления owned ресурсов. Synthetic
namespaces не являются реальными российскими/outside provider measurements;
production и исходный архитектурный план остаются без изменений.
