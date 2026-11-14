# Сетевые пробы `vpnctl/internal/probe`

Пакет `github.com/juvenileslave/vpn/vpnctl/internal/probe` сохраняет принятые
TCP-connect, verified TLS и bounded HTTP primitives из пункта 8.2
[архитектурного плана](ARCHITECTURE_PLAN.md). Они используют стандартную
библиотеку Go и остаются единственной сетевой реализацией probe.

`vpnctl probe ladder` оркестрирует эти primitives и отдельный **явно указанный**
pinned Xray для REALITY/VLESS/XHTTP; `vpnctl diagnose` классифицирует scoped
observations из принятого [store](STATE_STORE.md). Планировщика, mTLS probe-agent,
автоматической remediation, ban/rotation и доказательства конкретной системы
цензуры нет. `config validate` остаётся полностью offline.

## API

| Функция | Этапы | Запрос |
| --- | --- | --- |
| `TCP(ctx, TCPRequest)` | `tcp` | `Target` |
| `TLS(ctx, TLSRequest)` | `tcp` → `tls` | `Target`, `ServerName`, `RootCAs` |
| `HTTP(ctx, HTTPRequest)` | `tcp` → (`tls` для `https`) → `http` | `Target`, `URL`, `ServerName`, `RootCAs`, `MaxBytes`, `MaxHeaderBytes` |

Общая часть запроса — `Target`:

- `Address` — IP-литерал (`netip.Addr`) выбранного семейства, без zone. DNS не
  используется: ответ резолвера — отдельное наблюдение, которое может само быть
  искажено.
- `Port` — 1–65535.
- `Family` — `ipv4` или `ipv6`; соединение открывается через `tcp4` или `tcp6`
  соответственно. IPv6-адрес для `ipv4`, IPv4 или IPv4-mapped (`::ffff:a.b.c.d`)
  адрес для `ipv6` отклоняются до обращения к сети. Перехода на другое семейство
  нет.
- `Timeout` — обязательный общий предел всей пробы (все этапы вместе); более
  ранний deadline контекста имеет приоритет.
- `SourceIP` — необязательный локальный адрес того же семейства, к которому
  привязывается сокет.

TLS: `ServerName` обязателен, отправляется как SNI и проверяется по
сертификату. `RootCAs == nil` означает системные корневые сертификаты; проверка
сертификата никогда не отключается. Минимальная версия — TLS 1.2, ALPN —
`http/1.1`.

HTTP: один `GET` по HTTP/1.1 с `Connection: close` в новом соединении к
`Target.Address`. Хост из `URL` идёт в заголовок `Host` и, для `https`, в SNI,
если `ServerName` не задан. `MaxBytes` (обязателен) ограничивает чтение тела,
`MaxHeaderBytes` — размер статусной строки и заголовков (по умолчанию 64 КиБ).
URL с userinfo отклоняется.

Промежуточные ответы 1xx (например, `103 Early Hints`) пропускаются: они
читаются тем же буферизованным читателем и в пределах того же общего лимита
`MaxHeaderBytes` и timeout, а статус и тело берутся из итогового ответа.
`101 Switching Protocols` не запрашивается пробой и даёт `http_protocol_error`.

## Результат

`Result.Observations` содержит по одному `Observation` на каждый выполненный
этап; после первого неуспешного этапа проба останавливается. Поля:

- `Stage` — `request`, `tcp`, `tls` или `http`;
- `Outcome` — категория (таблица ниже);
- `Start`, `End`, `Duration()` — время этапа;
- `LocalAddr`, `RemoteAddr` — адреса сокета, сообщённые ядром; нулевые, если
  соединение не установлено;
- `Error` — текст исходной ошибки;
- `TLSVersion` — согласованная версия TLS;
- `StatusCode`, `HeaderReceived` — статус итогового (не 1xx) ответа и момент
  получения его заголовков;
- `InterimResponses` — число промежуточных ответов 1xx перед итоговым;
- `BytesRead` — прочитано байт тела (не больше `MaxBytes`);
- `LimitReached` — прочитано `MaxBytes`, а тело не подтверждено завершённым
  (`Content-Length` больше лимита или неизвестен). Лишний байт за пределом не
  читается, поэтому остановка сервера сразу после лимита не превращает
  выполненную передачу в timeout.
- `HTTPRequest.HashBody` включает потоковую SHA-256 bounded body; по умолчанию
  payload hash не вычисляется. `SHA256` и `BodyDuration` — measured facts.
- `Certificate` содержит issuer identity (`SHA-256` DER issuer), validity window,
  `SANMatch`, `Verified` и ALPN. DNS-имена issuer/SAN и raw bytes сертификата
  не входят в эти facts. При failed verification доступные unverified facts
  остаются помечены `Verified: false`; проверка TLS не обходится.

## Что доказывает и чего не доказывает результат

| Outcome | Наблюдение | Чего это **не** доказывает |
| --- | --- | --- |
| `success` на `tcp` | TCP-рукопожатие с указанным адресом завершилось. | Что там нужный сервис, что работает VPN, что следующие этапы пройдут. |
| `success` на `tls` | Цепочка сертификата проверена для `ServerName` от заданных корней. | Работоспособность REALITY/VLESS и вообще VPN: REALITY здесь не проверяется. |
| `success` на `http` | Получен 2xx и прочитано `BytesRead` байт (или тело завершилось раньше). | Пропускную способность канала или доступность VPN; скорость не измеряется. |
| `timeout` | Истёк `Timeout` или deadline контекста. | Механизм блокировки: причиной может быть потеря пакетов, перегрузка, фильтрация или медленный сервер. |
| `canceled` | Контекст отменён вызывающим. | Ничего о сети. |
| `refused` | На попытку соединения пришёл отказ (RST). | Что RST отправил сам сервер, а не устройство на пути. |
| `source_unavailable` | `SourceIP` не удалось привязать локально; ничего не отправлено. | — |
| `network_error` | Иная ошибка сокета (например, нет маршрута). | Конкретную причину сверх текста `Error`. |
| `certificate_untrusted` | Цепочка не ведёт к доверенному корню. | Подмену сертификата: возможна и обычная ошибка конфигурации. |
| `hostname_mismatch` | Сертификат не выдан для `ServerName`. | То же. |
| `certificate_invalid` | Иная ошибка проверки (например, срок действия) либо отказ платформенного верификатора без указанной причины. | То же. |
| `handshake_failed` | Alert, сброс, не-TLS ответ или закрытие во время рукопожатия; ошибки проверки сертификата сюда не попадают. | Вмешательство DPI. |
| `http_status` | Итоговый ответ со статусом вне 2xx; редиректы не выполняются. | Недоступность ресурса по иной причине. |
| `http_protocol_error` | Ответ не разобран как HTTP, заголовки (вместе с 1xx) длиннее лимита или неожиданный `101`; обрыв внутри заголовков разбирается так же. | — |
| `early_eof` | Соединение закрыто до ответа или до конца тела, объявленного `Content-Length`/chunked. | Кто именно закрыл соединение. |
| `invalid_request` | Запрос отклонён до обращения к сети. | — |

При `RootCAs == nil` проверку выполняет платформа. На macOS (и Windows) системный
верификатор может отклонить цепочку без типизированной причины; `crypto/tls`
всё равно оборачивает такой отказ в `tls.CertificateVerificationError`, и он
классифицируется как `certificate_invalid`, а не `handshake_failed`. Поэтому для
системных корней конкретная категория (`certificate_untrusted` или
`certificate_invalid`) зависит от ОС; проверка при этом не ослабляется.

Привязка `SourceIP` задаёт только адрес источника. Она не доказывает, через
какой физический интерфейс или TUN ушёл трафик: выбор маршрута остаётся за
таблицами маршрутизации и политиками ядра, которые пакет не меняет.

## Гарантии реализации

- Одна попытка соединения на пробу: без повторов, перебора адресов, DNS,
  редиректов и повторного использования соединений.
- `http.Transport` не используется, поэтому `HTTP_PROXY`/`HTTPS_PROXY` и другие
  прокси окружения не меняют измеряемый путь (покрыто тестом). Маршруты не
  изменяются.
- Все этапы подчиняются контексту: deadline выставляется на сокет, отмена
  прерывает блокирующий ввод-вывод через `context.AfterFunc`. Других горутин
  пакет не запускает.
- Соединение закрывается при любом исходе. Тело потока читается в
  `io.Discard` порциями и не буферизуется целиком; `Body.Close` не вызывается,
  потому что он может дочитывать остаток тела без ограничения.

## Тесты

`go test ./internal/probe` (из каталога `vpnctl/`) поднимает реальные loopback
TCP-, TLS- и HTTP-серверы с сертификатами, созданными в памяти; публичная сеть
не нужна. Покрыты: успешное соединение и отказ, отмена и timeout, привязка и
недоступный `SourceIP`, выбор семейства по фактическим адресам сокета,
доверенный TLS, недоверенный CA, системные корни, несовпадение имени,
просроченный сертификат, не-TLS собеседник, не-2xx, `103 Early Hints` перед
`200`, неожиданный `101`, лимит передачи, ранний EOF для `Content-Length` и
chunked, превышение лимита заголовков (в том числе суммарно с 1xx), зависшее
тело.

Пропуск допускается только в двух случаях, причина выводится в сообщении `SKIP`:

- тест IPv6 — если `net.Listen("tcp6", "[::1]:0")` завершается ошибкой (на
  loopback нет `::1`);
- тест привязки второго loopback-адреса — если `net.Listen("tcp4",
  "127.0.0.2:0")` завершается ошибкой (на macOS/BSD псевдоним `127.0.0.2` по
  умолчанию не назначен). Привязка к `127.0.0.1` проверяется всегда.

## Relay probe ladder и `diagnose` (#55)

```sh
vpnctl probe ladder --node exit-example --family ipv4 \
  --inputs /путь/вне/checkout/probes/inputs.json \
  --store /путь/вне/checkout/probes/state.db \
  --xray /абсолютный/путь/xray --format json
vpnctl diagnose --node exit-example --family ipv4 \
  --inputs /путь/вне/checkout/probes/inputs.json \
  --store /путь/вне/checkout/probes/state.db --format text
```

`--family` по умолчанию `ipv4`, не «предпочтительное семейство». Отсутствующий
IPv6 — input error, закрытый IPv6 — собственный отказ, а не попытка IPv4.
`--vantage NAME` выбирает **фактическую** объявленную точку; без него используется
`local_vantage`. Название точки не доказывает географию: оператор отвечает за
реальную независимость `network` и смысл `in_country` / `outside` / `local_dc`.

`Family` описывает путь клиент → выбранный адрес/порт узла. Внутренняя принятая
relay → same-exit политика `v6_prefer` остаётся политикой profiles: её отдельный
IPv4 failover не доказывает end-to-end IPv6 и не смешивает IPv4/IPv6 CLI evidence.
Не добавляйте второй SNI в cover/profile для имитации недостающего контроля.

### Этапы, ограничения и успех

| Этап | Одна попытка | Условие успеха |
| --- | --- | --- |
| `tcp` | literal IP/port, только `tcp4` или `tcp6` | соединение установлено |
| `tls` | тот же сокет, точный `server_name`, certificate verification включена | SAN/chain проверены; optional issuer pin совпадает с declared cover |
| `auth` | pinned core, один SOCKS-connected HTTP(S) GET через REALITY/VLESS/XHTTP | заданное маленькое представление с exact size + SHA-256 получено; открытый SOCKS listener сам по себе не является authentication |
| `transfer_small` | один GET | ровно 1 MiB, exact `Content-Length` и SHA-256 |
| `throughput` | один GET | ровно 20 MiB, exact size + SHA-256; bytes/body duration/rate измерены |
| `control_tls` | optional, отдельный verified TLS к **тому же адресу/порту** с declared control SNI | только независимое SNI-control observation, не повтор target SNI |

После первого отказа downstream-этапы явно `skipped` / `stage_not_run`.
Ошибочные REALITY key/shortId и VLESS UUID дают `auth` failure, не TCP block;
wrong SNI/certificate дают TLS facts/error, не догадку о фильтрации. Отличие
issuer от declared cover — `cover_mismatch`, тоже не автоматический block.

Нет DNS, redirects, retries, proxy environment или переключения SNI/family в
primitives/runner. Startup pinned process подтверждается его started marker,
без повторных remote connects. Core сохраняет принятую `stream-one`/XMUX policy;
runner не обещает изменения внутренних stock-core transport defaults.

`overall` ограничивает setup и все network stages (не больше 5 min); stage budgets
обязательны и не превышают overall. Более ранний deadline побеждает. `SIGINT`,
`SIGTERM`, deadline и обычный network failure закрывают owned sockets/core.
Local store open/append/read ограничены отдельными 5 s budgets; process reap —
3 s. Это не дополнительные сетевые попытки. Cleanup failure возвращает error,
а не success. SQLite append не повторяется; partial run не пригоден для verdict.

### Внешние inputs и credentials

Inputs и принятый client JSON — regular files `0600` под каталогом `0700`,
абсолютные пути **вне любого checkout**. Symlink-file, unknown JSON fields,
trailing documents и широкие права отвергаются без echo содержимого/пути.
CA file также вне checkout; nil roots означают системное доверие, не bypass.

Полный синтетический inputs для payload pattern `bytes(range(256))` (это fixture,
не рабочий адрес или credentials):

```json
{
  "schema": 1,
  "local_vantage": "relay-dc",
  "vantages": [
    {"name": "relay-dc", "network": "lab-dc-a", "kind": "local_dc"},
    {"name": "outside-control", "network": "lab-dc-b", "kind": "outside"}
  ],
  "budgets": {
    "overall": "90s", "setup": "5s", "tcp": "2s", "tls": "3s",
    "auth": "12s", "small": "10s", "large": "30s", "control": "3s"
  },
  "throughput_floor_bytes_s": 1048576,
  "evidence_window": "10m",
  "nodes": [{
    "name": "exit-example", "ipv4": "192.0.2.10", "ipv6": "2001:db8::10",
    "port": 18443, "server_name": "cover.example.test",
    "profile_file_env": "VPNCTL_NODE_CLIENT_FILE",
    "endpoints": {
      "auth": {"address": "192.0.2.100", "port": 18081,
        "url": "http://192.0.2.100:18081/ladder/auth", "bytes": 256,
        "sha256": "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"},
      "small": {"address": "192.0.2.100", "port": 18081,
        "url": "http://192.0.2.100:18081/ladder/small", "bytes": 1048576,
        "sha256": "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83"},
      "large": {"address": "192.0.2.100", "port": 18081,
        "url": "http://192.0.2.100:18081/ladder/large", "bytes": 20971520,
        "sha256": "3568217a72eed5450d704907de96e14c75cc1b18661f38e0c9f458e462b38def"}
    }
  }]
}
```

`profile_file` и `profile_file_env` — альтернативы; второе содержит имя переменной
с **путём**, не секрет. `roots_file`, `cover_issuer_sha256` и
`control_server_name` необязательны. Auth endpoint — 1…16 KiB; small/large имеют
фиксированные 1/20 MiB; SHA-256 — 64 lowercase hex. Endpoint URL не содержит
userinfo/query/fragment; destination IP и порт явно заданы, без DNS. Все ответы
должны быть конечными представлениями: неизвестная/chunked длина на лимите не
доказывает exact size и даёт failure, без чтения лишнего байта.

Client file создаёт **единственный** [immutable profiles renderer](PROFILES.md).
Probe только декодирует принятый client shape, проверяет target/SNI/transport,
и делает приватную временную копию: новый loopback SOCKS listener, явно выбранный
literal адрес семьи, безопасный log sink. Key/shortId/UUID, fixed routing,
`firefox`, `stream-one` и padding `100-1000` не меняются. Freedom/mux/API/DNS/
observatory/log-file additions отвергаются; server bundles и panel policy не
перерисовываются. Private config `0600` под `0700` удаляется при каждом исходе;
credentials нет в argv, output или SQLite.

`--xray` (или `VPNCTL_XRAY_PATH`) — явный executable path; `xray version` должен
соответствовать принятому **26.11.9**. Во время пробы binary/image не скачивается.
Только отдельный setup disposable lab извлекает stock core из закреплённого
RemnaNode image. `VPNCTL_PROBE_INPUTS`, `VPNCTL_STATE_DB` задают defaults путей.

### Evidence, classifier и Globalping

Каждый Event содержит target label, vantage/network/kind, family, scope,
stage/outcome/error code, timestamp, bytes, expected size, duration/body duration
и budget. Report не содержит IP/SNI/URL/configs/payloads/headers/raw certs.
Issuer identity, validity, SAN match и ALPN — bounded certificate facts. В store
пишутся только метки, short codes, opaque comparison identities и числа.

`diagnose` — pure `Classify(plan, complete reports)` над окном до 30 min. Он
разрешает только comparison contract из inputs и не читает private client JSON
или CA file: классификация использует уже записанные observations, поэтому
недоступный или ротированный bundle не блокирует повторный разбор evidence.
Нельзя смешивать старый config/endpoint/SNI, разные семьи или разные logical
network labels одной сети. Partial/newer contradictory evidence, future/stale
controls, отмена, одна точка/одна network и truncated store query дают `unknown`.
Confidence supported verdict — не выше `moderate`; `scope.global` всегда false.

| Verdict | Минимальное наблюдаемое основание |
| --- | --- |
| `ip_block` | in-country TCP timeout и полный reachable outside control того же адреса/порта/семьи/контракта; не одна точка |
| `sni_filter` | TCP success, target TLS timeout/handshake failure, verified declared control SNI на том же адресе; certificate/cover mismatch не является фильтрацией |
| `dpi_stream_stall` | authenticated request и 1 MiB завершились; 20 MiB stream действительно закрылся/reset после 16…20 KiB с измеренными bytes/time; timeout на этой границе сам по себе недостаточен |
| `throttling` | все этапы/integrity успешны, measured 20 MiB rate ниже объявленного порога; нет reset evidence |
| `node_outage` | TCP/TLS reachability отказывает со **всех** declared independent точек, включая outside; живой SNI control противоречит outage |
| `unknown` | всё остальное; каждый verdict включает `confidence`, `missing_evidence`, `scope` |

Stream/throttling patterns могут возникнуть у endpoint или в сети. Они не
являются packet-level DPI proof, не называют конкретную систему и не запускают
ban/rotation/remediation. Здоровая лестница тоже не доказывает отсутствие цензуры.

`--globalping-file PATH` импортирует external private JSON
`{"measurement": <typed globalping.Measurement>, "port": N, "family": "ipv4"}`:
используется уже принятый [Globalping client/model](GLOBALPING.md), не второй
HTTP client. Только finished typed HTTP results, явно совпавший literal address/
family/port, bounded times и ASN labels. Raw output, headers, network/certificate
text, coordinates и credentials не копируются в report/store. Импорт не делает
API calls и не снимает rate limits принятого client. `external_http` не заменяет
TCP, same-address control SNI, authenticated handshake или transfer evidence.

### Коды выхода и фактическая проверка

| Код | Смысл |
| --- | --- |
| 0 | ladder: все пять этапов успешны; diagnose: supported scoped hypothesis |
| 1 | input/pinned core/store/output/private cleanup error; не успех сетевой пробы |
| 2 | неверные/недостающие CLI arguments, включая явный Xray path для ladder |
| 3 | diagnose: insufficient evidence / `unknown` |
| 4 | ladder: выполненный network/authorized/transfer stage отказал; не verdict о блокировке |

Text и JSON показывают реальные stage facts и verdict отдельно. Одиночный
успешный ladder может вернуть 0 при `diagnosis: unknown`; отказ ladder возвращает
4, даже если ещё недостаточно controls для диагноза. Никаких bot-команд нет.

Unit regressions используют pure evidence tables, реальные temporary SQLite,
in-memory TCP/TLS/HTTP pipes и принятые loopback primitives. Pinned core не
имитируется unit server. Реальный accepted #47 stack, wrong SNI/key/shortId/UUID,
exact counts/integrity, 17 KiB close, slow stream, cancellation/deadline,
IPv6-down/IPv4 isolation, outside control и stopped exit проверяет отдельный
[Relay probe ladder workflow](../.github/workflows/probe-ladder.yml):

```sh
# Только НОВЫЙ guarded GitHub-hosted Ubuntu 24.04 guest, не эта рабочая машина.
make -C ansible bootstrap
sudo env PATH="$PATH" HOME="$HOME" \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  VPN_PROFILES_DISPOSABLE_GUEST=yes \
  bash ansible/roles/profiles/tests/runtime_vm.sh probe-ladder
```

Фактический JSON `artifacts/active-probing/probe-ladder-runtime.json` получает
`result: PASS` только после behavioral gates **и** cleanup принятого lab.
Vantages в этом стенде — разные реальные synthetic namespaces, не российский
pilot и не real outside/provider measurements. Скрипт не обращается к existing
VM/panel/production, публичным DNS/ACME или owner secrets. Setup downloads public
pins отдельно; probe не скачивает binary. Исходный architecture plan не меняется.

В [PR #65](https://github.com/juvenileslave/vpn/pull/65) фактический
[hosted run 43630121210](https://github.com/juvenileslave/vpn/actions/runs/43630121210)
на commit `5a0d2a9` завершил **37 сценариев и cleanup с PASS**: real pinned
REALITY/VLESS/XHTTP, exact 1/20 MiB integrity/count receipts и SQLite round-trip,
wrong credentials без proxy access, 17 KiB close, measured slow stream,
deadline/SIGTERM, IPv4/IPv6 isolation, outside control и stopped exit.
Это bounded synthetic acceptance, не production rollout и не российский pilot.


Откат — отдельный revert PR squash-коммита без переписывания master. External
network state probes не меняют; локальные observations сохраняются. База версии
3 не downgrade автоматически: границы старого reader/backup — в
[STATE_STORE.md](STATE_STORE.md).
