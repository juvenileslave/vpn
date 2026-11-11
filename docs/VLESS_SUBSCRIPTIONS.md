# Разбор VLESS-ссылок и подписок

Пакет `vpnctl/internal/upstream/vless` разбирает VLESS share-ссылки и подписки
(plain или base64) в типизированные кандидаты и строит из них outbound-объекты
Xray. Это офлайн-библиотека: CLI-команды для неё пока нет.

## Чего пакет не делает

- Не скачивает подписки и не открывает сетевых соединений: на вход подаётся уже
  полученное тело подписки или отдельная ссылка.
- Не проверяет доступность серверов, не выбирает маршруты и не применяет
  конфигурацию к Xray или к системе.
- Не подменяет неподдерживаемые настройки «похожими», не понижает защиту и не
  превращает ошибочные записи в прямые (`direct`) маршруты.

## API

| Функция / тип | Назначение |
| --- | --- |
| `ParseLink(link string) (*Link, error)` | Разбор одной ссылки `vless://`. |
| `ParseSubscription(data []byte) (*Subscription, error)` | Разбор тела подписки. |
| `(*Link).Outbound(tag string) Outbound` | Outbound Xray; сериализуется через `encoding/json`. |
| `Link` | `Label`, `ID`, `Address`, `Port`, `Encryption`, `Flow`, `Transport`, `Security`, `TLS` / `Reality`, `XHTTP`. |
| `Subscription` | `Encoding` (`plain`/`base64`), `Candidates`, `Errors`. |
| `Candidate` | `Entry`, `Line`, `Link`. |
| `EntryError` | `Entry`, `Line`, `Err` (обычно `*FieldError`). |
| `FieldError` | `Field` (`port`, `pbk`, `extra.xmux.maxConnections`…) и `Reason`. |

`Label` — только подпись для отображения: она не попадает в сетевые настройки и
не используется как `tag`. Тег outbound задаёт вызывающий код.

`ParseSubscription` возвращает ошибку только когда непригодно всё тело:
`ErrTooLarge`, `ErrEncoding`, `ErrEmpty`. Каждая запись — либо `Candidate`, либо
`EntryError`; записи не отбрасываются молча. Подписка, в которой все записи
ошибочны, возвращается без ошибки, с пустым `Candidates` — решение принимает
вызывающий код.

## Поддерживаемое подмножество

Формат ссылок — [предложение XTLS/Xray-core #716](https://github.com/XTLS/Xray-core/discussions/716);
схема outbound — Xray v26.11.9.

| `type` | `security` | Результат |
| --- | --- | --- |
| `xhttp` | `reality` | `network: xhttp`, `realitySettings`, `xhttpSettings` |
| `tcp` | `tls` | `network: raw`, `tlsSettings` |

Остальные транспорты (`ws`, `grpc`, `kcp`, `httpupgrade`, `http`…), сочетания
(`tcp`+`reality`, `xhttp`+`tls`) и `security=none` (или его отсутствие) —
ошибки. Псевдонимы, не описанные в спецификации ссылок (`type=raw`,
`type=splithttp`), не принимаются.

### Общие параметры

| Параметр | Правило |
| --- | --- |
| user ID | Обязателен; UUID `8-4-4-4-12`, приводится к нижнему регистру. |
| адрес | DNS-имя (LDH, IDN только `xn--`), IPv4 или IPv6 в квадратных скобках без zone. |
| порт | Обязателен; десятичное число 1–65535 без ведущих нулей. |
| `#метка` | Необязательна; percent-decoding, без управляющих символов, до 256 символов. |
| `type` | Обязателен: `tcp` или `xhttp`. |
| `security` | Обязателен: `tls` или `reality` (см. таблицу сочетаний). |
| `encryption` | Только `none` (по умолчанию `none`). |
| `flow` | `xtls-rprx-vision` или `xtls-rprx-vision-udp443`, только для `type=tcp`; пустое значение — без flow. Vision для XHTTP — ошибка и не добавляется автоматически. |
| `headerType` | Допускается только `none` (ничего не меняет). |
| `allowInsecure` | `0`/`false` допускаются (ничего не меняют); `1`/`true` — ошибка. |

### TLS (`security=tls`)

| Параметр | Поле Xray | Правило |
| --- | --- | --- |
| `sni` | `serverName` | DNS-имя; если не задан, Xray использует адрес сервера. |
| `fp` | `fingerprint` | По умолчанию `chrome` (по спецификации ссылок). |
| `alpn` | `alpn` | Список через запятую, без пустых и повторов. |
| `pcs` | `pinnedPeerCertSha256` | SHA-256 сертификата (hex, допускаются `:`), список через запятую. |
| `vcn` | `verifyPeerCertByName` | DNS-имена через запятую. |
| `ech` | — | Не поддерживается: ошибка. |

### REALITY (`security=reality`)

| Параметр | Поле Xray | Правило |
| --- | --- | --- |
| `sni` | `serverName` | Обязателен; DNS-имя. |
| `fp` | `fingerprint` | Обязателен. |
| `pbk` | `password` | Обязателен; base64url без паддинга, 32 байта. |
| `sid` | `shortId` | Необязателен; чётное число hex-цифр, не более 16. |
| `spx` | `spiderX` | Необязателен; начинается с `/`. |
| `pqv` | `mldsa65Verify` | Необязателен; base64url, 1952 байта. |

Допустимые `fp`: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`,
`qq`, `random`, `randomized`, `randomizednoalpn`. `unsafe` и `hellogolang`
отклоняются.

### XHTTP (`type=xhttp`)

| Параметр | Поле Xray | Правило |
| --- | --- | --- |
| `path` | `path` | Начинается с `/`; по умолчанию `/`. |
| `host` | `host` | DNS-имя или IP. |
| `mode` | `mode` | `auto` (по умолчанию), `packet-up`, `stream-up`, `stream-one`. |
| `extra` | поля `xhttpSettings` | JSON-объект, см. ниже. |

Поддерживаемые ключи `extra` (клиентская часть Xray v26.11.9): `headers`,
`xPaddingBytes`, `xPaddingObfsMode`, `xPaddingKey`, `xPaddingHeader`,
`xPaddingPlacement`, `xPaddingMethod`, `uplinkHTTPMethod`, `sessionIDPlacement`,
`sessionIDKey`, `seqPlacement`, `seqKey`, `uplinkDataPlacement`, `uplinkDataKey`,
`uplinkChunkSize`, `noGRPCHeader`, `scMaxEachPostBytes`, `scMinPostsIntervalMs`,
`xmux` (`maxConcurrency`, `maxConnections`, `cMaxReuseTimes`, `hMaxRequestTimes`,
`hMaxReusableSecs`, `hKeepAlivePeriod`). Диапазоны — неотрицательное целое или
строка `"от-до"`.

Проверки повторяют правила загрузки Xray: в `headers` нет `Host`;
`xPaddingBytes` не может быть 0; `uplinkHTTPMethod: GET` и
`uplinkDataPlacement: cookie|header` требуют `mode=packet-up`; `maxConnections`
и `maxConcurrency` в `xmux` взаимоисключающие. `xmux` необязателен и не
добавляется, если не задан.

Ошибки `extra`: повторяющиеся ключи, неверные типы, `null`, лишние данные после
объекта, неизвестные ключи; серверные ключи (`noSSEHeader`,
`scMaxBufferedPosts`, `scStreamUpServerSecs`, `serverMaxHeaderBytes`);
неподдерживаемые здесь `downloadSettings`, `h2Params`, `sessionIDTable`,
`sessionIDLength`; `host`/`path`/`mode`, отличающиеся от параметров ссылки
(совпадающие допускаются).

## Разбор и кодирование

- Percent-encoding декодируется ровно один раз (`%2541` → `%41`); `+` остаётся
  `+`. Неэкранированные пробелы и управляющие символы в ссылке — ошибка.
- Повторяющиеся, пустые и безымянные параметры — ошибка. Известный параметр вне
  выбранного сочетания — ошибка «not applicable», неизвестный — «unknown
  parameter». Ничего не игнорируется молча.
- Допускается пустой путь URI (`host:port/?…`); иной путь — ошибка.
- Подписка: если в теле есть `://`, оно считается plain; иначе — стандартным
  base64 (с паддингом или без, переносы строк допускаются). URL-safe base64 не
  поддерживается. BOM в начале отбрасывается. Пустые строки и строки,
  начинающиеся с `#`, пропускаются. Для base64 номера строк относятся к
  декодированному тексту.

## Ограничения

| Предел | Значение |
| --- | --- |
| Тело подписки | `MaxSubscriptionBytes` = 1 MiB |
| Одна ссылка | `MaxLinkBytes` = 16 KiB |
| `extra` после декодирования | `MaxExtraBytes` = 8 KiB |

## Ошибки и секреты

Ошибки имеют вид `entry 3 (line 5): pbk: not a base64url X25519 public key`.
Они называют запись и поле, но никогда не содержат исходную ссылку, user ID,
ключи, short ID или другие значения. Исключения — имя схемы
(`unsupported scheme "vmess"`), имена параметров и ключей `extra`, а также уже
проверенные значения `type`/`security` в сообщении о неподдерживаемом сочетании.
`Link.String()` и `%#v` выводят только транспорт, защиту и адрес.

`Link.ID`, `Reality.PublicKey`, `Reality.ShortID` и построенный `Outbound`
содержат учётные данные: не записывайте их в логи и публичные материалы.

## Проверка

```sh
cd vpnctl
go vet ./internal/upstream/vless/ && go test ./internal/upstream/vless/
```

Тесты используют только синтетические данные и документационные адреса
(RFC 5737, RFC 3849, `example.*`). `TestXrayConfigSmoke` загружает
представительные outbound-объекты командой `xray run -test`, которая строит
конфигурацию без подключений; тест пропускается, если не задан
`VPNCTL_XRAY_BIN`:

```sh
VPNCTL_XRAY_BIN=/path/to/xray-v26.11.9 go test -run TestXrayConfigSmoke ./internal/upstream/vless/
```

Бинарник Xray берите из официального релиза v26.11.9 с проверкой SHA-256 из
файла `.dgst`.
