# Разбор Trojan- и Shadowsocks-ссылок и подписок

Пакеты `vpnctl/internal/upstream/trojan` и
`vpnctl/internal/upstream/shadowsocks` разбирают share-ссылки `trojan://` и
`ss://` и подписки (plain или base64) в типизированные кандидаты и строят из них
outbound-объекты Xray. Это офлайн-библиотеки: CLI-команд для них нет.

Общие примитивы (percent-decoding, проверка host/port, метка `#fragment`,
разбор query и декодирование тела подписки) вынесены во внутренний пакет
`vpnctl/internal/upstream/sharelink`. Пакет `vless` использует из него только
декодирование подписок; поведение и публичный API VLESS не изменились.

## Чего пакеты не делают

- Не скачивают подписки и не открывают сетевых соединений: на вход подаётся уже
  полученное тело подписки или отдельная ссылка.
- Не проверяют доступность серверов, не выбирают маршруты и не применяют
  конфигурацию к Xray или к системе.
- Не подменяют неподдерживаемые настройки «похожими», не понижают защиту и не
  превращают ошибочные записи в прямые (`direct`) маршруты.

Успешный разбор означает только корректность ссылки. Он не доказывает, что
пароль действителен, сервер доступен или туннель заработает.

## API

| Пакет | Функция / тип | Назначение |
| --- | --- | --- |
| `trojan` | `ParseLink(link string) (*Link, error)` | Разбор одной ссылки `trojan://`. |
| `trojan` | `ParseSubscription(data []byte) (*Subscription, error)` | Разбор тела подписки. |
| `trojan` | `(*Link).Outbound(tag string) Outbound` | Outbound Xray; сериализуется через `encoding/json`. |
| `trojan` | `Link` | `Label`, `Password`, `Address`, `Port`, `Transport`, `TLS{ServerName, ALPN}`. |
| `shadowsocks` | `ParseLink(link string) (*Link, error)` | Разбор одной ссылки `ss://`. |
| `shadowsocks` | `ParseSubscription(data []byte) (*Subscription, error)` | Разбор тела подписки. |
| `shadowsocks` | `(*Link).Outbound(tag string) Outbound` | Outbound Xray; сериализуется через `encoding/json`. |
| `shadowsocks` | `Link` | `Label`, `Address`, `Port`, `Method`, `Password`. |
| оба | `Subscription` | `Encoding` (`plain`/`base64`), `Candidates`, `Errors`. |
| оба | `Candidate` | `Entry`, `Line`, `Link`. |
| оба | `EntryError` | `Entry`, `Line`, `Err` (обычно `*FieldError`). |
| оба | `FieldError` | `Field` (`port`, `password`, `plugin`…) и `Reason`. |

`Label` — только подпись для отображения: она не попадает в сетевые настройки и
не используется как `tag`. Тег outbound задаёт вызывающий код.

`ParseSubscription` возвращает ошибку только когда непригодно всё тело:
`ErrTooLarge`, `ErrEncoding`, `ErrEmpty`, `ErrTooManyEntries`. Каждая запись —
либо `Candidate`, либо `EntryError`; записи не отбрасываются молча. Подписка,
в которой все записи ошибочны, возвращается без ошибки, с пустым `Candidates` —
решение принимает вызывающий код.

## Общие правила разбора

- Percent-encoding декодируется ровно один раз (`%2541` → `%41`); `+` остаётся
  `+`. Неэкранированные пробелы и управляющие символы в ссылке — ошибка.
- Адрес: DNS-имя (LDH, IDN только `xn--`), IPv4 или IPv6 в квадратных скобках без
  zone; имя приводится к нижнему регистру, IP — к канонической записи.
- Порт: десятичное число 1–65535 без ведущих нулей.
- `#метка`: необязательна; percent-decoding, без управляющих символов, до 256
  символов, обрезается по краям.
- Query: повторяющиеся, пустые и безымянные параметры, параметры без значения и
  неверное percent-encoding — ошибка. Известный параметр вне поддерживаемого
  сочетания сообщается отдельно, неизвестный — «unknown parameter». Ничего не
  игнорируется молча.
- Путь URI после authority не допускается ни в одной форме.

## Trojan (`trojan://`)

Поддерживается только `type=tcp` (в Xray — `network: raw`) поверх TLS. Это
единственное сочетание, которое проверено с закреплённым ядром Xray v26.11.9 в
текущем рендерере.

Outbound: `protocol: trojan`, `settings.servers[0].{address,port,password}`,
`streamSettings.network: raw`, `streamSettings.security: tls`.
`tlsSettings` добавляется только при непустых `serverName` или `alpn`; иначе Xray
использует адрес сервера как SNI.

| Параметр | Правило |
| --- | --- |
| password (userinfo) | Обязателен; percent-decoding; непустой; без управляющих символов. |
| адрес и порт | Как в общих правилах. |
| `type` | Отсутствует или `tcp`. Иное — ошибка `unsupported transport`. |
| `security` | Отсутствует или `tls`. `none` — ошибка (TLS обязателен), остальные значения — `unsupported security`. |
| `sni`, `peer` | Взаимозаменяемые алиасы `tlsSettings.serverName`: DNS-имя, приводится к нижнему регистру. Одновременное присутствие — ошибка `conflicts with sni`. |
| `alpn` | Список протоколов через запятую, без пустых элементов и повторов. |
| `allowInsecure` | `0`/`false` допускаются (ничего не меняют); `1`/`true` — ошибка: отключение проверки сертификата не поддерживается. |
| `headerType` | Допускается только `none` (ничего не меняет). |

Явно отклоняется:

| Что | Причина |
| --- | --- |
| `type=ws`, `grpc`, `h2`, `httpupgrade`, `kcp`, `quic`, `raw` и пустой `type` | Транспорт не поддержан и не проверен; псевдоним `raw` в ссылках не документирован. |
| `security=none`, `reality`, `xtls` | Trojan без TLS небезопасен; REALITY/XTLS не входят в текущее подмножество. |
| `allowInsecure=1`/`true` | Скрытое понижение защиты клиента. |
| `fp`, `pcs`, `vcn`, `ech`, `flow` | Соответствующие возможности TLS/REALITY не реализованы; параметр не игнорируется. |
| `path`, `host`, `serviceName`, `mode` | Применимы только к другим транспортам. |
| прочие параметры | `unknown parameter`. |

## Shadowsocks (`ss://`)

Поддерживаются обе формы SIP002 и устаревшая полностью base64-форма:

| Форма | Пример | Разбор |
| --- | --- | --- |
| SIP002, base64 userinfo | `ss://<base64(method:password)>@host:port#name` | base64 (standard или URL-safe, с паддингом или без) декодируется в `method:password`. |
| SIP002, percent-encoded userinfo | `ss://method:password@host:port#name` | userinfo percent-decoding, затем разделение по первому `:`. Пароль может содержать `:`. |
| legacy, полностью base64 | `ss://<base64(method:password@host:port)>#name` | Различается по отсутствию `@` вне base64; внутри обязан быть ровно один `@`. |

Outbound: `protocol: shadowsocks`,
`settings.servers[0].{address,port,method,password}`. `streamSettings` не
выводится: Shadowsocks работает поверх обычного TCP, TLS и транспортных
параметров у формата нет.

Поддерживаемые методы (имена сверяются без учёта регистра, в outbound попадает
каноническое имя Xray):

| Метод | Пароль |
| --- | --- |
| `aes-128-gcm`, `aes-256-gcm` | Непустой, без управляющих символов. |
| `chacha20-poly1305`, `chacha20-ietf-poly1305` | То же; алиас приводится к `chacha20-poly1305`. |
| `2022-blake3-aes-128-gcm` | Канонический standard base64 **с паддингом**, ровно 16 байт ключа. |
| `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` | То же, ровно 32 байта ключа. |

Для методов `2022-blake3-*` пароль с `:` (multi-key/EIH) отклоняется: текущее
подмножество поддерживает один ключ. Xray принимает и «сырой» ключ длиной 16/32
байта, но такой пароль не является переносимым и здесь отклоняется.

Явно отклоняется:

| Что | Причина |
| --- | --- |
| не-AEAD методы (`rc4-md5`, `aes-256-cfb`, `chacha20` и т. п.) | Устаревшие шифры без аутентификации. |
| `xchacha20-poly1305` и прочие методы вне таблицы | Не входят в документированное подмножество. |
| `plugin=...` (`obfs-local`, `v2ray-plugin` и др.) | Плагины не реализованы; запись не переписывается в «похожую». |
| прочие query-параметры (`uot`, …) | `unknown parameter`. |
| пустой метод, пустой пароль, отсутствие `:` | Ошибка соответствующего поля. |
| несколько `@` в userinfo или в legacy-payload | Неоднозначное разделение учётных данных и адреса. |
| путь URI, отсутствующий порт, IPv6 без скобок | Как в общих правилах. |

## Подписки

Декодирование тела общее для Trojan, Shadowsocks и VLESS
(`sharelink.Decode`) и следует принятым правилам VLESS:

- Если в теле есть `://`, оно считается plain-текстом; иначе — стандартным
  base64 (с паддингом или без, переносы строк допускаются). URL-safe base64 в
  теле подписки не поддерживается. BOM в начале отбрасывается.
- Одна запись на строку; пустые строки и строки, начинающиеся с `#`,
  пропускаются. Для base64 номера строк относятся к декодированному тексту.
- `ErrTooManyEntries` — больше 1024 непустых некомментированных строк.
- Размер тела — не более 1 MiB; размер одной ссылки — не более 16 KiB
  (`MaxLinkBytes`). Ссылка сверх предела становится `EntryError`, а не
  ошибкой всего тела.

`EntryError` содержит номер записи, номер строки и типизированную причину; он
не содержит исходную строку. Подписка без единой пригодной записи — это пустой
`Candidates` и заполненный `Errors`, а не паника и не ошибка всего тела.

## Ошибки и секреты

Ошибки имеют вид `entry 3 (line 5): password: not a padded standard base64 key of
32 bytes` или `password: missing`. Они называют запись и поле, но никогда не
содержат исходную ссылку, пароль, base64 userinfo, ключ Shadowsocks 2022 или
метку `#fragment`. Исключения — имя схемы (`unsupported scheme "vmess"`) и имена
параметров/полей.

`Link.Password` и построенный `Outbound` содержат учётные данные: не
записывайте их в логи и публичные материалы. `Link.String()` и `%#v` выводят
только схему/метод, транспорт и адрес; `String()` для Trojan —
`trojan raw+tls host:port`, для Shadowsocks — `shadowsocks <method> host:port`.

## Проверка

```sh
cd vpnctl
go vet ./internal/upstream/trojan/ ./internal/upstream/shadowsocks/
go test ./internal/upstream/trojan/ ./internal/upstream/shadowsocks/
```

Тесты используют только синтетические данные и документационные адреса
(RFC 5737, RFC 3849, `example.*`). `TestXrayConfigSmoke` в каждом пакете
загружает представительные outbound-объекты командой `xray run -test`, которая
строит конфигурацию без подключений; тест пропускается, если не задан
`VPNCTL_XRAY_BIN`:

```sh
VPNCTL_XRAY_BIN=/path/to/xray-v26.11.9 go test -run TestXrayConfigSmoke \
  ./internal/upstream/trojan/ ./internal/upstream/shadowsocks/
```

Бинарник Xray берите из официального релиза v26.11.9 с проверкой SHA-256 из
файла `.dgst`; для `Xray-macos-arm64-v8a.zip` закреплён хеш
`233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26` (см.
[PROFILES.md](PROFILES.md)).
