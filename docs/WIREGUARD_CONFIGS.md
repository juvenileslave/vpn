# Конфигурации WireGuard → outbound Xray

Пакет `vpnctl/internal/upstream/wireguard` разбирает клиентский конфиг
WireGuard в формате wg-quick (INI) и строит из него outbound Xray с протоколом
`wireguard`. Это библиотека: CLI-команды для неё нет.

## Чего пакет не делает

- Не исполняет содержимое конфига: `PreUp`, `PostUp`, `PreDown`, `PostDown`
  никогда не запускаются и приводят к ошибке.
- Не вызывает `wg`/`wg-quick`, не создаёт интерфейсы, не меняет маршруты.
- Не загружает конфиги по сети, не разрешает DNS-имена endpoint и не подключается
  к VPN.

Успешный разбор означает только корректность файла. Он не доказывает, что ключи
действительны, сервер доступен или туннель заработает.

## API

```go
cfg, err := wireguard.Parse(data)        // data — содержимое .conf, не более 64 KiB
if err != nil {
	// err — wireguard.ErrorList со всеми найденными ошибками;
	// errors.Is(err, wireguard.ErrHook) и т. п. определяет вид ошибки.
}
outbound := cfg.XrayOutbound("wg-example") // типизированный outbound
data, _ := json.Marshal(outbound)          // JSON содержит секретные ключи
```

- `Config{Interface, Peers}` — нормализованная типизированная модель:
  `Key` (32 байта), `netip.Prefix`, `netip.Addr`, `Endpoint{Host, Port}`.
- `Key` при выводе через `fmt` и текстовой сериализации заменяется на
  `[redacted]`; значение возвращает только `Key.Base64()`.
- `Error{Line, Section, Key, Kind, Reason}`: номер строки, секция (`Interface`,
  `Peer N`), каноническое имя ключа и фиксированная причина. Значения, исходные
  строки и нераспознанные имена ключей в ошибки не попадают.
- Виды ошибок: `ErrSyntax`, `ErrHook`, `ErrUnsupported`, `ErrInvalid`,
  `ErrDuplicate`, `ErrMissing`.

## Поддерживаемое подмножество

Ровно одна секция `[Interface]` и одна или больше `[Peer]`. Имена секций и
ключей сравниваются без учёта регистра. Комментарий начинается с `#` в любом
месте строки; поддерживаются пустые строки, CRLF и UTF-8 BOM. Списки разделяются
запятыми; списочные ключи можно повторять, значения накапливаются.
Однозначные ключи повторять нельзя.

| Секция | Ключ | Обязателен | Проверка |
| --- | --- | --- | --- |
| Interface | `PrivateKey` | да | 44 символа канонического base64, ровно 32 байта |
| Interface | `Address` | да | IP или CIDR, IPv4 и IPv6; голый IP → `/32` или `/128`; без повторов |
| Interface | `DNS` | нет | только IP-адреса серверов |
| Interface | `MTU` | нет | 576–65535; при IPv6-адресе не меньше 1280 |
| Peer | `PublicKey` | да | как `PrivateKey`; уникален среди peer |
| Peer | `PresharedKey` | нет | как `PrivateKey` |
| Peer | `Endpoint` | да | `host:port`, IPv6 только в скобках (`[2001:db8::1]:51820`), порт 1–65535, host — IP или DNS-имя |
| Peer | `AllowedIPs` | да | IP или CIDR; одинаковый префикс у двух peer запрещён |
| Peer | `PersistentKeepalive` | нет | `off` или 0–65535 |

## Явно отклоняется

| Что | Почему |
| --- | --- |
| `PreUp`, `PostUp`, `PreDown`, `PostDown` (в любой секции и регистре) | shell-команды не исполняются (`ErrHook`) |
| `Table`, `FwMark` | управление маршрутизацией и метками хоста |
| `ListenPort` | outbound Xray не поддерживает фиксированный порт |
| `SaveConfig` | запись конфига обратно |
| поисковые домены в `DNS` | влияют на резолвер хоста; в Xray нет аналога |
| неизвестные ключи и секции (например, параметры AmneziaWG) | непонятная настройка не отбрасывается молча |
| зоны IPv6 (`%eth0`), `0.0.0.0`/`::` в endpoint, пустые значения и элементы списков | неоднозначны или зависят от хоста |

## Отображение на Xray

Схема соответствует `infra/conf/wireguard.go` в Xray-core **v26.11.9**.

| wg-quick | Xray `settings` | Примечание |
| --- | --- | --- |
| `PrivateKey` | `secretKey` | |
| `Address` | `address` | CIDR сохраняется как записан |
| `DNS` | `remoteDNS` | если DNS нет, поле опущено и Xray использует свои резолверы по умолчанию |
| `MTU` | `mtu` | если MTU нет, поле опущено (в Xray 1420); автоподбора MTU, как в wg-quick, нет |
| `PublicKey` | `peers[].publicKey` | |
| `PresharedKey` | `peers[].preSharedKey` | опускается, если не задан |
| `Endpoint` | `peers[].endpoint` | IPv6 в скобках |
| `AllowedIPs` | `peers[].allowedIPs` | выводится всегда: без поля Xray направил бы весь трафик в peer |
| `PersistentKeepalive` | `peers[].keepAlive` | 0/`off` → поле опущено |
| — | `noKernelTun: true` | всегда |

### Почему `noKernelTun: true`

На Linux Xray может поднять kernel TUN и правила маршрутизации. Несколько
экземпляров Xray (например, по одному на upstream) тогда конкурировали бы за
таблицы маршрутизации и TUN-устройства хоста. Пакет всегда выбирает userspace
TCP/IP-стек: каждый outbound изолирован и не трогает сеть хоста. Это стоит
некоторой производительности.

### Пример

Синтетические ключи; адреса из документационных диапазонов.

```ini
[Interface]
PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Address = 10.8.0.2/24, fd00:8::2/64
DNS = 192.0.2.53, 2001:db8::53
MTU = 1380

[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
PresharedKey = BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=
Endpoint = [2001:db8::10]:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

```json
{
  "tag": "wg-example",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    "address": ["10.8.0.2/24", "fd00:8::2/64"],
    "peers": [
      {
        "publicKey": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "preSharedKey": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=",
        "endpoint": "[2001:db8::10]:51820",
        "keepAlive": 25,
        "allowedIPs": ["0.0.0.0/0", "::/0"]
      }
    ],
    "mtu": 1380,
    "remoteDNS": ["192.0.2.53", "2001:db8::53"],
    "noKernelTun": true
  }
}
```

Тот же вывод проверяется тестом `ExampleConfig_XrayOutbound`.

## Ограничения

- Xray открывает UDP-сокет по endpoint первого peer; несколько peer
  выводятся как есть, но их поведение определяется Xray.
- DNS-имена в endpoint не проверяются на существование и разрешаются Xray при
  подключении.
- Сгенерированный JSON содержит приватный и preshared-ключи — храните его как
  секрет.
- Проверка `xray run -test` (если выполнялась) подтверждает только, что Xray
  принимает конфигурацию, но не работоспособность туннеля.

## Проверка

```sh
cd vpnctl
go vet ./internal/upstream/wireguard/
go test ./internal/upstream/wireguard/
```

Тесты используют только синтетические данные и не обращаются к сети.
