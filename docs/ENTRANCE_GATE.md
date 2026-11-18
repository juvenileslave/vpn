# Entrance acceptance gate и план ротации входа (#74)

Документ описывает офлайн-срез задачи #74: трёхзначный gate доступности
**входа** (RU-relay), классификацию отказов и план ротации адреса входа.
Реальный VPN, публикация подписки, панель и облачная ротация в репозитории не
реализованы и не развёрнуты. Наличие этого документа и unit-тестов не является
отчётом о проверке реальных RU Wi-Fi/mobile сетей.

## 1. Задача и границы

Публикация подписки опасна, если вход недоступен из реальных сетей РФ, даже
когда probe из датацентра или из текущей сети оператора успешен. Gate отвечает
на один вопрос: **есть ли принятые ladder-наблюдения, доказывающие доступность
входа из минимум двух независимых объявленных in-country сетей**.

Gate:

- использует только уже записанные принятые `probe ladder` observations;
- не делает сетевых, DNS, provider-, panel- или publication-вызовов;
- не является второй сетевой реализацией и не заменяет ladder;
- не доказывает географию и не превращает datacenter/local probe в mobile/RU;
- не публикует подписку и не меняет профиль;
- при отсутствии доказательств возвращает `unknown`, никогда `ok`.

Реализация: `vpnctl/internal/entrance`. CLI: `vpnctl entrance ...`.
Модель ladder-этапов, identities и store — в [PROBES.md](PROBES.md) и
[STATE_STORE.md](STATE_STORE.md).

## 2. Модель доказательств

Gate принимает только **принятые** ladder-попытки:

| Условие | Требование |
| --- | --- |
| Полнота | все пять stages `tcp`, `tls`, `auth`, `transfer_small`, `throughput` записаны согласованно; после отказа downstream stages сохранены как skipped |
| Идентичность | target, family, endpoint/config/SNI identities и throughput floor совпадают с comparison plan из внешних inputs |
| Время | конец попытки и все stages внутри `evidence_window` (не больше 30 min); future/stale evidence не принимается |
| Vantage | событие принадлежит объявленной точке; `Vantage` сравнивается целиком |
| Противоречия | две свежие принятые попытки одной точки с разными outcome-подписями дают `unknown` |

Этапы проверяются теми же правилами, что и `diagnose`
(`RunReport.AcceptedStages`):

- `tcp` — literal IP/port и выбранная семья;
- `tls` — точный объявленный `server_name`, проверка сертификата выполнена в
  момент измерения; issuer/SAN facts не сохраняются в SQLite;
- `auth` — REALITY/VLESS/XHTTP handshake и маленький авторизованный ответ;
- `transfer_small` — ровно 1 MiB с exact size и SHA-256;
- `throughput` — ровно 20 MiB с exact size и SHA-256.

Неполная/непринятая *старая* попытка не перекрывает более новую принятую
попытку той же точки: решение использует самую новую принятую попытку, а
более новая неполная попытка остаётся `insufficient_evidence`. Это позволяет
границе bounded store window отбросить хвост старой попытки, не превращая
`clean` в вечный `unknown`.

В store попадают только стадии, outcome/error codes, размеры и длительности.
Адреса, SNI, URL, тела, сертификаты и credentials не сохраняются и не печатаются.
Labels (`target`, `vantage`, `network`) выводятся в text/JSON как есть, поэтому
gate отклоняет labels с точкой: IPv4-адрес или DNS-имя нельзя случайно выдать
за label. Используйте короткие имена без точек (`ru-wifi`, `ru-mobile-net`).

### RU vantage и независимость

`kind: "in_country"` — это **объявление оператора**, а не измеренная география.
Gate требует:

1. минимум две объявленные in-country точки;
2. у них разные `network` labels;
3. каждая объявленная in-country точка имеет свежее принятое non-client
   evidence в окне;
4. минимум две независимые сети имеют clean принятое evidence в окне.

Точки с `outside` и `local_dc` не считаются RU-доказательством. Две точки в
одной `network` — это одна сеть, а не два независимых наблюдения. Если clean
in-country network меньше двух, gate возвращает `unknown`, даже когда все
объявленные точки успешны.

## 3. Классификация

| Код | Класс | Смысл |
| --- | --- | --- |
| `entrance_tcp` | `entrance` | TCP connect не установлен |
| `entrance_sni` | `entrance` | TCP успешен, declared-SNI TLS не завершился (timeout/handshake/early close) |
| `entrance_certificate` | `entrance` | TLS завершился с ошибкой проверки сертификата |
| `entrance_cover` | `entrance` | verified issuer не совпал с объявленным cover identity |
| `entrance_reality` | `entrance` | TCP и TLS успешны, REALITY/VLESS/XHTTP auth или первый авторизованный запрос отказал |
| `exit_transfer` | `exit` | вход прошёл, bounded 1 MiB transfer отказал или нарушил integrity |
| `exit_throughput` | `exit` | вход и 1 MiB прошли, 20 MiB измерение отказало |
| `client_failure` | `client` | попытка отказала локально (canceled, invalid request, pinned-core/setup failure); о входе ничего не доказывает |
| `insufficient_evidence` | — (`unknown`) | нет свежего полного непротиворечивого evidence хотя бы для одной объявленной in-country точки |
| `no_ru_vantage` | — (`unknown`) | in-country точки не объявлены; local_dc/outside недостаточны |
| `independent_vantage` | — (`unknown`) | clean in-country сетей меньше двух |
| `uncorroborated_failure` | — (`unknown`) | in-country точка наблюдала отказ входа/выхода, но свежее принятое evidence есть меньше чем от двух независимых in-country сетей |
| `contradictory_evidence` | — (`unknown`) | свежие принятые попытки одной точки расходятся или датированы будущим |
| `invalid_evidence_plan` | — (`unknown`) | malformed comparison plan |

Усечение bounded store window (`scope.query_truncated=true`) не является
отдельным вердиктом: запрос возвращает самые новые ladder-строки, а окно
сравнения ограничено сверху. Отброшенные старые строки не могут добавить
свежее evidence, поэтому решение принимается по доступным новым попыткам;
если для объявленной точки свежей полной попытки нет, результат остаётся
`unknown` (`insufficient_evidence`).

Коды этапов — это наблюдаемые категории, а не доказательство конкретной
системы фильтрации. `entrance_reality` может означать и неверный
profile/key/UUID, а `entrance_certificate`/`entrance_cover` — ошибку cover или
конфигурации; в любом случае gate не публикует профиль.

Правила приоритета:

- классифицируется первый не-success stage в порядке acceptance;
- client-side код (`canceled`, `invalid_request`, `source_unavailable`,
  `xray_start_failed`, `cleanup_failed`, `run_identity_failed`,
  `profile_invalid`) не превращается в отказ входа; такой результат
  объявленной in-country точки делает gate `unknown` (`client_failure`), а не
  `clean`. Отказ pinned core/profile до первого записанного stage не создаёт
  run-строк в store, поэтому такая попытка видна как отсутствие evidence
  (`insufficient_evidence`), а не как `client_failure`;
- отказ входа одной in-country точки важнее exit-отказа другой, но сам gate
  сообщает `failed` только когда свежее принятое evidence есть минимум от двух
  независимых in-country сетей; иначе `uncorroborated_failure` / `unknown`,
  хотя per-vantage результат всё равно показывает `failure_class=entrance`;
- отказ outside-точки не блокирует clean, доказанный двумя in-country сетями,
  но сам по себе никогда не делает gate clean;
- datacenter/local успех не повышает состояние до `clean`.

## 4. Состояния gate и публикация

| State | `usable` | Публикация |
| --- | --- | --- |
| `clean` | `true` | разрешена только этим фактом, при прочих принятых проверках |
| `unknown` | `false` | закрыта/unavailable |
| `failed` | `false` | закрыта/unavailable |

`usable: true` выставляется только при `state: clean`, то есть при полном
clean evidence от минимум двух независимых in-country сетей. Любой `failed`
или `unknown` оставляет публикацию закрытой. Публикатора в репозитории нет:
будущий путь публикации обязан проверять `usable` и не имеет права трактовать
`unknown` как успех.

`scope` содержит целевой label, family, окно, объявленные vantages, список
in-country labels, число объявленных независимых in-country сетей, требуемое
число, `ru_vantage_verified` и диагностический `query_truncated`. Сколько из
них реально clean, видно из per-vantage `state` и `missing_evidence`.
`missing_evidence` содержит только authored коды и bounded labels.

## 5. CLI

```sh
vpnctl entrance gate --node NAME [--family ipv4|ipv6] \
  --inputs PATH --store PATH [--format text|json]
```

- `--inputs` — внешний приватный JSON того же формата, что у `probe ladder` и
  `diagnose`; объявленные vantages и `evidence_window` берутся из него.
- `--store` — локальная SQLite база с принятыми ladder observations.
- `--family` по умолчанию `ipv4` и никогда не переключается.
- `--format json` (или `--json`) печатает объект `gate`.
- text-вывод содержит state, usable, reason, failure class/code, scope,
  per-vantage stage facts и `missing_evidence`.

Exit codes `entrance gate`:

| Код | Смысл |
| --- | --- |
| 0 | `clean`, `usable=true` |
| 3 | `unknown`: недостаточно evidence, одна сеть, только local_dc/outside, противоречие |
| 4 | `failed`: отказ входа или выхода, подтверждённый evidence от двух независимых in-country сетей |
| 1 | ошибка inputs/store/output; не сетевой успех |
| 2 | неверные/недостающие аргументы |

Gate пишет одну marker-запись в `probes` на каждый запуск: stage
`entrance_gate`, outcome `success` только для `clean` (при этом `error_code`
пуст, как требует контракт store), иначе `failure` с reason code. Marker не
содержит ladder context и не реконструируется как ladder run; он также
исключён из ladder-window (`LatestLadderProbes`). Полный `scope`
(окно, vantages, число сетей, per-stage facts) доступен в text/JSON-выводе; в
schema 4 его нельзя сохранить отдельной scoped-записью, не смешав с ladder
evidence, поэтому persisted marker хранит только решение и label/family.
Этот PR не добавляет миграцию; текущая схема (версия 4) уже содержит таблицы
alert-воркера, а marker-записи используют существующие CHECK-констрейнты.

## 6. План ротации входа

```sh
vpnctl entrance rotation plan --node NAME --provider hetzner|cloudflare \
  --current LABEL --candidate LABEL [--family ipv4|ipv6] \
  --store PATH [--confirm] [--format text|json]
```

`--current` и `--candidate` — **bounded labels** вида `entrance-a`, которые
оператор сопоставляет ресурсу провайдера вне репозитория. IP-литералы, IPv6,
DNS-имена и произвольные строки отклоняются; в план и store попадают только
SHA-256 identities этих labels. Токены, provider IDs, адреса и DNS-записи не
читаются и не печатаются.

Шаги плана:

1. `preflight` (`passed`) — офлайн-проверка labels, family, provider и того,
   что current и candidate различны;
2. `readonly_verify` (`planned`) — перечисляет принятые read-only операции
   клиентов [CLOUD_CLIENTS.md](CLOUD_CLIENTS.md): `hetzner.ListServers` /
   `ListPrimaryIPs` или `cloudflare.ListZones` / `ListDNSRecords`; **не
   выполняется**, токены не читаются;
3. `confirmation` — без `--confirm` шаг `refused`, план `refused`;
4. `mutation` — даже с подтверждением `refused` с кодом
   `provider_write_not_implemented`: принятые клиенты предоставляют только
   GET, поэтому офлайн-срез не может безопасно изменить адрес;
5. `entrance_verify` (`manual`) — после разрешённого владельцем изменения
   провайдера оператор запускает `entrance gate` на свежих наблюдениях.

Exit codes `entrance rotation plan`:

| Код | Смысл |
| --- | --- |
| 0 | план `ready` (подтверждён), mutation всё равно не выполнена |
| 3 | план `refused` (нет подтверждения или mutation недоступна) |
| 1 | invalid request/store/output |
| 2 | неверные/недостающие аргументы |

Каждый план пишет marker `entrance_rotation_plan`: `success` для `ready`,
`failure` / `confirmation_required` для `refused`. Marker не утверждает, что
ротация выполнена.

### Rollback

Rollback описан как ручная процедура, потому что автоматической mutation нет:

1. восстановить предыдущий entrance mapping (current identity) через консоль
   или API провайдера;
2. подтвердить mapping принятым read-only клиентом;
3. запустить `entrance gate` на восстановленном mapping;
4. держать публикацию закрытой, пока gate не вернёт `clean` от двух
   независимых in-country сетей;
5. зафиксировать результат вне репозитория.

Rollback не меняет DNS, firewall или publication автоматически. Отключение
самого gate — отдельное решение владельца; оно не меняет provider IP и не
является откатом ротации.

## 7. Ручная проверка Wi-Fi/mobile

Реальные RU Wi-Fi/mobile vantage и реальная ротация в этой задаче **не
проверялись**. Никакие реальные адреса, домены, ключи и провайдерные ресурсы не
использовались. Ниже — операторская процедура, а не отчёт о её выполнении.

1. В приватном inputs-файле вне checkout (0600/0700) объявить минимум две
   фактические точки с разными `network` и `kind: "in_country"`, например
   `ru-wifi-1` / `ru-wifi-net-1` и `ru-mobile-1` / `ru-mobile-net-1`.
   Дополнительно можно объявить `outside` control; он не заменяет RU-точки.
2. Из **каждой** такой сети выполнить принятый
   `vpnctl probe ladder --vantage ИМЯ --store ...` с явным pinned core и
   внешним client JSON. Нужны полные принятые пять stages.
3. Запустить `vpnctl entrance gate` с тем же `--inputs` и `--store`.
4. Трактовать результат: `clean`/0 только при двух независимых in-country
   сетях; одна точка, только `local_dc`/`outside`, stale или противоречивое
   evidence — `unknown`/3; отказ входа даёт `failed`/4 только когда его
   подтверждают две независимые in-country сети, иначе `unknown`/3.
5. В отчётах и переписке указывать только категории, labels и exit codes, не
   адреса, SNI, UUID, токены и приватную конфигурацию.

Отсутствие evidence всегда означает `unknown`, а не `ok`. Успех из датацентра
или из текущей сети оператора не равен успеху из mobile/RU.

## 8. Ограничения и риски

- `in_country` и независимость `network` — объявления оператора; gate не
  измеряет географию и не обнаруживает две точки за одним NAT/оператором.
- Gate не хранит certificate details; TLS verification выполняется во время
  ladder, а gate использует принятые stage outcomes и opaque SNI identity.
- Marker-записи gate/rotation и Globalping HTTP-строки не входят в
  ladder-window: `ReadRuns` читает только run-scoped non-HTTP наблюдения.
  Окно ограничено `MaxLimit` (1000 ladder-строк на target); при переполнении
  отбрасываются самые старые строки, а `scope.query_truncated` становится
  диагностическим `true`. Свежие попытки по-прежнему оцениваются; если для
  объявленной точки в окне нет полной свежей попытки, результат `unknown`.
  Marker-строки больше не могут сами приблизить этот предел.
- `clean` — необходимое, но не достаточное условие публикации: exit-качество,
  панель и клиентские конфигурации проверяются отдельно.
- Ложный `clean` опубликует недоступный вход; ложный `failed` скроет здоровый
  узел. Меры: две независимые сети, явный `unknown`, запрет datacenter-only
  успеха, persisted history и ручной fallback без автопубликации.
- Gate не доказывает устойчивость к цензуре и не запускает remediation,
  ротацию, ban или изменение DNS/firewall.

## 9. Проверка

Unit-тесты используют только синтетические observations, временный SQLite и
детерминированное время; сеть, реальные адреса и provider-вызовы не нужны.
Финальные команды выполняет интегратор:

```sh
make vpnctl-test    # gofmt -l, go vet ./..., go test ./...
make vpnctl-build   # vpnctl/bin/vpnctl
make check          # публичные tracked/staged файлы
```

`make check` не заменяет CI `Secret scan` и не проверяет историю Git.
