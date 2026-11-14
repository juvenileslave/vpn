# Планирование публикации bundle в Remnawave

Read-only часть [issue #53](https://github.com/juvenileslave/vpn/issues/53).
**Write adapter, apply и rollback не реализованы:** владелец выбрал строгую
защиту от независимого конкурентного writer. Закреплённый Remnawave 3.4.10
такую защиту не предоставляет. `apply --apply` возвращает отказ **до любого I/O**.
Эксклюзивного режима, фиктивного `If-Match`, replay POST и обхода защиты нет.
Issue #53 этим срезом не закрывается; VPN не развёрнут.

## Реальные факты закреплённой панели

Источники — [backend 3.4.10](https://github.com/remnawave/backend/tree/3.4.10),
commit `9a51c76af9e20536d3faca74cf1b938fee32ab3c`,
[контракты](https://github.com/remnawave/backend/tree/3.4.10/libs/contract/commands)
и одноразовый compose из принятой роли `remnawave_panel`. Образ проверялся как
`remnawave/backend:3.4.10@sha256:19efa7828b3a2e2c2f8f8503c175d84c9391358a6b1a5fd3b8112b8064ca6038`.
Три сервиса были `running/healthy`; API доступен через loopback TLS proxy
с отдельно сгенерированным доверенным CA, без отключения проверки TLS.
Production, публичные DNS/ACME и существующие серверы не затрагивались.

| Наблюдение | Фактический результат |
| --- | --- |
| `PATCH /api/config-profiles` с заведомо устаревшим `If-Match` | HTTP 200, профиль изменён: заголовок **не precondition**. |
| Идентичность snippet | Только `name` и `snippet`; нет UUID/revision/incarnation marker. |
| `POST /api/config-profiles` | HTTP 201; статические inbound `settings.clients` сохранены. |
| `PATCH /api/config-profiles` с `config` | HTTP 200; managed inbound `settings.clients` очищены. Это целиком replacement, не JSON merge patch. |
| Частичный `PATCH /api/hosts` | HTTP 200; неуказанные SNI/tags/viewPosition сохранены. |
| `PATCH /api/snippets` | HTTP 200; `computed-config` изменяется сразу, без sync. |
| `POST /api/snippets/actions/sync` | HTTP 202, пустое тело: очередь принята, не подтверждение node restart. |
| DELETE профиля/host/snippet | HTTP 204, пустое тело. Probe objects удалены; unrelated/default objects не менялись. |

Повторное чтение перед PATCH не атомарно и не устраняет race между read и write.
Локальная блокировка SQLite не защищает от другого клиента панели. Пока upstream
не предлагает проверяемый атомарный precondition, невозможно честно гарантировать
строгий ownership/concurrency-контракт #53. Смена закреплённого API требует отдельной
проверки метода, body, response и фактического CAS, а не только новой версии в docs.

### Настоящая модель snippets

[SnippetsService](https://github.com/remnawave/backend/blob/3.4.10/src/modules/config-profiles/snippets.service.ts)
хранит именованный **непустой массив непустых JSON objects**.
Create/update возвращают полный `{"response":{"total":N,"snippets":[...]}}`.
`DELETE /api/snippets` принимает JSON `{"name":"..."}`, а не UUID в пути.
`defaultSnippets` из схем редактора не является моделью API или скрытым источником
merge: контрольный profile с этим полем не получил его содержимое в effective config.

[replaceSnippets](https://github.com/remnawave/backend/blob/3.4.10/src/common/helpers/xray-config/xray-config.validator.ts)
и фактический `computed-config` подтвердили:

- Root `snippets: [name, ...]` добавляет только отсутствующие root keys.
  Поздняя часть snippet заменяет раннюю contribution; явные поля профиля выигрывают.
  `api`, `inbounds`, `metrics`, `snippets`, `stats` защищены от root injection.
- Placeholder `{"snippet":"name"}` разворачивается только в `outbounds`,
  `routing.rules`, `routing.balancers`. Массив вставляется на место placeholder
  с сохранением порядка. Неизвестный snippet удаляет placeholder.
- Create/PATCH/DELETE snippet не подтверждают применение на узле. Явный sync
  ставит restart всех referencing profiles в очередь.
- `GET /api/config-profiles/{uuid}/computed-config` возвращает **profile envelope**
  `{"response":{uuid,name,config,inbounds,nodes,...}}`, не голый Xray JSON.
  Это expansion snippets, не конфигурация узла после panel-user injection.

Go planner **не эмулирует merge**. Он кодирует только явно объявленные references
и сравнивает настоящий `computed-config` с исходными renderer arrays. Изменение
snippet, используемого необъявленным профилем, — conflict.

## CLI и входы

```sh
vpnctl panel --config /outside/vpnctl.yaml \
  --bundle /outside/profiles/versions/BUNDLE_ID/manifest.json \
  --objects /outside/panel-objects.json

vpnctl panel show --config /outside/vpnctl.yaml \
  --bundle /outside/profiles/versions/BUNDLE_ID/manifest.json \
  --objects /outside/panel-objects.json

# Это тоже только plan, без mutating requests:
vpnctl panel apply --config /outside/vpnctl.yaml \
  --bundle /outside/profiles/versions/BUNDLE_ID/manifest.json \
  --objects /outside/panel-objects.json

# Строгий отказ, exit 3; файлы, env, SQLite и сеть не читаются:
vpnctl panel apply --apply
```

Config — существующая строгая схема [vpnctl](../vpnctl/README.md), без новых
секретных полей. Токен берётся **только** из переменной, названной `panel.token_env`.
Для разрешённой private-CA панели можно добавить `--ca-file /outside/ca.pem`:
доверие дополняет system roots; `InsecureSkipVerify` отсутствует. HTTPS обязателен,
все redirects запрещены, request timeout — 15 s, `SIGINT`/`SIGTERM` отменяют reads.

`--bundle` указывает существующий `manifest.json` роли [profiles](PROFILES.md).
Loader не рендерит ничего: проверяет strict schema, pins, фиксированную
host/SNI/XHTTP/REALITY-политику, каждое объявленное immutable JSON file и точный
renderer `bundle_id`. Hash включает `inputs.private.json`; его содержимое не
возвращается и не сохраняется. File symlinks и escaping paths отвергаются.
Лимиты: 16 МиБ на JSON file/HTTP response, 64 МиБ на bundle, глубина JSON 128.
Проверка identity **не runtime gate**: manifest остаётся
`candidate-not-runtime-validated`, без fabricated receipt/current.

`--objects` — отдельная несекретная strict declaration, не второй renderer:

```json
{
  "schema": 1,
  "profiles": [
    {"name": "owned-exit", "role": "exit", "snippets": ["owned-egress"]}
  ],
  "snippets": [
    {"name": "owned-egress", "role": "exit", "field": "outbounds"}
  ],
  "hosts": [
    {"name": "owned-direct", "profile": "owned-exit", "inbound": "direct-v4", "family": "ipv4"}
  ]
}
```

Для **существующих** profiles и hosts обязательно добавьте точный `uuid` к
соответствующему `name`. Без UUID declaration означает создание, **не adoption**:
существующее совпавшее имя вызывает conflict. Snippets идентифицируются точным name.
Разрешены только роли `exit|relay`, snippet fields `outbounds|routing.rules|routing.balancers`,
public inbounds `direct-v4/v6` и `slot-N-v4/v6`; transit Host запрещён.
`family` должен совпадать с inbound suffix. UUID и names не печатаются из
необъявленных объектов. Duplicate keys/names/UUIDs, неизвестные declaration fields,
неверные references и stale UUID отвергаются.

Host address/port берутся из bundle и выбранного inbound, `sni` и `host` — из
единственного `reality_sni`, path — из XHTTP, fingerprint — `firefox`.
Нельзя независимо задать foreign hostname/SNI, склонировать или пересортировать
hosts. IPv4/IPv6 aliases одного объявленного public listener допустимы только
как отдельные явные declarations; duplicate address+port и конфликтующие
hostname+port bindings отвергаются.

## Diff, ownership и unknown fields

Output — стабильный JSON с `mode`, opaque `bundle_id`, `atomic_writes:false`
и объявленными `kind/name/uuid/action`. Поля содержат **только фиксированные paths**
и `equal|drift|missing`; `show` выводит только фактическое наличие current fields.
Токен, клиентские UUID, ключи, full config/snippet и response bodies не выводятся.
Canonical JSON сравнивает порядок object keys и точные decimal numbers,
сохраняет значимый порядок arrays; duplicate keys отвергаются.

Planner читает collections и отдельные managed objects, проверяет identity и
обнаруживаемый drift между reads. Это **наблюдение, не atomic snapshot**.
Unknown panel-side поля сохраняются в памяти; их значения не печатаются.
Проспективный full profile replacement, теряющий поля либо static clients,
показывает безопасный diff и возвращает `ErrLossyUpdate` до записи.
Даже `unchanged` не разрешает writes и не доказывает работу узла.

| Exit code | Значение |
| --- | --- |
| 0 | Успешный read-only plan/show; diff может содержать изменения. |
| 1 | Неверный bundle/config/declaration/CA, token/TLS/HTTP/response/cancel ошибка. |
| 2 | Неверная команда, flags или недостающие обязательные paths. |
| 3 | Явный apply, ownership/current-state conflict либо потенциально lossy update. |

Library errors — `ErrInvalidInput`, `ErrConflict`, `ErrLossyUpdate`,
`ErrUnsupportedAtomicWrite`; сравнивать через `errors.Is`/`errors.As`.
Raw transport/parser errors остаются в error chain, но форматируются без тела/URL.
Старые read методы users/nodes и их redaction сохранены.

## Проверка и оставшиеся acceptance gates

```sh
make vpnctl-test
make check
```

HTTP tests — локальные TLS fake servers с временными credentials: exact GET
method/path/query/headers/body, envelopes, unknown fields, duplicates, redirects,
response limits, malformed JSON, 401/403/404/409/429/5xx, timeout/cancel и redaction.
Consumer tests проверяют canonical diff, ownership/shared snippets/hosts,
immutable bundle tampering, lossy refusal и pre-I/O apply refusal.

Node к этому одноразовому panel probe **не подключался**. Sync acceptance не
доказывает node restart, user injection, работу relay или доступность VPN.
Write idempotency, ambiguous write resolution, SQLite apply records, rollback
с текущим revocation overlay и end-to-end публикация bundle остаются **заблокированы**.
Пользовательские credentials/CRUD, renderer и inventory здесь не меняются.

Интеграционный smoke выполнен с собранным `vpnctl` и результатом **настоящего**
playbook `profiles.yml`: stable unchanged default/explicit plan, show, implicit
apply, настоящий computed snippet drift, lossy refusal и explicit pre-I/O
refusal — PASS. CLI отправил **54 GET и 0 mutating requests**. Все три сервиса
стенда были healthy; удаление owned compose resources и private inputs — PASS.

Откат этого read-only среза — отдельный revert-PR squash-коммита. Он не изменяет
состояние панели. Будущий panel write потребует собственного retained-payload
rollback; нельзя восстанавливать отозванные credentials из старого bundle.
