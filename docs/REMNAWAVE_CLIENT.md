# Клиент API Remnawave (только чтение)

Пакет `vpnctl/internal/remnawave` — библиотечный Go-клиент панели Remnawave для
чтения пользователей, узлов, config profiles, computed-config, именованных
snippets и hosts. Команды `vpnctl panel plan/show` используют только чтение;
условия STRICT и границы apply описаны в [PANEL_WRITE.md](PANEL_WRITE.md).

## Чего клиент не делает

- Нет методов создания, изменения и удаления: только девять GET-запросов ниже.
- Нет экспортированного универсального метода HTTP-запроса.
- Нет автоматических повторов. `429` и `5xx` возвращаются вызывающему коду.
- Нет логирования. Токен не читается из окружения или файлов: его передаёт
  вызывающий код.
- Конструктор не открывает сетевых соединений.
- Отключить проверку TLS-сертификата нельзя.

## Источник API

Контракт сверен с официальной спецификацией OpenAPI Remnawave:

| Параметр | Значение |
| --- | --- |
| Спецификация | `https://cdn.docs.rw/docs/openapi.json` (ссылка «API Specification» на docs.rw) |
| `info.version` | `3.4.10`, OpenAPI `3.0.0` |
| Исходники | `remnawave/backend`, тег `3.4.10` (`9a51c76af9e20536d3faca74cf1b938fee32ab3c`), `libs/contract` |
| Дата сверки | 2026-11-10 |

Аутентификация — схема `Authorization` (`http`, `bearer`): заголовок
`Authorization: Bearer <токен>`.

## Соответствие методов и эндпоинтов

| Метод | Запрос | Конверт ответа |
| --- | --- | --- |
| `ListUsers(ctx, start, size)` | `GET /api/users?start=&size=` | `{"response": {"users": [...], "total": N}}` |
| `User(ctx, id)` | `GET /api/users/{userId}` | `{"response": {...}}` |
| `ListNodes(ctx)` | `GET /api/nodes` | `{"response": [...]}` |
| `ListConfigProfiles(ctx)` | `GET /api/config-profiles` | `{"response":{"total":N,"configProfiles":[...]}}` |
| `ConfigProfile(ctx, uuid)` | `GET /api/config-profiles/{uuid}` | `{"response":ConfigProfile}` |
| `ComputedConfigProfile(ctx, uuid)` | `GET /api/config-profiles/{uuid}/computed-config` | `{"response":ConfigProfile}` |
| `ListSnippets(ctx)` | `GET /api/snippets` | `{"response":{"total":N,"snippets":[...]}}` |
| `ListHosts(ctx)` | `GET /api/hosts` | `{"response":[Host,...]}` |
| `Host(ctx, uuid)` | `GET /api/hosts/{uuid}` | `{"response":Host}` |

- Пагинация по смещению: `start` — смещение с нуля, `size` — от 1 до 1000
  (ограничения спецификации). Неверные значения отклоняются до запроса
  (`ErrInvalidArgument`). `total` — общее число пользователей; пустая страница
  возвращает пустой (не `nil`) срез. Перебор: увеличивайте `start` на `size`,
  пока страница не станет пустой или `start` не достигнет `total`.
- **Отличие от формулировки issue #6.** В API 3.4.10 `GET /api/users/{userId}`
  принимает положительный **числовой** `id` пользователя, а у пользователя нет
  поля `uuid`. Поэтому метод называется `User(ctx, id int64)`. Поиск по
  `shortUuid` и `username` не реализован: `shortUuid` входит в ссылку подписки.
- Остальные эндпоинты не реализованы.
- Шесть новых методов не используют query, тело запроса или пагинацию.
  `total` у profiles/snippets обязан совпадать с длиной полной коллекции.
  Пустые коллекции возвращаются непустым по типу, но пустым по длине срезом
  (`[]`, не `nil`). Дубликаты UUID (включая различие только регистра), имён
  profiles/snippets и UUID/tag inbounds отклоняются как malformed response.
- UUID проверяется до HTTP-запроса; одиночный ответ обязан содержать
  запрошенную идентичность. Inbound профиля обязан ссылаться на этот профиль.
- `computed-config` возвращает **конверт профиля**, а не голый Xray config.
  Snippets раскрывает сама панель; клиент не имитирует её алгоритм.
  Это не отдельная конфигурация узла с пользовательской инъекцией панели.

## Использование

```go
hc := &http.Client{Timeout: 15 * time.Second}
client, err := remnawave.New(cfg.Panel.URL, token, hc)
if err != nil {
	return err
}
ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
defer cancel()
page, err := client.ListUsers(ctx, 0, 100)
```

`New(baseURL *url.URL, token string, httpClient *http.Client, opts ...Option)`:

- `baseURL` — абсолютный `https`-URL с хостом, без userinfo, query и fragment.
  Путь сохраняется как префикс: для `https://host/panel` запрос пойдёт на
  `https://host/panel/api/users` (панель за reverse proxy).
- `token` — непустой, без пробелов и управляющих символов.
- `httpClient` обязателен. Клиент копируется, вызывающий объект не меняется.
  В копии редиректы запрещены. `*http.Transport` с `InsecureSkipVerify`
  отклоняется (`ErrInvalidConfig`).
- `WithMaxResponseBytes(n)` меняет лимит тела успешного ответа (по умолчанию
  16 МиБ).

`fmt` с `%v`, `%+v` и `%#v` не печатает токен клиента.

## Модели

Существующие безопасные модели пользователей и узлов не изменены:

- `User`: `ID`, `Username`, `Status` (`UserStatus`: `ACTIVE`, `DISABLED`,
  `LIMITED`, `EXPIRED`; неизвестные будущие значения сохраняются, `Known()`
  возвращает `false`), `ExpireAt`, `Usage` (`UsedBytes`, `LifetimeUsedBytes`,
  `LimitBytes` = `trafficLimitBytes` панели), `OnlineAt` и `FirstConnectedAt`
  (`nil`, если `null` или поле отсутствует).
- `UsersPage`: `Users`, `Total`.
- `Node`: `UUID`, `Name`, `CountryCode`, `Status` (`NodeStatus`, выводится из
  флагов в порядке приоритета: `disabled` → `connecting` → `connected` →
  `disconnected`), `UsersOnline`, `Usage` (`UsedBytes`, `LimitBytes` —
  указатели, `nil` при `null`), `LastStatusChange`.

Для `User`/`Node` намеренно **не** декодируются: `trojanPassword`, `ssPassword`,
`vlessUuid`, `shortUuid`, `subscriptionUrl`, email, Telegram ID; у узлов —
`address`, `proxyUrl`, `lastStatusMessage`. Их сырые ответы не сохраняются,
неизвестные поля игнорируются как прежде.

Новые модели для планирования:

- `ConfigProfile`: `UUID`, `Name`, `Config json.RawMessage`,
  `Inbounds []ConfigProfileInbound`, `Fields map[string]json.RawMessage`.
- `ConfigProfileInbound`: `UUID`, `ProfileUUID`, `Tag`, `Fields`.
- `Snippet`: `Name`, `Snippet json.RawMessage`, `Fields`. В API 3.4.10 нет
  UUID, revision, timestamp или маркера инкарнации snippet.
- `Host`: `UUID`, `Remark`, `Inbound HostInbound`, `Fields`.
- `HostInbound`: `ConfigProfileUUID`, `ConfigProfileInboundUUID`, `Fields`.
  Nullable UUID панели представлены пустыми строками; исходные `null`
  остаются в `Fields`, выдуманных ссылок нет.

`Fields` сохраняет **все** исходные поля, включая неизвестные и вложенные.
`Config` сохраняет исходный Xray объект, в том числе static clients; snippet —
непустой массив непустых объектов. Это приватные данные **в памяти**, которые
могут содержать credentials. Нельзя отдельно выводить `Config`, `Snippet` или
`Fields`. `fmt` (`%v`, `%+v`, `%#v`) и `json.Marshal` самих новых моделей,
указателей, срезов и контейнеров этих моделей всегда скрывают содержимое и
идентичности; JSON модели — `{"redacted":true}`.

Новые ответы проходят строгую проверку одного JSON-значения, обязательного
конверта, точного регистра полей, обязательных полей и типов, UUID, времени,
коллекций и повторяющихся ключей **на любой глубине**, включая opaque configs
и неизвестные поля. Парсер не повторяет тело или произвольное имя ключа в ошибке.

## Ограничения и безопасность

- Каждый запрос выполняется с переданным `ctx`; отмена и deadline прерывают
  ожидание и чтение тела (`errors.Is(err, context.Canceled)` или
  `context.DeadlineExceeded`). `Timeout` переданного `http.Client` тоже действует.
- Тело успешного ответа ограничено (`ErrResponseTooLarge`) и по
  `Content-Length`, и при фактическом чтении. Из тела ошибки читается не более
  64 КиБ. Тело всегда закрывается.
- Любой ответ `3xx` возвращается как `ErrRedirect` без перехода: токен не
  уходит на другой адрес, `Location` в ошибку не попадает.
- Ошибки транспорта не повторяют URL запроса.

## Ошибки

Сравнивайте через `errors.Is` / `errors.As`:

| Ошибка | Когда |
| --- | --- |
| `ErrInvalidConfig` | Неверные аргументы `New` или опции. |
| `ErrInvalidArgument` | Неверные `start`, `size`, `id`, UUID или `nil` context; запрос не отправляется. |
| `ErrMalformedResponse` | Не JSON, обрезанный или лишний JSON, не тот конверт, нет обязательных полей, неверные типы, UUID или время, `Content-Type` не `application/json`; для новых моделей — duplicate keys/identities и несогласованный `total`. |
| `ErrResponseTooLarge` | Тело больше лимита. |
| `*APIError` | Ответ не `2xx`: `StatusCode`, `Code` (`errorCode` панели вида `A025`, если корректен), `RetryAfter` для `429`. |

`*APIError` разворачивается в sentinel: `3xx` → `ErrRedirect`, `400` →
`ErrBadRequest`, `401` → `ErrUnauthorized`, `403` → `ErrForbidden`, `404` →
`ErrNotFound`, `429` → `ErrRateLimited`, `5xx` → `ErrServer`, остальное →
`ErrUnexpectedStatus`. Сообщение (`message`) и тело ответа в ошибку не
копируются, заголовок `Authorization` — тоже.

Ошибки транспорта и чтения тела не печатают исходный текст, URL или тело;
цепочка причин для `errors.Is`/`errors.As`, отмены, deadline и timeout сохранена.

## STRICT: запись намеренно недоступна

Владелец выбрал защиту от **независимых writers**, а не эксклюзивное владение.
На disposable панели pinned 3.4.10 устаревший `If-Match` не предотвратил PATCH:
панель приняла изменение с HTTP 200. Атомарного API precondition нет;
повторное чтение перед записью не заменяет CAS. Поэтому клиент не содержит
mutating методов, а явный apply отказывается **до** токена, сети и состояния.
Нет обхода `--exclusive`, фиктивного CAS, журнала apply или rollback.

Дополнительно full profile PATCH очищает managed inbound static clients,
хотя POST сохраняет их. Сохранение raw config при чтении не разрешает такой
lossy update. Доставка на реальные nodes и user injection не подтверждены.
Read-only срез не завершает write adapter и **не закрывает issue #53**.

## Проверка

Тесты используют локальные `httptest` TLS-серверы с доверенным тестовым
сертификатом. Новые тесты генерируют временные токены и UUID. Реальная панель
и credentials не нужны; внешней сети в тестах нет.

```sh
cd vpnctl
go test ./internal/remnawave
go vet ./internal/remnawave
```

Покрыто: перебор страниц и `total`, пустая страница, `null`/отсутствующие
временные метки, лишние поля, некорректные и обрезанные ответы,
`400/401/403/404/409/429/5xx`, лимит тела (с `Content-Length` и chunked), отмена и
deadline, отказ от редиректа (цель редиректа не получает запросов), отказ от
недоверенного сертификата и от `InsecureSkipVerify`, отсутствие токена и
секретных полей в моделях и ошибках.

Новые synthetic тесты проверяют все шесть method/path/query/header/body
контрактов, raw/unknown поля в памяти и redaction моделей/контейнеров;
mandatory fields, неверные envelopes, UUID, duplicate keys/identities,
несогласованный `total`, malformed/trailing JSON, HTTP errors, oversized
Content-Length/chunked ответы, отмену/deadline/client timeout до и после
заголовков, безопасные transport/body errors с сохранённой цепочкой причин.

Формы ответов и ограничения записи сверены с pinned исходниками и реальной
disposable панелью 3.4.10 за доверенным TLS proxy. Probe-объекты удалены.
К ней не был подключён Node: HTTP readback и принятие очереди не доказывают
эффективную конфигурацию узлов, refresh или пользовательскую инъекцию.
