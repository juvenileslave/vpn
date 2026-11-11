# Клиент Globalping

Пакет `vpnctl/internal/globalping` — часть задачи 8.3 из
[архитектурного плана](ARCHITECTURE_PLAN.md): внешние HTTP-пробы с российских
точек через [Globalping](https://globalping.io). Это только библиотечный клиент:
CLI, конфигурация, расписание и бот его пока не вызывают, поэтому `vpnctl` по-прежнему
не открывает сетевых соединений.

Контракт сверен с официальной OpenAPI
`https://raw.githubusercontent.com/jsdelivr/globalping/master/public/v1/spec.yaml`:
`info.version` 1.0.0, последний коммит каталога `public/v1` —
`7b28a4fc9d94380f3be828b056288668efb9abd7` (2026-10-28).

## Что делает

| Метод | Запрос | Успех |
| --- | --- | --- |
| `CreateHTTPMeasurement` | `POST /v1/measurements` | только `202` с заголовком `Location`, `id` и `probesCount` |
| `Measurement` | `GET /v1/measurements/{id}` | `200`, один запрос |
| `WaitMeasurement` | повторяет `Measurement`, пока статус `in-progress` | первый финальный статус |

Тело создания: `type: http`, `target`, `locations: [{"country": "RU"}]`, `limit`
и `measurementOptions` (`protocol`, `port`, `ipVersion`, `request.method|path|query|host`).
Пустые поля не отправляются, API подставляет свои значения по умолчанию
(`HTTPS`, `HEAD`, порт 443/80). `target` — только имя хоста или IP-адрес без схемы,
порта и пути; `ipVersion` допустим только для имени хоста.

`Location` должен указывать на тот же origin и путь
`<base>/v1/measurements/<id>` с тем же `id`, что и тело ответа; иначе ответ
считается некорректным. Последующие запросы строятся из настроенного base URL,
а не из `Location`.

## Лимиты

- `limit` — от 1 до 500; без токена API принимает не больше 50 проб.
  По данным спецификации: без токена 250 бесплатных тестов в час, с токеном 500
  и дополнительные кредиты. Значения меняются на стороне API; клиент их не
  кеширует.
- Заголовки `X-RateLimit-*`, `X-Credits-*`, `X-Request-Cost` разбираются в
  `RateLimit` (`-1`, если заголовка нет); у `429` также `Retry-After`.
- Тело ответа ограничено: 64 КиБ для создания и ошибок, 32 МиБ для результата
  измерения (до 500 проб с сырыми данными). Превышение — `ErrResponseTooLarge`.

## Авторизация

Токен необязателен и передаётся как `Authorization: Bearer <token>` только на
настроенный base URL. Токен не хранится в конфигурации репозитория и не попадает
в сообщения об ошибках или `fmt`-вывод клиента. Откуда его брать, решит будущий
вызывающий код (по аналогии с `panel.token_env` — из переменной окружения).

Защита от утечки:

- base URL — только `https`, без userinfo, query и fragment; префикс пути сохраняется;
- редиректы не выполняются: любой `3xx` — ошибка `ErrRedirect`;
- `http.Transport` с `InsecureSkipVerify` отклоняется конструктором;
- обязательный `User-Agent` идентифицирует клиента, как просит API.

## Опрос

После каждого ответа со статусом `in-progress` клиент ждёт `PollInterval`
(по умолчанию и минимум 500 мс), поэтому получается не больше двух запросов в
секунду, как требует API. Опрос прекращается при любом финальном статусе
(в том числе неизвестном), первой ошибке, отмене контекста или по истечении
`MaxWait` (по умолчанию 1 минута; ошибка `ErrStillInProgress`). Автоматических
повторов нет: `429`, `5xx` и сетевые ошибки сразу возвращаются вызывающему.

## Результат

`Measurement` содержит `ID`, `Target`, `Status`, `CreatedAt`, `UpdatedAt`,
`ProbesCount` и `Results`. Каждый результат:

- `Probe` — `Continent`, `Region`, `Country`, `State`, `City`, `ASN`, `Network`,
  координаты и `Tags`;
- `HTTP` — `Status` (`finished`, `failed`, `offline`, `in-progress`),
  `FailureSource` для `failed`; для `finished` также `StatusCode`,
  `StatusCodeName`, `ResolvedAddress`, `Truncated`, `Timings`
  (`Total`, `DNS`, `TCP`, `TLS`, `FirstByte`, `Download`; `DNS`/`TLS` — `nil`,
  если фаза не выполнялась) и `TLS` (протокол, шифр, `Authorized`, причина
  отказа, срок действия, subject/issuer, тип и размер ключа, серийный номер,
  SHA-256 отпечаток).

`rawOutput`, `rawHeaders`, `rawBody`, `headers` и `publicKey` в модель не
попадают. Неизвестные поля JSON игнорируются; неверный, обрезанный JSON, лишние
данные после него и отсутствие обязательных полей — `ErrMalformedResponse`.

## Ошибки

| Ситуация | Проверка |
| --- | --- |
| 400 / 403 / 404 / 422 / 429 / 5xx | `errors.Is(err, ErrBadRequest / ErrForbidden / ErrNotFound / ErrNoProbes / ErrRateLimited / ErrServer)` |
| другой неожиданный статус | `ErrUnexpectedStatus` |
| детали ответа | `errors.As(err, *APIError)`: `StatusCode`, `Type`, `RateLimit`, `RetryAfter` |
| редирект | `ErrRedirect` |
| некорректный ответ | `ErrMalformedResponse`, `ErrResponseTooLarge` |
| отмена или дедлайн | `context.Canceled`, `context.DeadlineExceeded` |
| неверная конфигурация или запрос | `ErrInvalidConfig`, `ErrInvalidRequest` (запрос не отправляется) |

`APIError` хранит только статус и машинный `error.type` (короткий
идентификатор, иначе пусто); `error.message` и `params` отбрасываются, так как
могут повторять данные запроса.

## Проверка

```sh
cd vpnctl
go vet ./internal/globalping
go test ./internal/globalping
```

Тесты используют только `httptest` с TLS: создание и опрос, проваленная проба,
коды ошибок, некорректный JSON, отсутствующий `Location`, отмена, отказ от
редиректа и отсутствие токена в ошибках. Тесты не обращаются к
`api.globalping.io` и не требуют токена.

## Вне задачи

- адаптер check-host и TCP-пробы задачи 8.3;
- классификатор причины (8.4), сверка с реестром (8.5);
- хранение результатов, расписание, метрики, алерты и команды бота;
- подключение клиента к CLI и конфигурации `vpnctl`.
