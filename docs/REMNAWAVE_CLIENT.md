# Клиент API Remnawave (только чтение)

Пакет `vpnctl/internal/remnawave` — библиотечный Go-клиент панели Remnawave для
чтения состояния пользователей и узлов. Это первый ограниченный срез задачи 5.1
[архитектурного плана](ARCHITECTURE_PLAN.md). В CLI `vpnctl` клиент **не
подключён**: команды, читающие токен и обращающиеся к панели, — отдельная задача.

## Чего клиент не делает

- Нет методов создания, изменения и удаления: только три GET-запроса ниже.
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

Экспортируются только небольшие типизированные структуры:

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

Намеренно **не** декодируются: `trojanPassword`, `ssPassword`, `vlessUuid`,
`shortUuid`, `subscriptionUrl`, email, Telegram ID; у узлов — `address`,
`proxyUrl`, `lastStatusMessage`. Сырые тела ответов не сохраняются.
Неизвестные поля ответа игнорируются ради совместимости с будущими версиями.

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
| `ErrInvalidArgument` | Неверные `start`, `size`, `id` или `nil` context; запрос не отправляется. |
| `ErrMalformedResponse` | Не JSON, обрезанный или лишний JSON, не тот конверт, нет обязательных полей, неверные типы или время, `Content-Type` не `application/json`. |
| `ErrResponseTooLarge` | Тело больше лимита. |
| `*APIError` | Ответ не `2xx`: `StatusCode`, `Code` (`errorCode` панели вида `A025`, если корректен), `RetryAfter` для `429`. |

`*APIError` разворачивается в sentinel: `3xx` → `ErrRedirect`, `400` →
`ErrBadRequest`, `401` → `ErrUnauthorized`, `403` → `ErrForbidden`, `404` →
`ErrNotFound`, `429` → `ErrRateLimited`, `5xx` → `ErrServer`, остальное →
`ErrUnexpectedStatus`. Сообщение (`message`) и тело ответа в ошибку не
копируются, заголовок `Authorization` — тоже.

## Проверка

Тесты используют локальные `httptest` TLS-серверы с доверенным тестовым
сертификатом. Реальная панель и токен не нужны, внешней сети нет.

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

Проверки против реальной панели Remnawave не выполнялись.
