# Клиенты облачных API (только чтение)

Пакеты `vpnctl/internal/cloud/hetzner` и `vpnctl/internal/cloud/cloudflare`
реализуют срез задачи 9.1 архитектурного плана: чтение серверов и Primary IP
Hetzner Cloud, зон и DNS-записей Cloudflare. Это библиотечный код: CLI и
конфигурация `vpnctl` его пока не вызывают, токены нигде не читаются.

## Чего здесь нет

- Нет операций записи: создание, назначение и удаление Primary IP, poweroff и
  poweron серверов, изменение DNS-записей не реализованы. В экспортируемом API
  есть только `GET`-запросы.
- Нет конечного автомата смены IP exit (план, раздел «Смена IP exit»), хранения
  состояния и возобновления операций. Это отдельные задачи.
- Нет повторов запросов, кэша и ожидания по rate limit: каждая ошибка сразу
  возвращается вызывающему коду.
- Тесты не обращаются к Hetzner и Cloudflare: используются только локальные
  `httptest`-серверы и синтетические токены.

## Сверка с OpenAPI (2026-11-11)

| | Hetzner Cloud | Cloudflare |
| --- | --- | --- |
| Спецификация | `https://docs.hetzner.cloud/cloud.spec.json` | `openapi.json` из `github.com/cloudflare/api-schemas`, commit `c1489e8ed2bfc099c45a442893b6cdca80e2f26a` |
| OpenAPI / `info.version` | 3.1.2 / `1.0.0` | 3.0.3 / `4.0.0` |
| `DefaultBaseURL` | `https://api.hetzner.cloud/v1` | `https://api.cloudflare.com/client/v4` |
| Аутентификация | `Authorization: Bearer <token>` | `Authorization: Bearer <token>` (схема `api_token`) |

Пути (относительно базового URL) и используемые параметры:

| Метод клиента | Запрос | operationId | Параметры |
| --- | --- | --- | --- |
| `hetzner.ListServers` | `GET /servers` | `list_servers` | `name`, `label_selector`, `page`, `per_page=50` |
| `hetzner.Server` | `GET /servers/{id}` | `get_server` | `id` от 1 до 2^53−1 |
| `hetzner.ListPrimaryIPs` | `GET /primary_ips` | `list_primary_ips` | `name`, `label_selector`, `page`, `per_page=50` |
| `hetzner.PrimaryIP` | `GET /primary_ips/{id}` | `get_primary_ip` | `id` от 1 до 2^53−1 |
| `cloudflare.ListZones` | `GET /zones` | `zones-get` | `name`, `status`, `account.id`, `page`, `per_page=50` |
| `cloudflare.ListDNSRecords` | `GET /zones/{zone_id}/dns_records` | `dns-records-for-a-zone-list-dns-records` | `type`, `name.exact`, `content.exact`, `page`, `per_page=100` |

## Пагинация

- **Hetzner:** `meta.pagination` обязателен. Клиент запрашивает страницы
  начиная с 1 по `per_page=50` (максимум API) и идёт по `next_page`, пока он не
  `null`. Ответ отклоняется как `ErrMalformedResponse`, если `page` не совпадает
  с запрошенной, `next_page` не равен `page+1`, элементов больше `per_page` или
  пустая страница объявляет следующую.
- **Cloudflare:** `success: true` и `result_info.page/per_page/total_pages`
  обязательны. Страницы запрашиваются, пока `page < total_pages`; пустой
  результат с `total_pages` 0 или 1 — пустой список. Отклоняются несовпадение
  `page`, `count`, не равный числу элементов, превышение `per_page` и пустая
  страница не последней. Для зон `per_page=50` — максимум API; для DNS-записей
  `per_page=100` — значение API по умолчанию.
- Оба клиента прекращают обход после `MaxPages` (1000) страниц с
  `ErrPaginationLimit`. Пустой результат — непустой (`non-nil`) пустой срез.

## Безопасность и ошибки

- Конструктор `New(baseURL, token, *http.Client)` не обращается к сети и
  принимает только абсолютный `https`-URL без userinfo, query и fragment;
  префикс пути (например, прокси `/edge/client/v4`) сохраняется. Токен
  передаётся явно — глобальных credentials и чтения окружения нет. Значения URL
  и токена не попадают в тексты ошибок; `fmt` печатает клиент без токена.
- Переданный `*http.Client` копируется; копия отклоняет любые редиректы
  (`ErrRedirect`), поэтому токен не уходит на другой адрес. TLS-настройки
  транспорта не меняются.
- Тело ответа читается не более `MaxResponseBytes` (4 МиБ,
  `ErrResponseTooLarge`) и всегда закрывается. Если у контекста нет дедлайна,
  запрос ограничивается `DefaultTimeout` (30 с).
- Клиенты ничего не логируют. Ошибка содержит HTTP-статус и только код и
  сообщение провайдера (первый элемент `errors` у Cloudflare, `error.code` и
  `error.message` у Hetzner): сообщение обрезается до 256 символов, управляющие
  символы заменяются, вхождения токена — на `[REDACTED]`. Сырое тело ответа в
  ошибку не попадает.
- `*APIError` сопоставляется через `errors.Is` с `ErrUnauthorized` (401),
  `ErrForbidden` (403), `ErrNotFound` (404), `ErrRateLimited` (429) и
  `ErrServer` (5xx); у Cloudflare ответ 2xx с `success: false` — `ErrUnsuccessful`.
  Неверный JSON, отсутствующие обязательные поля и обрезанное тело —
  `ErrMalformedResponse`. Истечение контекста распознаётся как
  `context.DeadlineExceeded`.

## Минимальные права токенов

- **Hetzner Cloud:** API-токен создаётся внутри одного проекта и действует
  только в нём; права — **Read**. Read & Write этим клиентам не нужен.
- **Cloudflare:** пользовательский API Token с правами **Zone → Zone → Read** и
  **Zone → DNS → Read**, в Zone Resources — **Include → Specific zone** с одной
  зоной. `ListZones` с таким токеном видит только эту зону. Global API Key и
  заголовки `X-Auth-Email`/`X-Auth-Key` не поддерживаются.
- Токены для будущих операций записи (смена IP, обновление DNS) должны
  выпускаться отдельно, когда эти операции появятся.

## Проверка

```sh
cd vpnctl
go vet ./internal/cloud/...
go test ./internal/cloud/...
```
