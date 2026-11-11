# Метрики: клиент запросов и пороговые правила

Пакет `vpnctl/internal/metrics` реализует клиентскую часть задачи 10.2
[архитектурного плана](ARCHITECTURE_PLAN.md): клиент Prometheus-совместимого
HTTP API (VictoriaMetrics) и вычисление пороговых правил без состояния.

## Чего здесь нет

- Роли `victoriametrics`, экспортёров и самих метрик: имена метрик в примерах
  ниже — проектные намерения, а не существующие ряды.
- Планировщика («раз в минуту»), хранения истории алертов, дедупликации,
  перехода в «resolved», уведомлений в Telegram и PNG-графиков.
- Команды CLI и поля конфигурации `vpnctl`: пакет пока никем не вызывается.
- Повторов запросов. Повтор, backoff и реакция на `429` — решение вызывающего.

## Клиент

`NewClient(Options)` только проверяет параметры и не открывает соединений:

| Поле | Требование |
| --- | --- |
| `BaseURL` | Только `https`, с хостом; без учётных данных, query и fragment. Путь сохраняется: `https://vm.example.com/select/0/prometheus` → `.../select/0/prometheus/api/v1/query`. |
| `HTTPClient` | Обязателен; транспорт, TLS и прокси настраивает вызывающий. |
| `Timeout` | Больше нуля; ограничивает весь запрос, включая чтение тела. |
| `MaxBodyBytes` | `0` — 8 MiB по умолчанию; отрицательное значение — ошибка. |
| `BearerToken` / `BasicAuth` | Необязательны и взаимоисключающие. В Git и примеры не попадают. |

- `Query(ctx, expr, at)` — `POST /api/v1/query` с полями `query` и `time`
  (секунды Unix с миллисекундами; нулевое `at` — время сервера). Допустимы
  `scalar`, `vector` и `matrix` (для выражений с range selector).
- `QueryRange(ctx, expr, start, end, step)` — `POST /api/v1/query_range`;
  принимается только `matrix`. Пустое выражение, `end < start` и `step <= 0`
  отклоняются до запроса.

POST выбран, чтобы длинные выражения не попадали в URL и журналы доступа.
Метки рядов сохраняются как есть; время семпла — `time.Time` в UTC с точностью
до миллисекунды. Значения `NaN` и `±Inf` разбираются без потерь, а решение о них
принимает вычислитель правил. Поле `warnings` возвращается в `Result.Warnings`.

### Ошибки

Тело ответа никогда не включается в текст ошибки. Ошибки различаются через
`errors.As`/`errors.Is`:

| Тип | Когда |
| --- | --- |
| `*APIError` | `"status": "error"` при любом HTTP-коде. `Type` и `Message` — поля `errorType` и `error`, обрезаны до 256 символов, управляющие символы заменены. |
| `*HTTPError` | Не-2xx без корректного конверта ошибки (например, `429` или `503` от прокси). |
| `*BodyTooLargeError` | Тело больше `MaxBodyBytes`. |
| `*DecodeError` | Некорректный, обрезанный JSON, лишние данные после него, неизвестный `status`, неверная форма ряда или семпла. |
| `*ResultTypeError` | `resultType`, не допустимый для вызова (например, `string`). |
| `*RequestError` | Сетевой сбой, тайм-аут или отмена; `errors.Is(err, context.DeadlineExceeded)` и `context.Canceled` работают. |

## Правила

```go
type Rule struct {
	Name        string      // ^[a-z0-9][a-z0-9_.-]{0,63}$, уникальное
	Query       string      // непустое instant-выражение
	Aggregation Aggregation // max | min | sum | avg
	Comparison  Comparison  // > | >= | < | <= | == | !=
	Threshold   float64     // конечное число
	Severity    Severity    // info | warning | critical
}
```

`Evaluate(ctx, querier, rules, at)` сначала проверяет **все** правила
(`ValidateRules`); при ошибке возвращает `*ValidationError` со списком проблем и
не делает ни одного запроса. Затем для каждого правила выполняется один
instant-запрос и возвращается `Alert{Rule, Severity, State, Value, Threshold,
Labels, Series, Err}`. Ошибка запроса не прерывает остальные правила.

Состояние:

- `firing` — `Value <Comparison> Threshold` истинно; `ok` — ложно.
- `unknown` — запрос завершился ошибкой (`Err` содержит типизированную ошибку),
  результат пуст (`ErrNoData`) или среди значений есть `NaN`/`±Inf`, включая
  переполнение суммы (`ErrNonFinite`). Отсутствие данных **никогда** не
  считается `ok`.

Агрегация:

- `scalar` — одно значение без меток.
- `vector` — значение каждого ряда.
- `matrix` — последний по времени семпл каждого ряда; ряды без семплов
  пропускаются. Оконная семантика задаётся в самом запросе
  (`max_over_time(...[5m])` и т. п.).
- `max`/`min` возвращают метки ряда с крайним значением (при равенстве — первого),
  `sum`/`avg` — метки, общие для всех рядов с одинаковыми значениями.
  `Series` — число учтённых рядов.

Граница включается только операторами `>=`, `<=` и `==`: значение 80 при
`> 80` даёт `ok`, при `>= 80` — `firing`.

## Файл правил

`LoadRules(io.Reader)` принимает ровно один YAML-документ; неизвестные поля,
неверные типы, `.nan`/`.inf` в `threshold` и пустой список отклоняются.
Пример ниже синтетический: метрики `node_*` предполагают node_exporter, а
`vpn_relay_*`, `vpn_cert_*`, `vpn_domain_*` и `provider_balance` — будущие
экспортёры, которых в репозитории нет.

```yaml
rules:
  - name: node-cpu-busy
    query: 100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])))
    aggregation: max
    comparison: ">="
    threshold: 90
    severity: warning
  - name: node-memory-available
    query: 100 * node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes
    aggregation: min
    comparison: "<"
    threshold: 10
    severity: critical
  - name: node-disk-usage
    query: 100 * (1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"})
    aggregation: max
    comparison: ">="
    threshold: 90
    severity: critical
  - name: relay-daily-traffic
    query: increase(vpn_relay_transmit_bytes_total[24h]) / 1e9
    aggregation: max
    comparison: ">="
    threshold: 900
    severity: warning
  - name: cert-expiry-days
    query: (vpn_cert_not_after_seconds - time()) / 86400
    aggregation: min
    comparison: "<"
    threshold: 14
    severity: critical
  - name: domain-expiry-days
    query: (vpn_domain_expiry_seconds - time()) / 86400
    aggregation: min
    comparison: "<"
    threshold: 30
    severity: warning
  - name: provider-balance
    query: provider_balance
    aggregation: min
    comparison: "<"
    threshold: 5
    severity: warning
```

## Проверка

```sh
cd vpnctl
go vet ./internal/metrics
go test ./internal/metrics
```

Тесты используют только `httptest`-серверы с TLS и не обращаются к реальному
VictoriaMetrics; учётные данные в тестах — синтетические строки.
