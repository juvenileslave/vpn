# VictoriaMetrics: роль `victoriametrics`

Документ описывает задачу 10.1 [архитектурного плана](ARCHITECTURE_PLAN.md):
роль `ansible/roles/victoriametrics` и playbook
`ansible/playbooks/victoriametrics.yml` — single-node VictoriaMetrics с
генерируемым из inventory scrape-конфигом. **Роль не применялась ни к одному
рабочему серверу.** Это хранилище метрик, а не система алертинга: правила
оценки, отправка уведомлений и графики остаются за `vpnctl` (задача 10.2, ещё
не подключена к этой роли) и Telegram-ботом.

## Что делает роль

| Действие | Подробности |
| --- | --- |
| Проверка до изменений | ОС Linux, systemd, архитектура `x86_64`/`aarch64`, литеральный адрес прослушивания (loopback либо приватный RFC 1918/ULA), ACL источников против контракта роли `base`, retention с явной единицей, интервал скрейпа, лимиты ресурсов, порт, источник учётных данных панели (только файлы вне репозитория). При несоответствии роль завершается ошибкой, ничего не изменив. |
| Scrape-конфиг | Рендерится из inventory в scratch-каталог, проверяется закреплённым бинарём `-promscrape.config.dryRun` (строгий разбор, отказ на неизвестных полях) и только затем устанавливается. |
| Учётная запись | Системные группа и пользователь `victoriametrics`, shell `/usr/sbin/nologin`. |
| Установка | Официальный архив релиза скачивается с GitHub и проверяется по закреплённому SHA256, затем распаковывается в `/opt/victoriametrics/victoria-metrics-linux-<arch>-v<версия>/`. Файлы принадлежат `root`. |
| Данные | `/var/lib/victoriametrics` (`0750`, владелец `victoriametrics`) — персистентный каталог `-storageDataPath`, переживает перезапуск сервиса. |
| Сервис | `/etc/systemd/system/victoriametrics.service`: `Restart=on-failure`, `MemoryMax`/`CPUQuota`, `ProtectSystem=strict` с `ReadWritePaths` только на каталог данных, прочие `Protect*`/`Restrict*`. `systemd-analyze verify` при каждом применении. |
| Проверка здоровья | После (пере)запуска роль опрашивает `/health` на адресе прослушивания до ответа `200` (это эндпоинт без авторизации; проверяет живость, не метрики). |
| Preflight | Отказ забирать установку без управляемого этой ролью конфига: существующий `/var/lib/victoriametrics` без метки `Managed by the Ansible role victoriametrics` в scrape-конфиге останавливает запуск. |

Роль не меняет firewall, sysctl, SSH, пакеты, Docker и другие сервисы и не
трогает роли экспортёров. Она не открывает портов сама: ограничения источника
для не-loopback адреса задаёт firewall роли `base`.

## Версия и контрольные суммы

Версия закреплена в `ansible/roles/victoriametrics/vars/main.yml`:
**VictoriaMetrics v1.155.0** (single-node, бинар `victoria-metrics-prod`).
SHA256 взяты из официальных
`victoria-metrics-linux-{amd64,arm64}-v1.155.0_checksums.txt` релиза:
архив проверяется `get_url` при скачивании, а распакованный бинар
`victoria-metrics-prod` — отдельной задачей после распаковки
(см. `vars/main.yml`).

| Архитектура | Файл | SHA256 |
| --- | --- | --- |
| `amd64` | `victoria-metrics-linux-amd64-v1.155.0.tar.gz` | `7180e65913d55ab99c0be8f4a3ad17a0fafe5598a21ff6327fecba3190d7b176` |
| `amd64` | `…/victoria-metrics-linux-amd64-v1.155.0/victoria-metrics-prod` | `aca3c49816db88c0e48012772fcf2a94eb66aaccd925b35d397b8b6f7f40fb43` |
| `arm64` | `victoria-metrics-linux-arm64-v1.155.0.tar.gz` | `c6af3f35c597e2cb45c9bbb7a7fc1638c6f1ec10a8198c2861aa14531bf439d7` |
| `arm64` | `…/victoria-metrics-linux-arm64-v1.155.0/victoria-metrics-prod` | `5024a2a13237fbfbf7b276e60b7942cf0efb3bea5f53b5ca4b690e4d0719ca58` |

Версия и суммы находятся в `vars/`, а не в `defaults/`: их нельзя случайно
переопределить из inventory. Обновление версии — отдельный PR, меняющий
версию и все суммы вместе. `latest` не поддерживается.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `victoriametrics_listen_address` | `127.0.0.1` | Литеральный IPv4/IPv6-адрес этого хоста; `0.0.0.0`, `::`, multicast и имена хостов отклоняются. |
| `victoriametrics_listen_port` | `8428` | TCP-порт, 1–65535. |
| `victoriametrics_data_dir` | `/var/lib/victoriametrics` | Каталог данных (`0750`); persistent. |
| `victoriametrics_retention` | `30d` | Retention; конечная длительность не меньше 24h с явной единицей `s/h/d/w/M/y`. Голое число означает месяцы и отвергается. |
| `victoriametrics_scrape_interval` | `30s` | Интервал скрейпа (`s/m/h/d`). |
| `victoriametrics_memory_max` | `512M` | `MemoryMax` systemd; пустая строка отключает. |
| `victoriametrics_cpu_quota` | `50%` | `CPUQuota` systemd; пустая строка отключает. |
| `victoriametrics_allowed_sources` | `[]` | ACL источников запросов; см. раздел «Сетевой доступ». |
| `victoriametrics_panel_metrics` | `{}` | Скрейп метрик панели; см. раздел «Метрики панели». |
| `victoriametrics_scrape_nodes` | `groups['exit'] + groups['relay']` | Имена inventory-хостов, чьи node_exporter скрейпятся. |
| `victoriametrics_health_path` | `/health` | Путь проверки здоровья. |

## Диск и ёмкость

Retention ограничивает возраст данных, но не размер каталога. `MemoryMax` и
`CPUQuota` также не являются дисковой квотой. На небольшом exit оставляйте
не менее 20% диска свободными для слияния частей и учитывайте место вне
`/var/lib/victoriametrics`: индексы, логи, архивы и прежние версии в `/opt`.

Оценка по [руководству VictoriaMetrics по sizing](https://docs.victoriametrics.com/guides/understand-your-setup-size/):
`bytes_per_sample × samples_per_second × (retention_seconds + retention_cycle) / 0.8`.
Для retention `30d` цикл очистки — один день. Например, 10 000 активных рядов
при интервале `30s` дают около 333 точек/с; при условном 1 байте на точку
получается около 1.04 GiB за 31 день с резервом 20%. Это оценка, а не лимит
и не обещание сжатия: churn и кардинальность меток могут увеличить расход.
Размер точки и скорость поступления измеряйте на тестовой нагрузке по
`vm_data_size_bytes`, `vm_rows` и `vm_rows_inserted_total`, затем пересчитывайте
ёмкость. Эта роль не добавляет дисковых алертов и не гарантирует свободное место.

## Скрейп-конфиг

`/etc/victoriametrics/scrape.yml` (`0640`) генерируется, не правится на хосте:

- `victoriametrics` — self-scrape с адреса прослушивания;
- `node_exporter` — цели `<имя хоста>:9100` из `victoriametrics_scrape_nodes`
  (контракт роли node_exporter: один адрес `127.0.0.1:9100` на каждом узле,
  поэтому скрейп возможен только с того же хоста; для сбора с exit/relay на CP
  node_exporter на этих узлах должен слушать адрес, доступный с CP, а firewall
  роли `base` ограничивает порт 9100 источником CP);
- `panel` — только если задан `victoriametrics_panel_metrics`.

Перед установкой конфиг проверяется `-promscrape.config.dryRun` закреплённой
версией: ошибки разбора, неизвестные поля и неверные scrape-цели препятствуют
изменению установки. Dry-run не проверяет сетевую доступность экспортёров.
Роль перезапускает сервис при изменении unit-файла, scrape-конфига или
файлов учётных данных панели.

Метрики, которых ещё нет, не являются ошибкой: `up` = 0 для цели без
установленного экспортёра, значения имён рядов появляются по мере установки
ролей (см. «Non-goals» issue #57).

## Метрики панели

Панель Remnawave публикует метрики на `METRICS_PORT 3001` только внутри
compose-стека; с хоста она доступна, если compose-проект размещён на том же
хосте и порт проброшен на loopback (задача роли `remnawave_panel`; сейчас
порт 3001 наружу не публикуется и используется healthcheck'ом — поэтому
скрейп панели с CP по loopback потребует отдельного изменения роли панели).

`victoriametrics_panel_metrics` принимает:

- `url` — необязателен, по умолчанию `http://127.0.0.1:3001/metrics`;
- `username_file` и `password_file` — абсолютные пути на управляющей машине
  вне репозитория, задаются только парой. Каждый файл содержит только значение
  соответствующего поля, а не dotenv-файл целиком.

Литеральные секреты в переменных запрещены: роль отклоняет любые ключи,
кроме `url`, `username_file` и `password_file`. Значения никогда не попадают
в шаблоны, argv, логи или diff: роль копирует содержимое файлов в
`/etc/victoriametrics/panel-metrics-{username,password}` (`0640`, читаемо
только группой сервиса `victoriametrics`), а scrape-конфиг ссылается на них
ключами `username_file`/`password_file`. URL не может содержать userinfo,
query-параметры или fragment. Задачи с секретами выполняются с `no_log` и
`diff: false`; при отсутствии учётных данных устаревшие файлы удаляются.

## Сетевой доступ

- По умолчанию query API слушает `127.0.0.1:8428`. Метрики содержат сведения
  об инфраструктуре (узлы, ядра, память, имена целей); не публикуйте их.
- Роль передаёт `-enableTCP6` для IPv6-listen и IPv6 scrape-целей; HTTP-сокет
  остаётся привязан к одному явно выбранному адресу, не к wildcard.
- Не-loopback адрес требует одновременно:
  - приватный адрес (RFC 1918 / `fc00::/7`), назначенный хосту; публичные,
    TEST-NET и link-local адреса отклоняются до изменений;
  - непустой `victoriametrics_allowed_sources` — список точных приватных
    `/32` и `/128` CIDR того же семейства адресов, что и адрес прослушивания;
    широкие сети, публичные и loopback-источники отклоняются до изменений;
  - предварительно применённый firewall роли `base`, `base_firewall_enabled: true`
    и ровно одно правило `base_firewall_source_ports` с `proto: tcp`, TCP-портом
    `victoriametrics_listen_port` (по умолчанию `8428`) и теми же CIDR в
    `source_cidrs`. Роль VictoriaMetrics проверяет декларацию ACL, но не
    применяет firewall и не проверяет его фактическое состояние.
- С `cp_placement: exit` переменные живут в `host_vars`/`group_vars` exit
  (роль применяется playbook'ом `-e victoriametrics_hosts=exit`); с
  `cp_placement: dedicated` — на CP-хосте. Механизм ACL один и тот же.
- Исходящий HTTPS к `github.com` нужен для загрузки архива.

## Запуск

Команды выполняются из каталога `ansible/` после `make -C ansible bootstrap`.

```sh
# Синтаксис (без подключения к узлам):
../.venv/bin/ansible-playbook --syntax-check playbooks/victoriametrics.yml

# Предварительный просмотр изменений:
../.venv/bin/ansible-playbook -i <inventory> --limit <хост> --check --diff \
  playbooks/victoriametrics.yml

# Применение:
../.venv/bin/ansible-playbook -i <inventory> --limit <хост> playbooks/victoriametrics.yml

# С cp_placement: exit:
../.venv/bin/ansible-playbook -i <inventory> -e victoriametrics_hosts=exit \
  playbooks/victoriametrics.yml
```

В check mode архив не загружается: на чистой системе dry-run переносится на
реальный прогон. Роль создаёт только временный приватный scratch-каталог в
`/tmp` и удаляет его; конфигурация, данные и сервис не меняются. Для dry-run
новой установки файловая система scratch-каталога должна разрешать исполнение.
На хосте с установленным бинарём check mode проверяет рендеренный конфиг.
Применение к рабочим узлам требует отдельного
явного разрешения владельца (см. [AGENTS.md](../AGENTS.md)).

## Проверка на узле

```sh
systemctl is-active victoriametrics.service
ss -Hltn "sport = :8428"
curl -fsS http://127.0.0.1:8428/health
curl -fsS 'http://127.0.0.1:8428/api/v1/query?query=up'
/opt/victoriametrics/victoria-metrics-linux-amd64-v1.155.0/victoria-metrics-prod --version
```

Ожидается: сервис `active`, ровно один сокет на настроенном адресе,
`{"status":"success",...}` c `up` по целям, `victoria-metrics-...-v1.155.0`
в версии. Повторный запуск playbook должен завершаться с `changed=0`.
Проверка retention и персистентности: вставка пробной точки, перезапуск
сервиса, повторный запрос той же точки.

## CI

Workflow [`.github/workflows/victoriametrics.yml`](../.github/workflows/victoriametrics.yml)
(job `victoriametrics role`) запускается для pull request и push в `master` на
одноразовом runner `ubuntu-24.04` с systemd. Job проверяет отказ для неверных
адресов, retention, лимитов ресурсов и scrape-целей до изменений, check mode
на чистом хосте и на установленной роли, установку принятого node_exporter,
запуск сервиса, права, `MemoryMax`/`CPUQuota`, значения `up=1` и сохранение
вставленной точки после перезапуска. Повторные применения должны давать
`changed=0`; проверяются оба `cp_placement`, IPv6 loopback и retention `31d`.
Отдельный шаг создаёт две veth-пары и network namespaces, применяет firewall
роли `base` и слушатель `10.203.46.1`. Источник `10.203.46.2/32` может
выполнить запрос к API; посторонний источник имеет маршрут к тому же адресу,
но его запрос блокируется. Это синтетические приватные адреса RFC 1918,
не TEST-NET. Job не входит в обязательные проверки
`Repository checks` и `Secret scan`.

## Откат

- **Репозиторий.** Отдельный PR с revert squash-коммита этой задачи; `master`
  не переписывается.
- **Версия на узле.** Revert изменения версии и повторный запуск playbook:
  unit снова указывает на каталог прежней версии, сервис перезапускается.
  Роль не откатывает данные. До обновления сохраните отдельную копию хранилища;
  совместимость данных при downgrade проверяйте по release notes обеих версий,
  а не предполагайте по номеру мажорной версии.
- **Адрес/ACL на узле.** Вернуть `victoriametrics_listen_address` к
  `127.0.0.1`, одновременно очистить `victoriametrics_allowed_sources: []`
  и запустить playbook; правила firewall роли `base` откатываются по её процедуре.
- **Полное удаление с узла** (вручную, роль этого не делает; удаляет и данные):

  ```sh
  systemctl disable --now victoriametrics.service
  rm /etc/systemd/system/victoriametrics.service
  systemctl daemon-reload
  rm -r /opt/victoriametrics /var/lib/victoriametrics /etc/victoriametrics
  userdel victoriametrics
  groupdel victoriametrics  # если группа не удалена вместе с пользователем
  ```

Описанный откат не выполнялся на рабочих узлах; после любого отката проверяйте
результат командами из раздела «Проверка на узле».
