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
| Проверка до изменений | ОС Linux, systemd, архитектура `x86_64`/`aarch64`, литеральный адрес прослушивания, retention с явной единицей, интервал скрейпа, лимиты ресурсов, порт. При несоответствии роль завершается ошибкой, ничего не изменив. |
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
`victoria-metrics-linux-{amd64,arm64}-v1.155.0_checksums.txt` релиза и
сверены с распакованными бинарями:

| Архитектура | Архив | SHA256 |
| --- | --- | --- |
| `amd64` | `victoria-metrics-linux-amd64-v1.155.0.tar.gz` | `aca3c49816db88c0e48012772fcf2a94eb66aaccd925b35d397b8b6f7f40fb43` |
| `arm64` | `victoria-metrics-linux-arm64-v1.155.0.tar.gz` | `5024a2a13237fbfbf7b276e60b7942cf0efb3bea5f53b5ca4b690e4d0719ca58` |

Версия и суммы находятся в `vars/`, а не в `defaults/`: их нельзя случайно
переопределить из inventory. Обновление версии — отдельный PR, меняющий
версию и все суммы вместе. `latest` не поддерживается.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `victoriametrics_listen_address` | `127.0.0.1` | Литеральный IPv4/IPv6-адрес этого хоста; `0.0.0.0`, `::`, multicast и имена хостов отклоняются. |
| `victoriametrics_listen_port` | `8428` | TCP-порт, 1–65535. |
| `victoriametrics_data_dir` | `/var/lib/victoriametrics` | Каталог данных (`0750`); persistent. |
| `victoriametrics_retention` | `30d` | Retention; явные единицы `s/h/d/w/M/y`. Голое число в VictoriaMetrics означает месяцы и здесь отвергается. Минимум — 24h (ограничение самой VM). |
| `victoriametrics_scrape_interval` | `30s` | Интервал скрейпа (`s/m/h/d`). |
| `victoriametrics_memory_max` | `512M` | `MemoryMax` systemd; пустая строка отключает. |
| `victoriametrics_cpu_quota` | `50%` | `CPUQuota` systemd; пустая строка отключает. |
| `victoriametrics_allowed_sources` | `[]` | ACL источников запросов; см. раздел «Сетевой доступ». |
| `victoriametrics_panel_metrics` | `{}` | Скрейп метрик панели; см. раздел «Метрики панели». |
| `victoriametrics_scrape_nodes` | `groups['exit'] + groups['relay']` | Имена inventory-хостов, чьи node_exporter скрейпятся. |
| `victoriametrics_health_path` | `/health` | Путь проверки здоровья. |

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
версией: ошибки разбора, неизвестные поля и недостижимая схема препятствуют
запуску до любых изменений. Конфиг перечитывается сервисом по SIGHUP; роль
перезапускает сервис только при изменении unit-файла или конфига.

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
- `username` и `password` — литеральные значения (например, из
  зашифрованного vars-файла SOPS); либо
- `username_file` и `password_file` — абсолютные пути на управляющей машине
  вне репозитория (dotenv-файл оператора).

Комбинации «value + file» для одного поля запрещены. Значения никогда не
попадают в шаблоны, argv, логи или diff: роль пишет их в файлы
`/etc/victoriametrics/panel-metrics-{username,password}` (`0600`), а
scrape-конфиг ссылается на них ключами `username_file`/`password_file`
(поддержка VictoriaMetrics, разбор при каждом использовании). Задачи с
секретами выполняются с `no_log` и `diff: false`.

## Сетевой доступ

- По умолчанию query API слушает `127.0.0.1:8428`. Метрики содержат сведения
  об инфраструктуре (узлы, ядра, память, имена целей); не публикуйте их.
- Не-loopback адрес требует одновременно:
  - непустой `victoriametrics_allowed_sources` — список точных приватных
    `/32` и `/128` CIDR (RFC 1918 / `fc00::/7`); широкие сети, публичные и
    loopback-источники отклоняются до изменений;
  - правило `base_firewall_source_ports` роли `base` с теми же CIDR
    (эта роль firewall не меняет);
  - адрес должен быть назначен хосту.
- Публичные источники и указание `0.0.0.0/0` невозможны: preflight отклоняет
  их до первого изменения.
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

В check mode архив не загружается, сервис не запускается и restart
регистрируется как `changed` без выполнения; существующие файлы не меняются.
Применение к рабочим узлам требует отдельного явного разрешения владельца
(см. [AGENTS.md](../AGENTS.md)).

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
одноразовом runner `ubuntu-24.04` с systemd: синтаксис playbook, отказ для
`0.0.0.0` до изменений, check mode на чистой системе, установка, `up` по
self-scrape и node_exporter через `/api/v1/query`, проверка retention-флага,
персистентность данных после перезапуска, повторный запуск с `changed=0`,
не-loopback адрес с ACL и запрет доступа из постороннего source namespace.
Job не входит в обязательные проверки `Repository checks` и `Secret scan`.

## Откат

- **Репозиторий.** Отдельный PR с revert squash-коммита этой задачи; `master`
  не переписывается.
- **Версия на узле.** Revert изменения версии и повторный запуск playbook:
  unit снова указывает на каталог прежней версии, сервис перезапускается.
  Данные сохраняются: формат хранения совместим в пределах мажорной версии VM.
- **Адрес/ACL на узле.** Вернуть `victoriametrics_listen_address` к
  `127.0.0.1` (или удалить переопределение) и запустить playbook; правила
  firewall роли `base` откатываются по её процедуре.
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
