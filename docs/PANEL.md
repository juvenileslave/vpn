# Панель Remnawave: роль `remnawave_panel`

Документ описывает задачу 2.1 [архитектурного плана](ARCHITECTURE_PLAN.md):
роль `ansible/roles/remnawave_panel` и playbook
`ansible/playbooks/remnawave_panel.yml`. Роль рендерит, проверяет и запускает
compose-проект `remnawave` (панель, PostgreSQL, Valkey) с привязкой панели
только к loopback. **Роль не применялась ни к одному реальному серверу**, а
полный runtime-прогон ещё не выполнен (см. «Что не проверено»).

## Что разворачивается

Каталог проекта на хосте (по умолчанию `/opt/remnawave`, режим `0750`):

| Файл | Режим | Содержимое |
| --- | --- | --- |
| `compose.yaml` | `0644` | Описание стека; секретов не содержит. |
| `panel.env` | `0600` | Секреты панели и вычисленный `DATABASE_URL`. |
| `db.env` | `0600` | `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`. |

Сервисы compose-проекта `remnawave`:

- `remnawave` — образ `remnawave/backend`, публикует только
  `panel_bind:panel_port` → `3000` в контейнере. Порт метрик `3001` наружу не
  публикуется и используется healthcheck'ом.
- `remnawave-db` — `postgres`, том `db-data` в `/var/lib/postgresql`.
- `remnawave-redis` — `valkey/valkey` без персистентности (кэш и очереди),
  том `valkey-data` в `/data`.

Все сервисы: `restart: unless-stopped`, healthcheck, `no-new-privileges`,
ротация json-логов, метка `io.github.juvenileslave.vpn.managed-by=remnawave_panel`.
Панель стартует после `service_healthy` базы и Valkey. Сеть `backend` —
`internal: true` (без выхода наружу): в ней находятся все три сервиса. Сеть
`frontend` есть только у панели: через неё публикуется loopback-порт и идут
исходящие соединения к node API.

Запрещено и проверяется до запуска: `privileged`, `network_mode`/`pid`/`ipc`
`host`, bind-монтирования (включая Docker socket), опубликованные порты у базы
и Valkey.

## Требования

- Целевой хост Debian/Ubuntu с Docker Engine и плагином Compose v2
  (`docker compose`). Установка Docker — задача роли `docker` (issue #11), эта
  роль Docker не устанавливает.
- Управляющая машина: `make -C ansible bootstrap` (ansible-core из
  `requirements-ansible.txt`); коллекции не нужны.
- Секреты из SOPS (issue #19) или иной файл оператора вне репозитория.
- Плагин `docker compose` нужен и в `--check`: проверка рендера выполняется
  на целевом хосте.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `image_tags.remnawave_panel` | нет | Тег `remnawave/backend`, обязателен. |
| `image_tags.postgres` | нет | Тег `postgres`, обязателен. |
| `image_tags.valkey` | нет | Тег `valkey/valkey`, обязателен. |
| `panel_bind` | `127.0.0.1` | IP из `127.0.0.0/8` или `::1`; иное отклоняется. |
| `panel_port` | `3000` | Порт на хосте, 1–65535. |
| `remnawave_panel_env_file` | `""` | Абсолютный путь к dotenv-файлу на управляющей машине вне репозитория. |
| `remnawave_panel_env` | `{}` | Mapping секретов (например, из зашифрованного vars-файла). |
| `remnawave_panel_sub_public_domain` | `""` | `SUB_PUBLIC_DOMAIN`: `host[/path]` без схемы и `/` в конце, обязателен. |
| `remnawave_panel_front_end_domain` | `*` | `FRONT_END_DOMAIN` (CORS): `*` или хост. |
| `remnawave_panel_dir` | `/opt/remnawave` | Каталог проекта. |
| `remnawave_panel_up_timeout` | `300` | Секунды ожидания healthy в `docker compose up --wait`. |
| `remnawave_panel_hosts` | `cp` | Группа хостов playbook; при `cp_placement: exit` — `exit`. |

### Закрепление образов

Значений по умолчанию нет. Роль останавливается до любых изменений, если ключ
отсутствует, пуст, равен `latest`, не строка или не соответствует шаблону:

- `remnawave_panel`, `valkey`: `MAJOR.MINOR.PATCH[-суффикс][@sha256:<64 hex>]`,
  например `3.4.10`, `9.1.3-alpine`;
- `postgres`: `MAJOR.MINOR[-суффикс][@sha256:…]`, `MAJOR` не ниже 18 (том
  смонтирован по раскладке образов 18+), например `"18.6"`.

Числовые теги пишите в кавычках: YAML превращает `18.6` в число, и роль его
отклонит. Пример для `group_vars/all.yml` (общий example inventory этой ролью не
меняется; проверять теги на Docker Hub перед выбором):

```yaml
image_tags:
  remnawave_panel: 3.4.10      # hub.docker.com/r/remnawave/backend
  postgres: "18.6"             # hub.docker.com/_/postgres
  valkey: 9.1.3-alpine         # hub.docker.com/r/valkey/valkey
```

### Секреты

Задаётся ровно один источник: `remnawave_panel_env_file` или
`remnawave_panel_env`; оба сразу или ни одного — ошибка. Файл — формат dotenv
(`KEY=VALUE`, комментарии `#`, необязательные `export` и кавычки), подходит
вывод `sops -d --output-type dotenv`. Файл должен лежать вне рабочей копии
репозитория.

Обязательные непустые ключи: `APP_SECRET`, `METRICS_USER`, `METRICS_PASS`,
`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`. Ограничения:

- `POSTGRES_USER`, `POSTGRES_DB` — `[A-Za-z_][A-Za-z0-9_]*`;
- `POSTGRES_PASSWORD` — не короче 16 символов из `[A-Za-z0-9._~-]` (входит в
  `DATABASE_URL` без экранирования), например `openssl rand -hex 32`;
- значение `change_me`, одинарная кавычка, перевод строки и NUL запрещены;
- ключи `APP_PORT`, `METRICS_PORT`, `DATABASE_URL`, `REDIS_HOST`, `REDIS_PORT`,
  `REDIS_SOCKET`, `FRONT_END_DOMAIN`, `SUB_PUBLIC_DOMAIN` задаёт роль; в
  секретах они отклоняются.

Остальные ключи (например, `TELEGRAM_BOT_TOKEN`) передаются панели как есть.
Сообщения об ошибках называют только ключи, не значения. Задачи с секретами
выполняются с `no_log`, env-файлы пишутся с режимом `0600` без diff. Значения
в `compose.yaml` не попадают. Окружение контейнеров видно root на хосте
(`docker inspect`); для однопользовательского узла это принято.

## Порядок выполнения и идемпотентность

1. Проверка переменных и секретов на управляющей машине.
2. Рендер `compose.yaml` во временный каталог хоста с env-файлами, где есть
   только имена ключей; `docker compose config --quiet` и проверка
   нормализованной модели (`config --format json`) на запреты выше. Daemon не
   нужен. Каталог удаляется.
3. Проверка доступности Docker daemon и конфликтов: контейнеры, тома и сети с
   меткой проекта `remnawave` или зарезервированными именами (включая имена
   upstream quick-start: `remnawave`, `remnawave-db`, `remnawave-redis`) без
   метки роли, а также чужой `compose.yaml` в каталоге проекта. Конфликт
   останавливает роль; ничего не удаляется и не перехватывается.
4. Запись файлов и `docker compose up --detach --wait --remove-orphans` только
   если изменился env-файл или `compose.yaml` либо не все три сервиса запущены.
   Повторный запуск без изменений даёт `changed=0`.

`--check --diff` выполняет шаги 1–3, показывает diff `compose.yaml`, сообщает
об изменении env-файлов без содержимого и о том, что `up` был бы выполнен.
Образы в check mode не скачиваются, контейнеры не меняются. Firewall и SSH роль
не трогает.

## Проверка

```sh
make -C ansible bootstrap
cd ansible
../.venv/bin/ansible-playbook -i inventories/example/hosts.yml \
  playbooks/remnawave_panel.yml --syntax-check
```

Роль подключается по относительному пути из playbook; альтернатива —
`ANSIBLE_ROLES_PATH=ansible/roles`. В example inventory `image_tags: {}`, поэтому
реальный запуск с ним намеренно падает на проверке закрепления.

Запуск на подготовленном хосте (рабочий inventory — только локально):

```sh
cd ansible
../.venv/bin/ansible-playbook -i inventories/production/hosts.yml \
  playbooks/remnawave_panel.yml --check --diff \
  -e remnawave_panel_env_file=/abs/path/outside/repo/panel.env
# после просмотра diff — тот же запуск без --check --diff
```

Доступ к панели — только через SSH-туннель:
`ssh -L 3000:127.0.0.1:3000 <cp-host>`, затем `http://127.0.0.1:3000`.

Ручная проверка на хосте: `docker compose -p remnawave ps` (все `healthy`),
`ss -ltn` (порт панели только на loopback, порты 5432/6379 отсутствуют),
`stat -c %a /opt/remnawave/*.env` (`600`).

## Обновление образов

1. Отдельным коммитом поменяйте тег в `image_tags` (точный тег из Docker Hub или
   release notes Remnawave; прочитайте заметки о миграциях).
2. Сделайте резервную копию базы (см. «Резервное копирование»).
3. Запустите playbook с `--check --diff`, затем без него: изменённый
   `compose.yaml` пересоздаёт только затронутые контейнеры; тома сохраняются.

Смена мажорной версии PostgreSQL (например, 18 → 19) **не выполняется** сменой
тега: нужен dump/restore по отдельному плану.

## Ротация ключей

- `APP_SECRET`, `METRICS_USER`, `METRICS_PASS`, прочие ключи панели: обновите
  значение в источнике секретов и запустите playbook — меняется `panel.env`,
  контейнер панели пересоздаётся. Смена `APP_SECRET` завершает активные сессии
  администраторов.
- `POSTGRES_PASSWORD`: образ PostgreSQL применяет его только при создании
  кластера. Сначала смените пароль в базе:
  `docker compose -p remnawave exec remnawave-db psql -U <user> -d <db> -c "\password <user>"`,
  затем внесите тот же пароль в источник секретов и запустите playbook
  (обновятся `db.env` и `DATABASE_URL`). Не публикуйте пароль в истории shell.
- `POSTGRES_USER`/`POSTGRES_DB` после первого запуска не меняйте: существующий
  кластер их не переименует.

## Резервное копирование

Состояние панели — в томе `remnawave_db-data`. Бэкап и восстановление
относятся к задачам `cp_backup`, `backup.yml`, `restore.yml` архитектурного
плана и этой ролью не реализованы. До их появления перед изменениями делайте
`pg_dump` вручную и храните его вне репозитория.

## Откат

- Файлы и контейнеры: верните предыдущие `image_tags`/секреты (revert PR) и
  запустите playbook.
- Остановка стека с сохранением данных:
  `docker compose -p remnawave --project-directory /opt/remnawave down`
  **без `-v`** — тома `remnawave_db-data` и `remnawave_valkey-data` остаются.
- Откат изменения репозитория — отдельный PR, отменяющий squash-коммит.

## Что не проверено

- Полный runtime-прогон в одноразовой Debian/Ubuntu VM с Docker не выполнен:
  в среде разработки Docker daemon не может создать bridge-сеть. Не проверены:
  первый запуск и `healthy` всех сервисов, доступность панели только через
  loopback, отсутствие портов PostgreSQL/Valkey на хосте, `changed=0` при
  повторном запуске, сохранение данных после перезапуска, обнаружение
  конфликтов на реальном daemon.
- Проверено локально без daemon: `--syntax-check`; рендер шаблонов и
  `docker compose config --quiet` (Compose 2.40.3); проверка политики на
  нормализованной модели; отказ на неверных тегах, `panel_bind`, источниках и
  ключах секретов до любых изменений; отсутствие синтетических секретов в
  выводе Ansible и `compose.yaml`; режим `0600` env-файлов.
- Работа панели с Valkey по TCP (`REDIS_HOST`/`REDIS_PORT`, вместо сокета
  upstream compose) взята из схемы конфигурации Remnawave 3.4.10 и не
  проверена запуском.
- Интеграция с ролью `docker` (#11) и SOPS-guardrails (#19) не проверена: они
  ещё не слиты.
