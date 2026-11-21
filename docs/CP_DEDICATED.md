# Выделенный control plane: режим `cp_placement: dedicated`

Документ фиксирует операционный и репозиторный контракт среза issue #76 для
размещения панели Remnawave на отдельном `cp`-хосте. **VPN не развёрнут**;
реальный перенос control plane, развёртывание на серверах, изменение DNS/ACME,
настройка production firewall и cutover не выполнялись. Наличие плейбуков,
валидации и runbook не является runtime acceptance (см. раздел «Матрица
проверок и что не проверено»).

## 1. Назначение и границы

Цель выделенного control plane — отделить управление от `exit`-узла так, чтобы
блокировка, смена адреса или отказ `exit` не лишали оператора доступа к панели
Remnawave, локальному резервному копированию PostgreSQL и управлению узлами.

Границы контракта в этом срезе:

- Описывается и валидируется модель размещения `cp_placement: dedicated` с
  путём отката на `cp_placement: exit` в рамках существующих ролей репозитория
  ([DEPLOYMENT.md](DEPLOYMENT.md), [BACKUP.md](BACKUP.md),
  [PANEL_PROXY.md](PANEL_PROXY.md)).
- Реальный перенос панели, production deployment, настройка внешнего DNS,
  выпуск сертификатов ACME и изменение боевого firewall не выполняются.
- Частный overlay/entrance-транспорт, offsite-копирование резервных копий и
  автоматическая запись профилей в панель (#53) в этот срез не входят.

## 2. Размещение и inventory

Режим размещения задаётся переменной `cp_placement` в `group_vars/all.yml`:

| Значение `cp_placement` | Группа `cp` | Panel-хост | Назначение |
| --- | --- | --- | --- |
| `dedicated` | Ровно один отдельный хост (не `exit`) | Хост `cp` | Целевое размещение с изоляцией CP от отказа `exit`. |
| `exit` | Пустая | Хост `exit` | Прежнее совмещённое размещение и штатный путь отката. |

Play-level `hosts` в Ansible вычисляется до применения `group_vars`, поэтому
плейбуки panel-хоста (`remnawave_panel.yml`, `cp_proxy.yml`, `panel_proxy.yml`,
`backup.yml`, `victoriametrics.yml`) выбирают inventory-visible группу `cp`
(если она непуста), иначе `exit`. Перед ролями выполняется общий guard
`ansible/playbooks/tasks/require_panel_host.yml`: он сверяет фактический
`inventory_hostname` с `cp_placement` и останавливает запуск ошибкой при
расхождении (вместо тихого `skipping: no hosts matched`). Явный `*_hosts`
override (`cp_proxy_hosts`, `panel_proxy_hosts`, `cp_backup_hosts` и т. п.)
пропускает guard; в этом случае согласованность выбора проверяет оператор.

Что именно меняется в приватном inventory (вне Git) при переходе на
`dedicated`:

- В `group_vars/all.yml` задаётся `cp_placement: dedicated`.
- В группу `cp` добавляется ровно один отдельный хост (не совпадающий с
  `exit`).
- Для управления узлами (`remnawave_node`): задаётся явный `node_api_port`,
  обновляется source ACL `node_port_allow` и ровно одна TCP-запись в
  `base_firewall_source_ports` с `source_cidrs`, равными `node_port_allow`.
- `node_api_port` не публикуется в `base_firewall_vpn_ports`.
- В режиме `dedicated` требуется реальный приватный маршрут от `cp` к узлу;
  loopback-only `node_port_allow` запрещён. Роль `remnawave_node` проверяет
  mTLS/JWT и активный nftables ACL до публикации API узла.

Пример структуры inventory на синтетических адресах (RFC 5737 / RFC 3849;
`node_api_port`, `node_port_allow` и `base_firewall_source_ports` задаются в
одном слое inventory как единая authority — ниже они показаны как иллюстрация,
а не второй источник):

```yaml
all:
  vars:
    cp_placement: dedicated
    subscription_public_host: sub.example.com
    subscription_public_path: /sub/
  children:
    cp:
      hosts:
        cp-example:
          ansible_host: 203.0.113.30
    exit:
      hosts:
        exit-example:
          ansible_host: 192.0.2.10
          node_api_port: 2223
          node_port_allow:
            - 203.0.113.30/32
            - "2001:db8:30::30/128"
          # плюс ровно одна TCP-запись base_firewall_source_ports с теми же source_cidrs
```

## 3. Доступ к панели

- Панель Remnawave слушает только loopback (`panel_bind`: `127.0.0.1` или
  `::1`, `panel_port`). Публичного admin listener на `cp` нет.
- Перед панелью на `cp` работает роль `panel_proxy`: nginx-vhost только на
  loopback (по умолчанию `127.0.0.1:7443`, без TLS), перезаписывающий
  `X-Forwarded-For` и `X-Forwarded-Proto: https` (см.
  [PANEL_PROXY.md](PANEL_PROXY.md)).
- Использование entrance-узла или private overlay допустимо только как
  транспорта до SSH/управления `cp`; сам overlay этим срезом не реализуется.
- Публичный vhost `cp_proxy` на `cp` проксирует исключительно subscription
  prefix (`subscription_public_path`). Запросы к `/api/`, `/admin/` и любым
  другим путям возвращают `404`.

Вход оператора в панель выполняется только через SSH-туннель к `cp`:

```sh
ssh -L 7443:127.0.0.1:7443 <cp-host>
```

После открытия туннеля интерфейс открывается локально по
`http://127.0.0.1:7443/`.

## 4. Граница DNS и публикации подписки

Единственная authority публикации подписки — пара `subscription_public_host` и
`subscription_public_path` в `group_vars/all.yml` (см.
[DEPLOYMENT.md](DEPLOYMENT.md)). Задавать отдельные
`remnawave_panel_sub_public_domain`, `cp_proxy_server_name`,
`cp_proxy_path_prefix` и `cp_proxy_upstream` в inventory запрещено.

Из authority выводятся:

| Параметр | Выводимое значение | Владелец |
| --- | --- | --- |
| `SUB_PUBLIC_DOMAIN` | `<host><path без завершающего />` (напр. `sub.example.com/sub`) | `remnawave_panel` |
| `server_name` vhost | `<host>` | `cp_proxy` |
| `cp_proxy_path_prefix` | `<path>` | `cp_proxy` |
| `cp_proxy_upstream` | `panel_bind:panel_port` (для IPv6 — `[::1]:port`) | `cp_proxy` |

Контракт границы в режиме `dedicated`:

- И панель, и публичный vhost `cp_proxy` находятся на `cp`; IP-адрес `exit` не
  является входом публикации подписки.
- Внешние записи DNS и выпуск/обновление сертификатов ACME не настраиваются
  Ansible; `cp_proxy_acme*` передаются как явные параметры роли.
- Потеря, блокировка или смена IP-адреса `exit` не меняет subscription state
  (`subscription_public_host`, `subscription_public_path`, `SUB_PUBLIC_DOMAIN`
  и vhost на `cp`).

Разделение проверок:

- **Проверено статически:** единственность authority в валидаторе inventory,
  запрет дублирующих переменных, вывод `SUB_PUBLIC_DOMAIN` и параметров
  `cp_proxy`, выбор `cp`-хоста и инвариант `404` для путей вне prefix.
- **Требует runtime:** переключение реальных DNS-записей на `cp`, выпуск и
  продление ACME-сертификата, проверка реального HTTPS-ответа на subscription
  prefix и `404` на `/api/` и `/admin/` через работающий nginx.

## 5. Backup и restore runbook для `cp`

Детальный контракт резервного копирования описан в [BACKUP.md](BACKUP.md).
В режиме `dedicated`:

- `ansible/playbooks/backup.yml` по умолчанию выбирает panel-хост по placement
  — в `dedicated` это `cp` (с проверкой через `require_panel_host.yml`).
- Роль `cp_backup` запускает `pg_dump --format=custom` внутри контейнера
  PostgreSQL панели, шифрует дамп `age`, проверяет шифротекст и сохраняет
  артефакты `cp-backup-<UTC>.pgcustom.age` в `/var/lib/cp-backup` на `cp` с
  ротацией по таймеру `cp-backup.timer`.
- Потеря или недоступность `exit` не блокирует доступ к панели на `cp`,
  выполнение резервного копирования и чтение артефактов на `cp`. Копирование
  артефактов вне сервера (offsite) остаётся отдельной задачей.
- Приватная age identity (`AGE-SECRET-KEY-…`) хранится только у оператора вне
  сервера и вне Git; на `cp` размещается только файл публичных получателей,
  расположенный вне Git-клона.

Установка резервного копирования на `cp` (пути вне Git):

```sh
.venv/bin/ansible-playbook -i /путь/к/приватному/inventory/hosts.yml \
  ansible/playbooks/backup.yml \
  -e cp_backup_recipients_file=/путь/вне/git/recipients.txt
```

Учебное восстановление выполняется `ansible/playbooks/restore.yml` **только** в
новую/одноразовую базу данных. Плейбук требует `-e cp_restore_confirm=true` и
отказывается работать с контейнером PostgreSQL живого compose-проекта панели
(`remnawave`) или уже существующей базой без явного `-e cp_restore_replace=true`:

```sh
.venv/bin/ansible-playbook -i /путь/к/приватному/inventory/hosts.yml \
  ansible/playbooks/restore.yml \
  -e cp_restore_hosts=<хост-учений> \
  -e cp_restore_confirm=true \
  -e cp_restore_artifact_src=/путь/вне/git/cp-backup-YYYYmmddTHHMMSSZ.pgcustom.age \
  -e cp_restore_identity_file=/путь/вне/git/identity.txt \
  -e cp_restore_container=<одноразовый-postgres> \
  -e cp_restore_db_name=panel_restore
```

## 6. Runbook миграции `exit -> dedicated`

**В этом issue реальный перенос не выполнялся.** Ниже приведена плановая
процедура для отдельного runtime-окна после подтверждения владельца.

### Preflight

1. Снять свежую проверенную резервную копию PostgreSQL панели на `exit`,
   забрать зашифрованный артефакт на управляющую машину и выполнить пробное
   восстановление в disposable БД через `restore.yml`.
2. Подготовить приватный inventory вне Git: выделить новый `cp`-хост в группе
   `cp`, указать `cp_placement: dedicated`, задать `node_api_port`,
   `node_port_allow` и единственную TCP-запись `base_firewall_source_ports` для
   приватного пути от `cp` к узлу.
3. Проверить key-only SSH-доступ, права `sudo`, наличие секретов панели/узла и
   файла получателей age вне Git-клона.
4. Проверить согласованность приватного inventory локальным валидатором
   (`make -C ansible state STATE_INVENTORY=/путь/к/приватному/inventory/hosts.yml`).

### Staging `cp`, изменение `cp_placement` и порядок применения

1. Заморозить изменения в панели на `exit` на время переноса, чтобы не
   потерять записи БД.
2. Применить `bootstrap.yml` к новому `cp`-хосту (hardening SSH/firewall,
   Docker, приватная панель Remnawave на loopback).
3. Остановить контейнер приложения панели на `cp` (оставив контейнер
   PostgreSQL запущенным), остановить запись в старую панель на `exit` и снять
   финальный дамп с `exit`; восстановить артефакт в PostgreSQL на `cp` (в
   новую БД для проверки, либо выполнить осознанную замену целевой БД панели
   при остановленном контейнере панели с явными `cp_restore_confirm=true` и
   `cp_restore_replace=true`, никогда не восстанавливая в живую работающую БД),
   проверить целостность данных и только затем запустить панель на
   восстановленной БД.
4. Применить обновлённую политику firewall (`base_firewall_source_ports`) на
   `exit` и остальных узлах, чтобы открыть `node_api_port` строго для
   приватного адреса `cp`, и затем применить `remnawave_node.yml` с
   `cp_placement: dedicated` для проверки mTLS/JWT и активного nftables ACL.
5. Применить на `cp` `panel_proxy.yml` и `backup.yml`. Если используется
   готовый сертификат оператора (`cp_proxy_acme: false`), применить
   `cp_proxy.yml` на этом шаге; при выпуске сертификата через ACME
   (`cp_proxy_acme: true`) применение `cp_proxy.yml` выполняется после
   переключения DNS на `cp` на шаге Cutover.

### Проверки перед cutover

- Панель: `ssh -L 7443:127.0.0.1:7443 <cp-host>` открывает интерфейс на
  `http://127.0.0.1:7443/`; данные совпадают с перенесённым снимком; публичного
  admin listener нет; если `cp_proxy` уже применён с готовым сертификатом,
  он отдаёт `404` на `/api/` и `/admin/`.
- Узел: панель на `cp` управляет `remnawave_node` по `node_api_port` через
  приватный маршрут; активный nft ACL разрешает только `node_port_allow`, порт
  отсутствует в `base_firewall_vpn_ports`.
- Бэкап: разовый запуск `systemctl start cp-backup.service` на `cp` проходит
  без ошибок и создаёт проверенный артефакт в `/var/lib/cp-backup`.

### Cutover

1. Во внешнем DNS (вне Ansible) перевести `subscription_public_host` на адрес
   `cp`; при режиме ACME применить `cp_proxy.yml` на `cp` и подтвердить
   наличие действующего сертификата и ответ `404` на `/api/` и `/admin/`.
2. Проверить получение подписки клиентом по публичному HTTPS URL.
3. Только после подтверждения работы отключить `cp-backup.timer` и остановить
   старую панель/`cp_proxy` на `exit`; прежние артефакты бэкапов не удалять.

### Rollback triggers

Немедленный откат на `exit` выполняется при любом из условий:

- сбой восстановления БД или расхождение состояния панели на `cp`;
- невозможность управления `remnawave_node` с `cp` (ошибка маршрута, mTLS/JWT
  или nftables ACL);
- публичная доступность admin-интерфейса либо ошибки TLS/подписки после DNS
  cutover;
- отказ резервного копирования `cp_backup` на `cp`.

## 7. Откат `dedicated -> exit`

1. Прекратить изменения в панели на `cp`, при необходимости снять финальный
   зашифрованный дамп с `cp`, затем отключить `cp-backup.timer` и остановить
   панель, `panel_proxy` и `cp_proxy` на `cp`, чтобы не оставлять второй
   активный control plane (артефакты и логи на `cp` не удалять).
2. Вернуть приватный inventory к `cp_placement: exit` (очистить группу `cp`,
   восстановить прежние `node_port_allow` и `base_firewall_source_ports` для
   размещения панели на `exit`), при необходимости откатить ревизию ролей и
   проверить inventory локальным валидатором (`make -C ansible state`
   `STATE_INVENTORY=/путь/к/приватному/inventory/hosts.yml`).
3. При необходимости восстановления БД на `exit` убедиться, что контейнер
   PostgreSQL на `exit` запущен, а контейнер приложения панели остановлен, и
   восстановить согласованное состояние БД (с явным `cp_restore_confirm=true`;
   флаг `cp_restore_replace=true` допустим только при осознанной замене
   существующей БД при остановленном контейнере панели).
4. Применить возвращённую политику firewall (`base_firewall_source_ports`) на
   `exit` и остальных узлах, затем применить `remnawave_panel.yml` (или
   `bootstrap.yml`), `remnawave_node.yml`, `panel_proxy.yml` и `backup.yml`;
   вернуть внешний DNS `subscription_public_host` на `exit` (вне Ansible) и
   применить `cp_proxy.yml` на `exit`.
5. Проверить вход в панель на `exit` через `ssh -L`, управление узлом,
   subscription endpoint (`200` на prefix, `404` на `/api/` и `/admin/`) и
   выполнение `cp-backup.service`.
6. **Артефакты резервных копий (`/var/lib/cp-backup`) и журналы на `cp` и
   `exit` не удалять** — они сохраняются для разбора инцидента.

## 8. Матрица проверок и «Что не проверено»

| Область проверки | Команда / источник | Статус |
| --- | --- | --- |
| Валидация inventory (`cp_placement`, authority, ACL) и offline-тесты Ansible | `make -C ansible validate test` | Статическая / offline проверка |
| Общие проверки репозитория (линтеры и тесты) | `make check` | Статическая / offline проверка |
| Учебный цикл `cp_backup` и `restore.yml` на disposable PostgreSQL | `ansible/roles/cp_backup/tests/drill.sh` | Отдельный контейнерный drill роли `cp_backup` (см. `BACKUP.md`, без живой панели и systemd PID 1; в этом срезе не запускался) |
| Перенос `exit -> dedicated`, DNS/ACME, node management, exit outage | Runtime acceptance на чистом одноразовом стенде | **Не проверено** |

### Что не проверено

Статические проверки и контейнерные учения **не доказывают** runtime acceptance;
следующие сценарии остаются непроверенными:

- реальный перенос control plane с `exit` на `cp` и production cutover;
- переключение внешнего DNS и выпуск/обновление сертификатов ACME на `cp`;
- доступ к `cp` через entrance или private overlay транспорт;
- учения по отказу или блокировке `exit` (exit outage drill) с проверкой
  сохранности панели, бэкапов и публикации подписки на `cp`;
- восстановление через `restore.yml` на реальном PostgreSQL живого стека
  Remnawave;
- управление `remnawave_node` с реального отдельного `cp`-хоста (проверка
  реальных mTLS/JWT и правил nftables ACL в работе).
