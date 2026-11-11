# node_exporter: роль Ansible

Документ описывает задачу 1.4 [архитектурного плана](ARCHITECTURE_PLAN.md):
роль `node_exporter` и playbook для её применения. **Роль не развёрнута ни на
одном рабочем сервере.** Её наличие в репозитории не означает, что мониторинг
работает: Prometheus, Grafana и VictoriaMetrics здесь не устанавливаются.

## Что делает роль

| Действие | Подробности |
| --- | --- |
| Проверка до изменений | Адрес и порт прослушивания, ОС Linux, systemd, архитектура `x86_64` или `aarch64`. При несоответствии роль завершается ошибкой, ничего не изменив. |
| Учётная запись | Системные группа и пользователь `node_exporter`, shell `/usr/sbin/nologin`, домашний каталог `/nonexistent` не создаётся. |
| Установка | Официальный архив релиза скачивается с GitHub `prometheus/node_exporter` в `/opt/node_exporter/` и проверяется по закреплённому SHA256, затем распаковывается в `/opt/node_exporter/node_exporter-<версия>.linux-<arch>/`. Файлы принадлежат `root`. |
| Сервис | `/etc/systemd/system/node_exporter.service`: запуск от `node_exporter`, без capabilities, с `NoNewPrivileges` и ограничениями `Protect*`/`Restrict*`. Сервис включается и запускается; перезапуск — только при изменении unit-файла (версия, адрес, порт). |

Роль не меняет правила firewall, sysctl, SSH, пакеты и другие сервисы и не
открывает дополнительных слушающих сокетов: node_exporter слушает ровно один
адрес. Дополнительные коллекторы и textfile-метрики не включаются.

## Версия и контрольные суммы

Версия закреплена в `ansible/roles/node_exporter/vars/main.yml`:
**node_exporter 1.12.1**. SHA256 взяты из официального
[`sha256sums.txt`](https://github.com/prometheus/node_exporter/releases/download/v1.12.1/sha256sums.txt)
релиза:

| Архитектура | Архив | SHA256 |
| --- | --- | --- |
| `x86_64` | `node_exporter-1.12.1.linux-amd64.tar.gz` | `b51d8a76aa2a9156a55d501aca6276fae09e262259a5e4e831d2c2222f084e63` |
| `aarch64` | `node_exporter-1.12.1.linux-arm64.tar.gz` | `ad35b605f9954b9f1ffddf5ba054bdc5a98d790b9eae5291e1eeb83f1ecbd0e7` |

Версия и суммы находятся в `vars/`, а не в `defaults/`: их нельзя случайно
переопределить из inventory. Обновление версии — отдельный PR, меняющий версию и
все суммы вместе. Если загруженный архив не совпадает с суммой, `get_url`
завершается ошибкой, и сервис не меняется.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `node_exporter_listen_address` | `127.0.0.1` | Литеральный IPv4- или IPv6-адрес без скобок, порта и zone index, например `127.0.0.1`, `::1`, `2001:db8::10`. |
| `node_exporter_listen_port` | `9100` | TCP-порт, 1–65535. |

Отклоняются: имена хостов, `0.0.0.0`, `::` и multicast-адреса (они открыли бы
exporter на всех интерфейсах или некорректны), а также адреса, не назначенные
хосту и не являющиеся loopback. IPv6 рендерится как `[адрес]:порт`.
Переменные можно задать в `host_vars`/`group_vars` рабочего inventory или через
`-e`; пример inventory этой ролью не изменяется.

## Сетевой доступ

- По умолчанию exporter доступен только локально (`127.0.0.1:9100`). Метрики
  содержат сведения о системе (ядро, интерфейсы, файловые системы, нагрузка);
  не публикуйте их и не добавляйте выгрузки метрик в Git.
- Не-loopback адрес нужен, чтобы CP мог собирать метрики. **Эта роль никогда не
  меняет firewall.** Доступ к порту 9100 на не-loopback адресе должен быть
  разрешён только с IP CP отдельным firewall роли `base` (задача 1.2 плана).
  Роль `base` в репозитории пока не реализована: до её появления и проверки
  правил на конкретном узле не задавайте не-loopback адрес.
- Нужен исходящий HTTPS с узла до `github.com` и его CDN для загрузки архива.

## Запуск

Команды выполняются из каталога `ansible/` после `make -C ansible bootstrap`.
Playbook подключает роль по пути `../roles/node_exporter`, поэтому
`ANSIBLE_ROLES_PATH` задавать не нужно. Playbook нацелен на `hosts: all`;
ограничивайте узлы через `--limit`.

```sh
# Синтаксис (без подключения к узлам):
../.venv/bin/ansible-playbook --syntax-check playbooks/node_exporter.yml

# Предварительный просмотр изменений на выбранном узле:
../.venv/bin/ansible-playbook -i <inventory> --limit <хост> --check --diff \
  playbooks/node_exporter.yml

# Применение:
../.venv/bin/ansible-playbook -i <inventory> --limit <хост> playbooks/node_exporter.yml
```

В check mode на новом узле архив не загружается, распаковка и запуск сервиса
пропускаются: unit ещё не существует. Применение к рабочим узлам требует
отдельного явного разрешения владельца (см. [AGENTS.md](../AGENTS.md)).

## Проверка на узле

```sh
systemctl is-active node_exporter.service
systemctl show --property=User,MainPID node_exporter.service
ss -Hltn 'sport = :9100'
curl -fsS http://127.0.0.1:9100/metrics | grep '^node_exporter_build_info'
/opt/node_exporter/node_exporter-1.12.1.linux-amd64/node_exporter --version
```

Ожидается: сервис `active`, пользователь `node_exporter`, ровно один сокет на
настроенном адресе, `version="1.12.1"` в `node_exporter_build_info`. Повторный
запуск playbook должен завершаться с `changed=0`.

## CI

Workflow [`.github/workflows/node-exporter.yml`](../.github/workflows/node-exporter.yml)
(job `node_exporter role`) запускается для pull request и push в `master`, с
правами `contents: read` и без secrets. На одноразовом runner `ubuntu-24.04` с
systemd он проверяет синтаксис, отказ для `0.0.0.0` до изменений, check mode на
чистой системе, установку, повторный запуск с `changed=0`, checksum архива по
официальному `sha256sums.txt`, версию, состояние сервиса, отсутствие
capabilities у процесса, единственный сокет `127.0.0.1:9100`, сбор метрик, а
затем то же для явного адреса `::1`. Job не входит в обязательные проверки
`Repository checks` и `Secret scan`.

## Откат

- **Репозиторий.** Отдельный PR с revert squash-коммита этой задачи; `master` не
  переписывается.
- **Версия на узле.** Revert изменения версии и повторный запуск playbook:
  unit снова указывает на каталог прежней версии, сервис перезапускается.
  Каталог прежней версии остаётся в `/opt/node_exporter/`, пока его не удалят.
- **Адрес на узле.** Вернуть `node_exporter_listen_address` к `127.0.0.1` (или
  удалить переопределение) и запустить playbook; правила firewall роли `base`
  откатываются отдельно по её процедуре.
- **Полное удаление с узла** (вручную, роль этого не делает):

  ```sh
  systemctl disable --now node_exporter.service
  rm /etc/systemd/system/node_exporter.service
  systemctl daemon-reload
  rm -r /opt/node_exporter
  userdel node_exporter
  groupdel node_exporter  # если группа не удалена вместе с пользователем
  ```

  Затем проверьте, что `ss -Hltn 'sport = :9100'` ничего не выводит.

Описанный откат не выполнялся на рабочих узлах; после любого отката проверяйте
результат командами из раздела «Проверка на узле».
