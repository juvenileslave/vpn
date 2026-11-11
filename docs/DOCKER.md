# Ansible: роль `docker`

Документ описывает задачу 1.3 [архитектурного плана](ARCHITECTURE_PLAN.md):
роль `ansible/roles/docker` и playbook `ansible/playbooks/docker.yml`. Роль
устанавливает Docker Engine из официального подписанного apt-репозитория Docker.
**Наличие роли не означает, что Docker где-либо установлен**: playbook не
запускается автоматически, CI его не применяет, VPN-контейнеры и приложения роль
не запускает.

## Что делает роль

1. **Preflight (только чтение, до любых изменений).** Проверяет платформу,
   параметры логирования, установленные пакеты, apt-источники и `daemon.json`;
   при проблеме завершается с понятным сообщением, ничего не меняя.
2. **Репозиторий.** Кладёт открытый ключ Docker в `/etc/apt/keyrings/docker.asc`
   и источник deb822 `/etc/apt/sources.list.d/docker.sources`
   (`Signed-By` указывает на этот ключ). Ключ хранится в роли
   (`roles/docker/files/docker.asc`) — копия `https://download.docker.com/linux/{ubuntu,debian}/gpg`,
   отпечаток `9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88`. Скрипты
   `curl | sh` и `get.docker.com` не используются.
3. **Пакеты.** Устанавливает точные версии `docker-ce`, `docker-ce-cli`,
   `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin`. Полная
   версия собирается как `<версия>~<дистрибутив>.<релиз>~<codename>`, например
   `5:29.9.3-1~ubuntu.24.04~noble`, и перед установкой проверяется по
   `apt-cache madison`: если такой версии в официальном репозитории нет, роль
   завершается ошибкой, а не подбирает другую. apt-кэш обновляется только при
   изменении ключа/источника или если закреплённых версий нет в кэше.
   Recommends не ставятся (иначе приходит незакреплённый
   `docker-ce-rootless-extras`); обязательные зависимости (например, `iptables`)
   устанавливает apt.
4. **`daemon.json`.** Роль владеет только ключами `log-driver` и `log-opts`;
   остальные ключи сохраняются. Кандидат сравнивается с текущим содержимым как
   JSON: если значения совпадают, файл не трогается (форматирование тоже).
   Иначе кандидат проверяется `dockerd --validate`, записывается с проверкой той
   же командой на временном файле (`copy validate`) и с резервной копией
   `daemon.json.<pid>.<дата>~` рядом.
5. **Служба.** `docker.service` включается и запускается; перезапуск — только
   handler'ом при записи `daemon.json`. Затем `docker info` подтверждает версию
   демона и драйвер логирования.

Роль не открывает Docker API по TCP, не добавляет пользователей в группу
`docker` (это равносильно root), не запускает контейнеры, не меняет SSH и не
удаляет пакеты, данные `/var/lib/docker` или существующие конфигурации.

## Поддерживаемые платформы

Только хосты с systemd. Список совпадает с релизами, для которых официальный
репозиторий публикует все закреплённые пакеты (проверено по индексам
`download.docker.com` на 2026-11-11):

| Дистрибутив | Релиз | Суффикс версии |
| --- | --- | --- |
| Ubuntu | 22.04 `jammy` | `~ubuntu.22.04~jammy` |
| Ubuntu | 24.04 `noble` | `~ubuntu.24.04~noble` |
| Ubuntu | 26.04 `resolute` | `~ubuntu.26.04~resolute` |
| Debian | 12 `bookworm` | `~debian.12~bookworm` |
| Debian | 13 `trixie` | `~debian.13~trixie` |

| `ansible_architecture` | Архитектура apt |
| --- | --- |
| `x86_64` | `amd64` |
| `aarch64` | `arm64` |

Другие платформы отклоняются первой задачей preflight. Для проверки режима
`--check` на хосте должен быть установлен `python3-apt` (требование модуля
`ansible.builtin.apt`; в обычном режиме модуль ставит его сам).

## Обнаружение существующей установки

Роль останавливается и сообщает о проблеме, ничего не исправляя сама, если:

- установлены конфликтующие пакеты дистрибутива: `docker.io`, `docker-compose`,
  `docker-compose-v2`, `docker-doc`, `podman-docker`, `containerd`, `runc`;
- Docker установлен из snap (`/snap/bin/docker`);
- `download.docker.com` уже подключён в другом файле apt (например, старый
  `docker.list` с другим `Signed-By` ломает `apt update`);
- установленные пакеты Docker имеют другую версию, чем закреплённая, а
  `docker_allow_version_change` не включён;
- `daemon.json` не является корректным JSON-объектом;
- `daemon.json` содержит `hosts` с `tcp://`.

Миграцию такого хоста выполняет оператор вручную, по отдельному согласованию.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `docker_package_versions` | см. ниже | Точные версии пакетов без суффикса дистрибутива. Задаётся целиком: словари в Ansible заменяются, а не сливаются. |
| `docker_allow_version_change` | `false` | Разрешить обновление или откат уже установленных пакетов Docker (`allow_downgrade`). |
| `docker_log_driver` | `local` | Драйвер логов по умолчанию: `local` или `json-file`. |
| `docker_log_opts` | `{max-size: "10m", max-file: "3"}` | Параметры драйвера; `max-size` и `max-file` обязательны, `compress` — необязательный. Значения записываются строками. |

Версии по умолчанию:

```yaml
docker_package_versions:
  docker-ce: "5:29.9.3-1"
  docker-ce-cli: "5:29.9.3-1"
  containerd.io: "2.4.2-3"
  docker-buildx-plugin: "0.38.1-1"
  docker-compose-plugin: "5.7.0-1"
```

Типы и допустимые значения проверяются `meta/argument_specs.yml` до выполнения
задач. Внутренние параметры (пути, список платформ, конфликтующие пакеты)
находятся в `roles/docker/vars/main.yml` и не предназначены для переопределения.

Ограничение логов действует для контейнеров, созданных после применения;
существующие контейнеры сохраняют драйвер, с которым были созданы.

## Запуск

Команды выполняются из каталога `ansible/` с общей `.venv`
(`make -C ansible bootstrap`). Цель задаётся явно через `docker_target_hosts`:
значения по умолчанию нет, без неё playbook завершается ошибкой.

```sh
cd ansible
# Проверка синтаксиса на example inventory, без подключения к узлам.
../.venv/bin/ansible-playbook --syntax-check -e docker_target_hosts=relay playbooks/docker.yml
# Предварительный просмотр на одноразовом тестовом хосте.
../.venv/bin/ansible-playbook -i <inventory> -e docker_target_hosts=<host> --check --diff playbooks/docker.yml
# Применение.
../.venv/bin/ansible-playbook -i <inventory> -e docker_target_hosts=<host> --diff playbooks/docker.yml
```

Роль подключается по относительному пути `../roles/docker` от каталога
playbook; `ansible.cfg` не меняется. Применение к рабочим серверам требует
отдельного явного разрешения владельца (см. [AGENTS.md](../AGENTS.md)).

### Режим `--check --diff`

Preflight, чтение apt-кэша и проверка кандидата `dockerd --validate` (через
stdin) выполняются и в check mode: они только читают состояние. Если репозиторий
ещё не подключён или закреплённых версий нет в кэше, роль печатает сообщение,
что установка пакетов не предсказана, а не изображает успех. Если `dockerd` ещё
не установлен, проверка кандидата откладывается до реального запуска, о чём
также выводится сообщение. Проверка `docker info` в check mode не выполняется.

## Влияние на хост

- **Перезапуск Docker** при изменении `log-driver`/`log-opts` останавливает
  контейнеры (если в `daemon.json` нет `"live-restore": true`); контейнеры с
  политикой restart поднимаются снова. На свежем хосте пакет сам запускает
  Docker с настройками по умолчанию, после чего роль один раз перезапускает его
  с новым `daemon.json`.
- **Сеть и firewall.** Сама роль правила firewall не меняет, но запущенный
  Docker Engine по умолчанию создаёт свои цепочки iptables/nftables,
  включает IP forwarding и выставляет политику `FORWARD` в `DROP`. Роль эти
  настройки Docker не переопределяет. Совместимость с правилами роли `base`
  (задача 1.2) нужно проверить до применения на exit (задача 1.5).

## Откат

- **Репозиторий:** отдельный PR, отменяющий squash-коммит роли; история
  `master` не переписывается. Отмена коммита не меняет уже настроенные хосты.
- **`daemon.json`:** восстановить предыдущую версию из резервной копии
  `/etc/docker/daemon.json.<pid>.<дата>~`, проверить её
  `dockerd --validate --config-file /etc/docker/daemon.json` и выполнить
  `systemctl restart docker` (с теми же последствиями для контейнеров). Если
  файла до роли не было — удалить его и перезапустить Docker.
- **Версии пакетов:** указать прежние версии в `docker_package_versions` и
  запустить playbook с `-e docker_allow_version_change=true`.
- **Полное удаление** (только вручную, по отдельному решению):
  `apt-get remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin`,
  затем удалить `/etc/apt/sources.list.d/docker.sources` и
  `/etc/apt/keyrings/docker.asc`, выполнить `apt-get update`. Образы, тома и
  контейнеры в `/var/lib/docker` и `/var/lib/containerd` при этом остаются;
  их удаление необратимо и в откат не входит.

Описанный откат не выполнялся; после отката проверьте `systemctl status docker`
и `docker info`.
