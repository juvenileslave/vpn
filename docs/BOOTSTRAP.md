# Bootstrap чистого хоста до приватной панели

`ansible/playbooks/bootstrap.yml` — один guarded entrypoint для чистых
Debian/Ubuntu systemd-хостов: первоначальный SSH-доступ `root` (ключ или
интерактивно введённый пароль) → Linux-администратор через роль `base` →
**новое** key-only SSH-подключение с проверкой UID и `sudo -n` → существующие
контракты SSH-hardening и firewall → Docker → приватная панель Remnawave на
правильном control-plane хосте. Playbook переиспользует роли `base`, `docker` и
`remnawave_panel`; роль `bootstrap` добавляет только отсутствующую подготовку
минимального хоста и gates переподключения.

Это не развёрнутый VPN и не доказательство готовности подписок. Playbook не
создаёт учётную запись администратора Remnawave, VPN-подписки, RemnaNode, cover,
profiles, метрики, бота, DNS или публичный HTTPS. `docs/ARCHITECTURE_PLAN.md` не
изменяется.

## Предпосылки

Управляющая машина:

- Python 3.11+ и `make -C ansible bootstrap` (закреплённый `ansible-core`
  2.19.15);
- OpenSSH client (`ssh`, `ssh-keygen`), `ssh` умеет проверить host key;
- приватный inventory — только в ignored `ansible/inventories/production/` (или
  вне checkout), файл секретов панели и приватный ключ администратора — **строго
  вне checkout**. Учётные данные не коммитятся и не передаются через `-e` в
  командной строке.

Целевой хост:

- чистый Debian/Ubuntu с systemd и `apt`; на минимальном образе playbook сам
  доставляет только отсутствующие `python3`, `sudo` и `python3-apt` (без
  upgrade/removal). Целевой минимальный образ — Ubuntu 24.04; полный runtime
  bootstrap в этой задаче не запускался;
- SSH-доступ `root` по ключу или по паролю (если `sshd` разрешает пароль);
- host key уже известен управляющей машине явным образом. Неизвестный или
  неверный host key не принимается автоматически: playbook останавливается.
  Не отключайте `StrictHostKeyChecking` и не направляйте `UserKnownHostsFile`
  в `/dev/null` в `ansible_ssh_common_args` или `~/.ssh/config`; сначала
  примите host key отдельной проверенной командой (`ssh-keyscan` — только
  синтетический стенд);
- gate использует `ssh -F /dev/null`: `ansible_host` должен разрешаться без
  `Host`-алиасов из `~/.ssh/config`, а `ProxyJump`/`ProxyCommand` и
  `UserKnownHostsFile` задаются в `ansible_ssh_common_args`. Иначе gate честно
  откажет, а не будет угадывать адрес;
- нет активного UFW/firewalld и незаявленных публичных listeners, которые
  `base` отказался бы закрывать. Эти отказы — явный контракт, а не повод
  отключать чужую службу или пропускать security.

## Одна команда

Для корректно заполненного приватного inventory/vars:

```sh
cd ansible
../.venv/bin/ansible-playbook -i inventories/production/hosts.yml \
  playbooks/bootstrap.yml --ask-pass
```

`--ask-pass` нужен только для первого входа под `root` паролем. Если root
доступен по ключу, тот же запуск выполняется без `--ask-pass`; тогда стандартные
connection-переменные inventory (`ansible_ssh_private_key_file` или ssh config)
должны давать **root-ключ**. После gate используется только
`bootstrap_admin_private_key_file`; root-ключ для администратора не нужен.
Пароль root вводится интерактивно и не попадает в argv, facts, вывод задач или
файлы. Администраторские фазы всегда идут ключом: пароль root для нового
администратора не используется.

## Обязательный input

| Переменная | Контракт |
| --- | --- |
| `base_admin_users` | Список `{name, sudo, authorized_keys}` по контракту роли `base`; выбранный администратор обязан иметь `sudo: true` и непустой ключ. |
| `bootstrap_admin_name` | Имя выбранного администратора из `base_admin_users`. При единственной записи выводится автоматически; при нескольких задайте явно. |
| `bootstrap_admin_private_key_file` | Абсолютный путь на управляющей машине, **вне репозитория**, к нешифрованному приватному ключу OpenSSH с режимом `0600`/`0400`. Его публичная часть должна совпадать с одним из `authorized_keys` выбранного администратора. |
| `base_ssh_enabled` | Обязательно `true`: иначе bootstrap не применял бы hardening. |
| `base_firewall_enabled` | Обязательно `true`. |
| `base_ssh_permit_root_login` | Обязательно `no`: повторный запуск идёт администратором, root обратно не включается. |
| `base_ssh_trusted_cidrs` | Непустой список безопасных CIDR по контракту `base`; текущий SSH-клиент проверяется ролью до firewall. |
| `base_ssh_port` | Должен совпадать с `ansible_port` (по умолчанию 22); роль не меняет порт sshd. |
| `cp_placement` | `dedicated` (один отдельный cp-хост) или `exit` (панель на exit, cp-группа пуста); ровно один `exit` и один `relay`, хост не в двух группах. |
| `image_tags.remnawave_panel`, `image_tags.postgres`, `image_tags.valkey` | Точные пины по контракту роли панели; `latest` и отсутствие пина отклоняются до изменений. |
| `panel_bind` / `panel_port` | Только loopback-адрес; порт не должен совпадать с 5432, 6379 или SSH-портом. |
| `remnawave_panel_sub_public_domain` / `remnawave_panel_front_end_domain` | Несекретные домены по контракту роли панели; DNS не настраивается. |
| `remnawave_panel_env_file` **или** `remnawave_panel_env` | Ровно один источник секретов. Файл — абсолютный путь вне checkout; значения проверяются до запуска панели. |

`base_admin_sudo_nopasswd` должен оставаться `true`: у созданных
администраторов нет пароля, а gate проверяет `sudo -n`. `base_admin_shell` по
умолчанию `/bin/bash`; gate использует обычную неинтерактивную команду.

`base_chrony_enabled` по умолчанию `true`; на стоковом Ubuntu с
`systemd-timesyncd` роль `base` **откажется** удалять чужую службу времени.
Разрешите конфликт вручную либо явно задайте `base_chrony_enabled: false`
(распределительная служба времени остаётся). Молчаливого удаления или
пропуска security в playbook нет. То же относится к UFW/firewalld,
chrony/systemd-timesyncd и незаявленным listeners: отказ останавливает запуск.

Синтетический `ansible/inventories/example/` не является bootstrap-ready: в нём
нет администратора, hardening-переключателей, panel-пинов/доменов и секретов.

## Порядок и gates

1. **Controller-only validation** (`connection: local`): SSH-опции inventory,
   `base_admin_users`, выбранный администратор и ключ, hardening-контракт,
   topology/`cp_placement`, приватный ключ вне репозитория и совпадение с
   `authorized_keys`; затем валидатор роли панели проверяет пины, домены и
   источник секретов. Неверный ввод завершает запуск до первого SSH-подключения.
2. **Первоначальный доступ** (`serial: 1`): root-доступ проверяется реальным
   соединением. Если он доступен, `bootstrap` доставляет отсутствующие
   prerequisites, собирает facts и применяет `base` с **выключенными**
   управлением SSH и firewall: создаются администратор, ключи и sudoers, старый
   root-доступ не закрывается. Если root уже закрыт, эта фаза пропускается; это
   не PASS, а rerun-путь.
3. **Gate нового доступа**: отдельный процесс `ssh` с `-F /dev/null` предлагает
   ровно объявленный ключ, проверяет host key, получает `id -un`/`id -u` и
   выполняет `sudo -n true`. Успех `become` под root, локальный
   `authorized_keys` или старая сессия доказательством не считаются. При отказе
   root остаётся открыт, hardening и панель не применяются.
4. **Hardening/firewall**: только после gate play подключается администратором
   (`BatchMode`, `IdentitiesOnly`, `PreferredAuthentications=publickey`) и
   применяет `base` с объявленными `base_ssh_*`/`base_firewall_*` контрактами.
   Внутри роли пользователи/ключи/sudoers сходятся до SSH и firewall. Затем тот
   же новый key-only gate повторяется уже под hardened-политикой.
5. **Docker**: роль `docker` ставит закреплённые пакеты на все inventory-хосты.
6. **Панель**: роль `remnawave_panel` применяется ровно на выбранном
   control-plane хосте (`exit` или dedicated `cp`). После запуска проверяются
   реальные loopback-listeners, отсутствие host-портов PostgreSQL/Valkey и
   HTTP 200 приватного endpoint с forwarded-заголовками. Завершение `apt` или
   Compose само по себе не считается готовностью.
7. **Secret-safe status**: выводится имя Linux-администратора, panel host/порт,
   команда SSH-туннеля и явное отделение будущей учётной записи Remnawave.

Любая реальная ошибка при `serial: 1` останавливает опасные следующие шаги.
Непригодный существующий хост (root закрыт, но объявленный ключ/sudo не
работает) завершает запуск ошибкой; фиктивного fallback нет.

## Повторный запуск

Повторный запуск — та же команда. Root-вход уже закрыт политикой
`base_ssh_permit_root_login: no`; playbook видит недоступность root, продолжает
через объявленный администратор и проверяет его ключ и `sudo -n`. Root обратно
не включается. Повторный запуск не меняет ключи/пользователей/настройки без
изменения input и не перезапускает панель: `changed=0` для base, Docker и
панели, контейнеры и `panel.env` сохраняются.

Смена bootstrap-ключа при уже закрытом root требует, чтобы новый ключ был
заранее установлен администратору, или отдельного доступа к хосту: playbook
проверяет ровно объявленный ключ и не откатывается к root/паролю. Это осознанный
отказ, а не fallback.

## Безопасность секретов

- Root-пароль: только интерактивный `--ask-pass`; не задавайте его через `-e`,
  inventory, `ANSIBLE_*` в публичной среде или логи.
- Приватный ключ администратора: файл вне репозитория, `0600`/`0400`, без
  парольной фразы (иначе неинтерактивная проверка невозможна). Содержимое
  ключа не читается Ansible и не печатается; задача `ssh-keygen` идёт с
  `no_log`.
- Секреты панели: файл вне checkout, режим `0600`; роль панели использует
  `no_log`/`diff: false`, сообщения называют только ключи. Значения не входят в
  `compose.yaml`.
- Итоговый отчёт содержит только несекретные имена, адреса, порты и команду
  туннеля. Не публикуйте приватный inventory, пути и вывод в issues/PR.

## Ограничения `--check`

`--check` не меняет хост и не выдаёт PASS за невыполненную runtime-проверку:

- на минимальном хосте без `python3`/`sudo`/`python3-apt` playbook не
  устанавливает их в check mode, а явно отказывает: сначала нужен реальный
  запуск. Это ограничение, а не успех;
- новые SSH-gate и приватный HTTP-gate выполняются реально (read-only) и в
  check mode. На уже подготовленном и запущенном хосте они подтверждают
  идемпотентность; на свежем хосте панель не запущена, поэтому gate честно
  падает, а не объявляет готовность;
- роли `base`, `docker` и `remnawave_panel` в check mode проверяют ввод,
  рендер и diff, но не выполняют установку/Compose. Firewall-проверка `base`
  требует уже установленный `nft`.

## Доступ к панели

Панель, PostgreSQL и Valkey не публикуются. Панель слушает только loopback;
host-портов 5432/6379 нет. Туннель:

```sh
ssh -N -L 3000:127.0.0.1:3000 <linux-admin>@<cp-host>
# проверка приватного endpoint с заголовками, которые требует панель:
curl -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' \
  http://127.0.0.1:3000/
```

Браузерный UI требует loopback-эндпоинт роли `panel_proxy` (отдельная задача;
bootstrap её не устанавливает). Bootstrap доказывает приватный loopback-HTTP
endpoint с forwarded-заголовками, а не публичный HTTPS/DNS и не готовность
подписок. Linux-администратор — не учётная запись Remnawave; последняя в этой
задаче не создаётся.

## Проверка

```sh
# синтаксис на синтетическом inventory
cd ansible && ../.venv/bin/ansible-playbook \
  -i inventories/example/hosts.yml playbooks/bootstrap.yml --syntax-check

# unit-тесты фильтров bootstrap (без хоста)
.venv/bin/python -m unittest discover -s ansible/roles/bootstrap/tests -v

# guarded runtime: только явно выделенный одноразовый GitHub-hosted Linux guest
sudo VPN_BOOTSTRAP_DISPOSABLE_GUEST=yes \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  bash ansible/roles/bootstrap/tests/runtime_vm.sh key
sudo VPN_BOOTSTRAP_DISPOSABLE_GUEST=yes \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  bash ansible/roles/bootstrap/tests/runtime_vm.sh password
```

Сценарий использует настоящий `sshd`, три inventory-хоста на `127.0.0.1`
одноразового гостя и существующие роли. Он проверяет: успешный root-key и
root-password bootstrap; отказ нового admin key/sudo оставляет root и не
включает hardening; повторный запуск при закрытом root идёт администратором и
даёт `changed=0` для base/Docker/panel; неверный input не начинает изменения;
панель healthy и доступна только приватно; `--check` не меняет хост и не
перезапускает контейнеры; секреты не попадают в логи. Перед запуском сценарий
удаляет предустановленный Docker гостя, чтобы роль поставила закреплённые
пакеты; это подготовка одноразового гостя, а не поведение playbook.

Сценарий и CI-workflow добавлены, но **в этой задаче не запускались**. Полный
runtime-результат публикует интегратор после проверки. Все три inventory-хоста
сценария указывают на один и тот же одноразовый guest, поэтому размещение
панели подтверждается выбранным control-plane хостом и приватным gate, а не
отдельными ядрами. Production, DNS, сертификаты и рабочие сервисы не
затрагиваются.

## Откат

- Изменение репозитория — отдельный PR с отменой squash-коммита; он не меняет
  уже настроенные хосты.
- Панель: `docker compose -p remnawave --project-directory /opt/remnawave down`
  **без `-v`**, чтобы сохранить тома. Секреты и пины возвращаются revert-PR и
  повторным запуском.
- SSH/firewall: контракт и ручной откат описаны в
  [BASE_ROLE.md](BASE_ROLE.md). Не удаляйте sudoers/ключи администратора, пока
  нет другого проверенного способа входа; root-доступ восстанавливается
  отдельно и осознанно.
- Для реального пилота нужен отдельно одобренный план восстановления; эта
  задача не развёртывает и не откатывает production.
