# Ansible: роль `base`

Роль реализует задачу 1.2 [архитектурного плана](ARCHITECTURE_PLAN.md): базовая
настройка узла Debian/Ubuntu — администраторы и ключи, политика SSH, chrony,
автоматические обновления безопасности, BBR, необязательный swap и собственная
таблица nftables. **Роль ни к одному серверу не применялась.** Её наличие не
означает, что VPN развёрнут; запуск на рабочих узлах требует отдельного явного
разрешения владельца (см. [AGENTS.md](../AGENTS.md)).

## Состав

```text
ansible/
├── playbooks/base.yml              # serial: 1, any_errors_fatal
└── roles/base/
    ├── defaults/main.yml           # все переменные и значения по умолчанию
    ├── filter_plugins/vpn_base.py  # проверка ввода на контроллере
    ├── tasks/                      # validate → preflight → изменения
    ├── handlers/main.yml
    ├── templates/
    └── tests/                      # unit, локальные отказы, сценарий VM
```

Внешние коллекции не нужны: используются только модули `ansible.builtin`
закреплённого `ansible-core` из `ansible/requirements-ansible.txt`.

## Поддерживаемые системы

Debian 12+ и Ubuntu 22.04+ с systemd. Другие системы роль отклоняет до изменений.
Фактически на VM проверяется только Ubuntu 24.04 (см. «Проверка»); Debian и
Ubuntu 22.04 в рантайме не проверялись.

## Принципы безопасности

- Сначала выполняются проверка переменных (`validate.yml`) и чтение состояния
  хоста (`preflight.yml`); любой отказ происходит до первого изменения.
  Единственное исключение — создание пустого каталога `/run/sshd` на tmpfs,
  без которого `sshd -T` не работает.
- `false` у переключателя означает «не управлять», а не «удалить»: ранее
  созданные ролью файлы остаются.
- Пакеты только устанавливаются (`apt --no-remove`); ничего не удаляется. Роль не
  добавляет группу `docker`, не меняет форвардинг и не трогает существующие VPN.
- Существующие пользователи сохраняют shell, пароль и группы; в
  `authorized_keys` только дописываются отсутствующие ключи, существующие строки
  (с опциями и комментариями) не меняются.
- Сообщения об ошибках не содержат ключей и адресов, только путь к переменной.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `base_admin_users` | `[]` | Список `{name, authorized_keys, sudo}`; `sudo` по умолчанию `true`. |
| `base_admin_shell` | `/bin/bash` | Shell только для создаваемых пользователей. |
| `base_admin_sudo_nopasswd` | `true` | `NOPASSWD` в `/etc/sudoers.d/vpn-base` (пароля у новых пользователей нет). |
| `base_ssh_enabled` | `false` | Управление политикой SSH. |
| `base_ssh_port` | `22` | Порт, который sshd **уже** слушает; роль его не меняет, а сверяет с `sshd -T`. |
| `base_ssh_permit_root_login` | `"no"` | `no` или `prohibit-password`. |
| `base_ssh_trusted_cidrs` | `[]` | Сети, из которых firewall пропускает SSH. |
| `base_firewall_enabled` | `false` | Управление таблицей `inet vpn_base`. |
| `base_firewall_vpn_ports` | `[]` | Публичные порты `{proto: tcp\|udp, port: N}`. |
| `base_firewall_allow_icmp_echo` | `true` | Ping v4/v6 (с ограничением частоты). |
| `base_firewall_allow_dhcpv6_client` | `true` | Ответы DHCPv6 с link-local сервера. |
| `base_firewall_acknowledged_closed_ports` | `[]` | Слушающие порты (`tcp/N`, `udp/N`), закрытие которых оператор подтверждает. |
| `base_chrony_enabled` | `true` | Установка и запуск chrony. |
| `base_chrony_pools` | `[]` | Дополнительные пулы в `/etc/chrony/sources.d/vpn-base.sources`. |
| `base_unattended_upgrades_enabled` | `true` | Ежедневные обновления только из источников безопасности. |
| `base_unattended_origins_patterns` | по дистрибутиву | `Origins-Pattern` для Debian или Ubuntu (включая ESM). |
| `base_bbr_enabled` | `true` | BBR, если ядро его поддерживает. |
| `base_bbr_qdisc` | `fq` | `net.core.default_qdisc`; пустая строка — не менять. |
| `base_swap_enabled` | `false` | Создать swap-файл, только если активного swap нет. |
| `base_swap_file` / `base_swap_size_mb` | `/swapfile` / `1024` | Путь и размер (64–65536 МиБ). |

Переключатели должны быть настоящими `true`/`false`; строка `"false"` отклоняется.
Из командной строки передавайте их в JSON: `-e '{"base_ssh_enabled": true}'`.

### Отклоняемый ввод

- Имя пользователя вне `^[a-z_][a-z0-9_-]{0,31}$`, `root`, системные имена,
  повторы, неизвестные поля; существующий пользователь с UID < 1000.
- Ключи: не одна строка, опции `authorized_keys`, приватный ключ, неверный
  base64 или несовпадение типа, DSA, RSA короче 3072 бит.
- CIDR без префикса, с битами хоста, `/0`, шире `/8` (IPv4) или `/32` (IPv6),
  loopback/multicast/IPv4-mapped.
- VPN-порт вне 1–65535, повтор, SSH-порт как публичный TCP-порт.
- `base_ssh_enabled` без администратора с `sudo` и ключом;
  `base_firewall_enabled` без `base_ssh_trusted_cidrs`.

## Компоненты

**Пользователи.** Отсутствующие создаются с паролем `*` (вход по паролю
невозможен, ключи работают). `~/.ssh` приводится к `0700`, `authorized_keys` —
к `0600`. Sudoers проверяется `visudo -cf` до установки.

**SSH.** Файл `/etc/ssh/sshd_config.d/00-vpn-base.conf` задаёт
`PubkeyAuthentication yes`, `PasswordAuthentication no`,
`KbdInteractiveAuthentication no`, `PermitEmptyPasswords no`, `PermitRootLogin`.
Порядок защиты от потери доступа:

1. до изменений: `sshd_config` подключает `sshd_config.d/*.conf`; `AllowUsers`,
   `DenyUsers`, `AllowGroups` не блокируют администраторов; при
   `PermitRootLogin no` текущая SSH-сессия не под `root`;
2. кандидат проверяется `sshd -t -f`, затем вся конфигурация `sshd -T` сверяется
   с политикой (конфликтующие более ранние файлы приводят к отказу без reload);
3. handler повторяет `sshd -t` и только затем выполняет
   `systemctl try-reload-or-restart ssh.service`.

**Firewall.** Управляется только таблица `inet vpn_base` (цепочка `input`,
policy `drop`); глобальный ruleset не очищается, UFW/firewalld не отключаются,
цепочки `forward`/`output` не создаются. Разрешено: `lo`; IPv6 ND/RA с
hop limit 255 и MLD с link-local; established/related; ICMP-ошибки
(включая fragmentation-needed и packet-too-big для PMTU); echo с ограничением
частоты; ответы DHCPv6; SSH из `base_ssh_trusted_cidrs`; `base_firewall_vpn_ports`.
Роль отказывается, если:

- UFW включён (`ENABLED=yes`) или firewalld активен;
- адрес текущего SSH-клиента не входит в доверенные сети;
- на не-loopback адресах слушают порты, не перечисленные ни в SSH, ни в
  `base_firewall_vpn_ports`, ни в `base_firewall_acknowledged_closed_ports`
  (защита работающих сервисов, например существующего VPN).

Кандидат `/etc/vpn-base/firewall.nft` проверяется `nft -c` до записи. Файл
заменяет таблицу в одной транзакции `nft -f`: при ошибке остаётся предыдущая.
Юнит `vpn-base-firewall.service` загружает таблицу при старте и, благодаря
`PartOf=nftables.service`, повторно после `systemctl restart nftables`
(стандартный `/etc/nftables.conf` содержит `flush ruleset`). Ручное изменение
содержимого таблицы роль не обнаруживает; обнаруживается только её отсутствие.

**chrony.** Установка chrony удаляет `systemd-timesyncd` (конфликт пакетов),
поэтому при установленных `systemd-timesyncd`, `ntp`, `ntpsec` или `openntpd`
роль отказывает. Замените службу времени вручную или задайте
`base_chrony_enabled: false`. Основной `chrony.conf` не меняется.

**Обновления.** `/etc/apt/apt.conf.d/52vpn-base-unattended-upgrades` идёт после
`20auto-upgrades` и `50unattended-upgrades`, очищает `Allowed-Origins` и
`Origins-Pattern` и оставляет только источники безопасности; автоперезагрузка
выключена. Проверяется `apt-config -c` до записи.

**BBR.** При поддержке: `tcp_bbr` в `/etc/modules-load.d/vpn-base-bbr.conf`,
значения в `/etc/sysctl.d/90-vpn-base-bbr.conf`, применяется только этот файл
(`sysctl -p <файл>`). Без поддержки роль выводит предупреждение и ничего не
меняет.

**Swap.** Если активен любой swap — ничего не создаётся. Иначе проверяется
свободное место (размер + 512 МиБ), файл создаётся под временным именем,
форматируется и переносится, затем `swapon` и запись в `/etc/fstab`
(существующая запись для того же пути не меняется). Существующий файл по пути
`base_swap_file` только активируется, но никогда не форматируется.

## Безопасное включение

1. Заполните `base_admin_users` ключом администратора; оставьте
   `base_ssh_enabled` и `base_firewall_enabled` выключенными. Проверьте:

   ```sh
   cd ansible
   ../.venv/bin/ansible-playbook -i <inventory> playbooks/base.yml --limit <хост> --check --diff
   ../.venv/bin/ansible-playbook -i <inventory> playbooks/base.yml --limit <хост>
   ```

2. Откройте **новую** SSH-сессию администратором и проверьте `sudo -n true`.
   Держите одну сессию открытой до конца всех шагов.
3. Включите `base_ssh_enabled: true`, подключаясь администратором (не `root`),
   повторите `--check --diff` и применение, затем снова новый вход.
4. Перечислите все публичные порты работающих сервисов в
   `base_firewall_vpn_ports`, задайте `base_ssh_trusted_cidrs`, включите
   `base_firewall_enabled: true`. Если роль отказала из-за слушающих портов,
   либо добавьте их, либо осознанно подтвердите закрытие. После применения —
   новый вход из доверенной сети и проверка VPN-портов.
5. Повторный запуск должен давать `changed=0`.

Playbook обрабатывает хосты по одному и останавливается при первой ошибке.

## Проверка

| Команда | Что проверяет |
| --- | --- |
| `cd ansible && ../.venv/bin/ansible-playbook -i inventories/example/hosts.yml playbooks/base.yml --syntax-check` | Синтаксис на синтетическом inventory. |
| `.venv/bin/python -m unittest discover -s ansible/roles/base/tests -v` | Unit-тесты фильтров; реальный `ansible-playbook` на `localhost`: отказы для неверных администраторов, ключей, CIDR и переключателей без изменений хоста; отключённое управление и `--check` дают `changed=0`. Нужны Debian/Ubuntu и sudo без пароля. |
| `sudo VPN_BASE_DISPOSABLE_GUEST=yes bash ansible/roles/base/tests/runtime_vm.sh` | **Только одноразовая VM.** Полный сценарий ниже. |

Сценарий VM (выполняется workflow [`base.yml`](../.github/workflows/base.yml) на
GitHub-hosted `ubuntu-24.04`, который уничтожается после job): отказ при
`systemd-timesyncd` и при незаявленном слушающем порте; первое применение
локально; второе применение по SSH из доверенной сети (netns, документационные
адреса) с `changed=0`; `--check --diff` с `changed=0`; свежие входы по новому и
старому ключу по IPv4/IPv6 и `sudo`; отказ входа без ключа; SSH закрыт для
недоверенной сети, VPN-порт открыт, незаявленный порт закрыт; ICMPv4/ICMPv6 и ND
после сброса neighbor cache; неизменность форвардинга, swap, посторонней таблицы
nftables, файлов, пользователей и служб; `nft -c`; BBR, chrony, источники
unattended-upgrades; некорректный кандидат не меняет активную таблицу; таблица
восстанавливается после `restart nftables`; создание swap и повтор с `changed=0`.

Job не входит в обязательные проверки (`Repository checks`, `Secret scan`). Для
PR из форка его запуск требует одобрения владельца.

### Что не проверено

- Debian 12/13 и Ubuntu 22.04 в рантайме; перезагрузка узла (загрузка таблицы
  юнитом при старте); реальная проверка PMTU (покрыта только правилами);
  DHCPv6; хосты с UFW/firewalld (проверен только отказ по условию в коде);
  работа ssh.socket при смене порта (роль порт не меняет).

## Откат

Откат репозитория — отдельный PR с отменой squash-коммита. Он **не** меняет
узлы, где роль применялась. На узле (из открытой административной сессии):

```sh
# firewall
sudo systemctl disable vpn-base-firewall.service
sudo nft delete table inet vpn_base
sudo rm /etc/systemd/system/vpn-base-firewall.service /etc/vpn-base/firewall.nft
sudo systemctl daemon-reload
# SSH-политика: удалить drop-in, проверить и перечитать
sudo rm /etc/ssh/sshd_config.d/00-vpn-base.conf
sudo sshd -t && sudo systemctl try-reload-or-restart ssh.service
# остальные собственные файлы роли
sudo rm /etc/apt/apt.conf.d/52vpn-base-unattended-upgrades \
        /etc/sysctl.d/90-vpn-base-bbr.conf /etc/modules-load.d/vpn-base-bbr.conf \
        /etc/chrony/sources.d/vpn-base.sources
sudo sysctl --system
```

`sysctl --system` перечитывает все файлы sysctl; значение congestion control
вернётся к заданному в системе. Созданные пользователи, строки
`authorized_keys`, `/etc/sudoers.d/vpn-base`, swap-файл и установленные пакеты
удаляются только вручную после проверки, что ими никто не пользуется. Не
удаляйте sudoers/ключи администратора, пока нет другого способа входа.
