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
| `base_firewall_source_ports` | `[]` | Непубличные порты `{proto: tcp\|udp, port: N, source_cidrs: [CIDR, …]}`. Только явно заданные источники; список сам не включает firewall. |
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
- Порт вне 1–65535 (включая строку и bool), неизвестные поля, повтор одной пары
  `proto/port`, пересечение публичного и ограниченного списка, TCP SSH-порт в
  любом из этих списков. TCP и UDP с одинаковым номером — разные пары.
- Пустые/невалидные `source_cidrs`, повтор CIDR после нормализации. Для source ACL
  действуют те же ограничения сетей, что для SSH; единственное исключение —
  точные `127.0.0.1/32` и `::1/128` для colocated management. SSH это исключение
  не получает; более широкие loopback-сети и IPv4-mapped по-прежнему отклоняются.
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
частоты; ответы DHCPv6; SSH из `base_ssh_trusted_cidrs`; публичные
`base_firewall_vpn_ports`; отдельные IPv4/IPv6 source-правила
`base_firewall_source_ports`.
Роль отказывается, если:

- UFW включён (`ENABLED=yes`) или firewalld активен;
- адрес текущего SSH-клиента не входит в доверенные сети;
- на не-loopback адресах слушают порты, не перечисленные ни в SSH, ни в
  `base_firewall_vpn_ports`, ни в `base_firewall_source_ports`, ни в
  `base_firewall_acknowledged_closed_ports` (защита работающих сервисов).
  Ограниченный listener считается управляемым: его не нужно открывать публично
  или подтверждать как полностью закрытый.

Полный кандидат сначала рендерится в закрытый временный каталог `/run` и
проверяется настоящим `/usr/sbin/nft -c -f`. При изменении сохраняются предыдущая
конфигурация и точный live dump **только собственной таблицы**. Кандидат повторно
проверяется непосредственно перед применением и заменяет таблицу одной
транзакцией `nft -f`. Только после успешного применения атомарно записывается
`/etc/vpn-base/firewall.nft`. Ошибка применения/записи восстанавливает прежнюю
таблицу и конфигурацию; отказ передаётся дальше и останавливает serial playbook.
На первом запуске ошибка удаляет только новую собственную таблицу/конфигурацию.
Временные копии удаляются даже при отказе, содержимое и nft-диагностика скрыты
`no_log`, diff для firewall не публикуется. `--check` проверяет настоящий кандидат
без изменения live policy или постоянного файла (создаётся и удаляется только
временный каталог tmpfs); для этого `nft` уже должен быть установлен.

Юнит `vpn-base-firewall.service` загружает сохранённый файл при старте,
reload/restart и, благодаря `PartOf=nftables.service`, после
`systemctl restart nftables`. Сам base не делает глобального flush: его
применение сохраняет чужие таблицы. Однако штатный `/etc/nftables.conf` может
содержать `flush ruleset`: такой **внешний** restart nftables очищает и чужие
таблицы; base восстанавливает только свою. Ручное изменение содержимого таблицы
роль не обнаруживает; обнаруживается её отсутствие.

### Публичные, ограниченные и transit-порты

```yaml
base_firewall_enabled: true
base_ssh_trusted_cidrs: ["192.0.2.0/24", "2001:db8:10::/64"]
base_firewall_vpn_ports:
  - {proto: tcp, port: 443}       # клиентский публичный listener
base_firewall_source_ports:
  - proto: tcp
    port: 8443                  # transit: объявленные relay egress
    source_cidrs: ["198.51.100.2/32", "2001:db8:20::2/128"]
  - proto: tcp
    port: 2222                  # пример private management-сети
    source_cidrs: ["192.0.2.0/24", "2001:db8:10::/64"]
```

Пример синтетический; реальные адреса задаются оператором отдельно для каждого
хоста и не вычисляются из DNS, имени relay или NAT. Между публичным/restricted
списками **нет приоритета**: пересечение запрещено до изменения хоста, иначе
публичное accept обходило бы source ACL. Существующие `lo` и
`established,related` имеют прежнюю семантику: loopback всегда разрешён,
объявление точного loopback management не сужает эту политику; уже установленные
соединения сохраняются. Проверку смены ACL делают новым соединением, а не
существующей сессией. Указаны только IPv4-источники — IPv6 для этого порта не
открывается, и наоборот; пустой список источников запрещён.

Base валидирует безопасные source-сети для private management. Transit-семантика
принадлежит интеграции inventory/profiles: там source ACL должен совпадать с явно
объявленными egress relay `/32` IPv4 и `/128` IPv6. Не заменяйте этот контракт
подсетью и не угадывайте исходящий адрес за NAT.

На одноразовом стенде egress проверяют на стороне принимающего listener:
создают новое IPv4 и IPv6 соединение с relay, сравнивают адрес peer после NAT с
объявленными `/32` и `/128`, затем проверяют отказ другому источнику. В нашем
сценарии namespace `nated` сначала получает отказ с незаявленных адресов, а после
SNAT реальные peer-адреса совпадают с явно разрешёнными. До включения политики
на разрешённом узле оператор должен таким же образом подтвердить **его**
фактический egress; успех синтетического теста не подтверждает адрес production.

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
4. Перечислите публичные клиентские порты в `base_firewall_vpn_ports`, private
   management/transit — отдельно в `base_firewall_source_ports`; подтвердите
   egress источников, задайте `base_ssh_trusted_cidrs`, сохраните предыдущий
   собственный файл/таблицу для ручного отката и включите
   `base_firewall_enabled: true`. При отказе из-за listener объявите его в
   правильном списке либо осознанно подтвердите закрытие. После применения —
   **новые** SSH и IPv4/IPv6 соединения к публичному и ограниченному сервисам
   из разрешённого и запрещённого источника, затем reload/restart собственной
   службы и повторная проверка доступа.
5. Повторный запуск должен давать `changed=0`.

Playbook обрабатывает хосты по одному и останавливается при первой ошибке.

## Проверка

| Команда | Что проверяет |
| --- | --- |
| `cd ansible && ../.venv/bin/ansible-playbook -i inventories/example/hosts.yml playbooks/base.yml --syntax-check` | Синтаксис на синтетическом inventory. |
| `.venv/bin/python -m unittest discover -s ansible/roles/base/tests -v` | Unit-тесты фильтров; реальный `ansible-playbook` на `localhost`: отказы для неверных администраторов, ключей, CIDR и переключателей без изменений хоста; отключённое управление и `--check` дают `changed=0`. Нужны Debian/Ubuntu и sudo без пароля. |
| `sudo VPN_BASE_DISPOSABLE_GUEST=yes GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted bash ansible/roles/base/tests/runtime_vm.sh` | **Только явно выделенный одноразовый GitHub-hosted Linux guest.** Полный сценарий ниже; guard не является разрешением запускать на обычном хосте. |

Сценарий VM запускается workflow [`base.yml`](../.github/workflows/base.yml) на
GitHub-hosted `ubuntu-24.04`, уничтожаемом после job. Он проверяет отказы при
другой службе времени/незаявленном listener/невалидном ACL; первое применение;
повтор по SSH и `--check --diff` с `changed=0`; новые SSH-входы с IPv4/IPv6,
сохранение старых ключей и sudo; отсутствие входа без ключа; реальные dual-stack
TCP/UDP listener с передачей данных только разрешённым namespace и отдельный
публичный TCP listener; IPv4-only ACL, не открывающий IPv6; ND после сброса cache;
наблюдаемый SNAT egress; routed IPv4/IPv6 transfer 1 МиБ с проверкой SHA256 через
MTU 1280 и обязательным capture настоящих fragmentation-needed/packet-too-big
(black-hole fallback выключен только на время теста); сохранение чужих таблиц,
форвардинга, swap, файлов, пользователей и служб при применении; настоящий
`nft -c`; отказ невалидному кандидату в реальной роли; fault injection ошибки
настоящего `nft -f` после успешной валидации с сохранением live policy и файла;
смену ACL, восстановление предыдущего файла/таблицы с повторной пакетной
проверкой; reload/restart собственной службы и restart nftables с повторным
доступом и свежим SSH; BBR, chrony, unattended-upgrades и swap/idempotence.

Guard проверяет `VPN_BASE_DISPOSABLE_GUEST=yes`, root, Linux, systemd,
`GITHUB_ACTIONS=true` и `RUNNER_ENVIRONMENT=github-hosted`. Сценарий устанавливает
публичные пакеты openssh-server/iproute2/iputils-ping/nftables/tcpdump/ethtool,
использует host network namespaces, veth/bridge и временные ключи. Нужны
`CAP_NET_ADMIN`, рабочее ядро nftables/IPv6/BBR и доступ к apt; подготовленный
`.venv` создаётся `make -C ansible bootstrap`. Никакие cloud/DNS/owner credentials
не требуются. Дополнительный `runtime_pmtu.sh` вызывается только основным
guarded entrypoint; отдельного разрешения на production он не даёт. Временные
процессы, namespaces, fault-injection wrapper и ключи удаляются exit trap.

После интеграции один владелец проверки запускает существующие тесты фильтров и
validation, этот runtime, `make -C ansible validate test` и финальный `make check`.
Делегированный implementer проверки не запускает; наличие сценария не является
записью успешного результата. Фактические команды/результаты фиксируются в PR.

Job не входит в обязательные проверки (`Repository checks`, `Secret scan`). Для
PR из форка его запуск требует одобрения владельца.

### Что не проверено

- Debian 12/13 и Ubuntu 22.04 в рантайме; перезагрузка узла (загрузка таблицы
  юнитом при старте); DHCPv6; хосты с UFW/firewalld (проверен только отказ по
  условию в коде);
  работа ssh.socket при смене порта (роль порт не меняет).

## Откат

Откат репозитория — отдельный PR с отменой squash-коммита. Он **не** меняет
узлы, где роль применялась. На узле (из открытой административной сессии):

Для отката **политики**, а не удаления firewall, до изменения отдельно сохраните
последний рабочий `/etc/vpn-base/firewall.nft` в закрытое место вне репозитория.

```sh
sudo install -d -o root -g root -m 0700 /root/vpn-base-rollback
sudo cp -p /etc/vpn-base/firewall.nft /root/vpn-base-rollback/firewall.nft
```

Снимок делают **до** изменения; не перезаписывайте его новым кандидатом.

Из независимой административной сессии на явно разрешённом хосте:

```sh
sudo nft -c -f /root/vpn-base-rollback/firewall.nft
sudo nft -f /root/vpn-base-rollback/firewall.nft
sudo install -o root -g root -m 0644 /root/vpn-base-rollback/firewall.nft /etc/vpn-base/firewall.nft
sudo systemctl reload vpn-base-firewall.service
```

После восстановления откройте новые SSH, public и restricted соединения по
IPv4/IPv6 с обоих источников; сверяйте наблюдаемое поведение, не только `nft list`.
Автоматическая временная копия транзакции не является долгосрочным архивом.
При отсутствии прежней собственной таблицы откат — удалить только `inet
vpn_base` и собственный loader/config, не чужие таблицы. Полное снятие управления
ниже не эквивалентно восстановлению предыдущего fail-closed ACL.

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
