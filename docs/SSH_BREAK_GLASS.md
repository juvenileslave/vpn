# Прямой аварийный SSH-доступ (break-glass)

Документ описывает контракт и операционный runbook прямого SSH-доступа
администратора к каждому объявленному узлу (`exit`, `relay`, `cp`) независимо
от entrance (`relay`), приватного overlay и control plane (`cp`).

- **Статус:** реализованы базовый SSH/firewall hardening, статический контракт
  inventory, прямой gate в `bootstrap` и документация (срезы issue #75).
- **Состояние инфраструктуры:** **VPN не развёрнут, production-хосты не
  изменялись.** Наличие этого документа, шаблонов и статических проверок не
  является runtime acceptance на рабочих серверах. Любые изменения на реальных
  узлах требуют отдельного явного разрешения владельца
  ([AGENTS.md](../AGENTS.md), [INVARIANTS.md](INVARIANTS.md)).

## Зачем нужен прямой break-glass путь

Обычный путь управления может идти через entrance (`relay`), через
`ProxyJump`/`ProxyCommand` или через приватный overlay. Потеря entrance,
overlay или control plane не должна отрезать владельца от оставшихся узлов.
Поэтому каждый объявленный узел сохраняет собственный **прямой** SSH-вход с
рабочей станции администратора по явному узкому source ACL, только по ключу,
под выделенным не-root администратором и с обязательной проверкой host key.

## Контракт прямого пути по узлам

Ниже приведена **синтетическая** таблица для примера топологии
`ansible/inventories/example/` (только документационные диапазоны RFC 5737 /
RFC 3849; реальные адреса и ключи хранятся вне репозитория):

| Узел | Роль | Прямой адрес (`ansible_host` / IPv6) | SSH-порт | Источник (`base_ssh_trusted_cidrs`) | Учётная запись и sudo |
| --- | --- | --- | --- | --- | --- |
| `exit-example` | `exit` | `192.0.2.10` / `2001:db8:10::10` | `22` (`base_ssh_port`) | `192.0.2.0/24`, `2001:db8:10::/64` | не-root из `base_admin_users`, `sudo: true` |
| `relay-example` | `relay` (entrance) | `198.51.100.20` / `2001:db8:20::20` | `22` (`base_ssh_port`) | `192.0.2.0/24`, `2001:db8:10::/64` | не-root из `base_admin_users`, `sudo: true` |
| `cp-example` | `control_plane` | `203.0.113.30` / `2001:db8:30::30` | `22` (`base_ssh_port`) | `192.0.2.0/24`, `2001:db8:10::/64` | не-root из `base_admin_users`, `sudo: true` |

При `cp_placement: exit` группа `cp` пуста, а control plane работает на узле
`exit`: прямой путь обязан существовать для обоих объявленных узлов (`exit` и
`relay`).

### Обязательные требования на каждом узле

1. **Точный узкий source ACL (`base_ssh_trusted_cidrs`):**
   - обязателен и не может быть пустым при `base_ssh_enabled: true` или
     `base_firewall_enabled: true`;
   - допустимы только явные CIDR с маской не шире `/24` (IPv4) и `/64` (IPv6);
     для статических адресов администратора предпочтительны точные `/32` и
     `/128`;
   - запрещены `0.0.0.0/0`, `::/0`, loopback, multicast, unspecified,
     IPv4-mapped IPv6 и повторы после нормализации;
   - порт `base_ssh_port` запрещено добавлять в `base_firewall_vpn_ports` или
     `base_firewall_source_ports`: в `inet vpn_base` он открыт только правилами
     из `base_ssh_trusted_cidrs`, а политика цепочки `input` — `drop`.
2. **Аутентификация только по ключу (`00-vpn-base.conf`):**
   - `PubkeyAuthentication yes`, `AuthenticationMethods publickey`,
     `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
     `PermitEmptyPasswords no`, `HostbasedAuthentication no`;
   - ограниченные окна и попытки: `MaxAuthTries` (по умолчанию `4`, допустимо
     `1–6`) и `LoginGraceTime` (по умолчанию `30` с, допустимо `10–60`);
   - дополнительно выключены `X11Forwarding no` и `PermitUserEnvironment no`;
   - `AllowTcpForwarding` не выключается, чтобы сохранялся доступ к приватной
     панели через `ssh -L`; `AllowUsers`/`AllowGroups` ролью не задаются, чтобы
     не сломать ранее существовавшие не-административные учётные записи;
   - принимаются только `ssh-ed25519`, FIDO2 `sk-*`, ECDSA и RSA от 3072 бит;
     DSA и короткие RSA отвергаются до изменений.
3. **Не-root и контролируемый `sudo`:**
   - `base_ssh_permit_root_login` принимает только `"no"` (`PermitRootLogin no`);
     общего root-ключа и публичного SSH для пользователей VPN нет;
   - администратор имеет UID `>= 1000`, собственный ключ и запись в
     `/etc/sudoers.d/vpn-base`, проверенную `visudo -cf`.
4. **Обязательная проверка host key:**
   - `ansible/ansible.cfg` держит `host_key_checking = True`, `bootstrap`
     отклоняет `StrictHostKeyChecking=no|off|false|accept-new` и
     `UserKnownHostsFile=/dev/null|none`;
   - preflight роли `base` до изменений проверяет, что все действующие файлы
     `hostkey` из `sshd -T` существуют и не пусты;
   - на реальном узле отпечаток host key сверяется out-of-band (через консоль
     провайдера: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`) до записи
     в локальный `known_hosts`; `ssh-keyscan` допустим только на синтетическом
     одноразовом стенде.

### Проверка прямого пути одной командой

Проверка выполняется **новым** процессом `ssh` без чтения `~/.ssh/config` и с
явным отключением прокси:

```sh
ssh -F /dev/null \
  -o ProxyJump=none \
  -o ProxyCommand=none \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/абс/путь/к/known_hosts \
  -o IdentitiesOnly=yes \
  -o PubkeyAuthentication=yes \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey \
  -i /абс/путь/вне/checkout/admin_key \
  -p 22 \
  opsadmin@192.0.2.10 \
  'printf "user=%s uid=%s\n" "$(id -un)" "$(id -u)" && sudo -n true && echo sudo=ok'
```

Команда повторяется для каждого объявленного узла (`exit`, `relay`, `cp`).

## Обычный путь через entrance и необязательный прокси

- Обычная работа оператора может идти через entrance (`relay`) с помощью
  `ProxyJump` или `ProxyCommand` в локальном `~/.ssh/config` либо в приватном
  `ansible_ssh_common_args`.
- В репозитории нет переменной `relay_proxy_command` и нет жёсткой зависимости
  от `ProxyCommand`: прокси — **только опциональное удобство**, а не условие
  работы `base`, `bootstrap` или break-glass.
- **Статический контракт inventory (`validate_inventory.py`):** для каждого
  объявленного хоста обязательны `base_ssh_port` (и равенство с `ansible_port`),
  `base_ssh_permit_root_login: "no"`, непустой узкий `base_ssh_trusted_cidrs` и
  отсутствие SSH-порта в `base_firewall_vpn_ports`/`base_firewall_source_ports`,
  а в рабочем (non-example) inventory — `base_ssh_enabled: true`. Наличие
  `relay_proxy_command` или `ProxyJump`/`ProxyCommand` не подменяет прямой
  контракт.
- **Прямой gate в `bootstrap.yml` (`roles/bootstrap/tasks/verify.yml`):** на
  каждом хосте до и после hardening/firewall сначала выполняется независимая
  прямая проверка без прокси (`bootstrap_direct_ssh_args` удаляет
  `ProxyJump`/`ProxyCommand`/`-J`, передаются `ProxyJump=none`/`ProxyCommand=none`),
  а при наличии прокси в `ansible_ssh_common_args` дополнительно проверяется
  проксируемый путь. Отказ прямой проверки останавливает изменение.
- При использовании `ProxyJump` через entrance учтите, что для прямого входа
  на `exit` и `cp` в `base_ssh_trusted_cidrs` обязан присутствовать реальный
  источник рабочей станции администратора, а не только адрес entrance.

## Preflight и порядок изменений по одному узлу

`ansible/playbooks/base.yml` запускается с `serial: 1`, `any_errors_fatal: true`
и `max_fail_percentage: 0`. При любом изменении SSH или firewall соблюдайте
порядок:

1. **Локальная валидация без подключения:**
   ```sh
   make -C ansible validate test
   cd ansible && ../.venv/bin/ansible-playbook -i /абс/путь/hosts.yml \
     playbooks/base.yml --syntax-check
   ```
2. **Сначала проверьте прямой доступ к `exit` и `cp`, прежде чем менять
   `relay` (entrance):** потеря entrance не должна оставлять без связи
   остальные узлы.
3. **Держите открытой проверенную прямую сессию** на изменяемом узле до конца
   всех проверок.
4. **Снимите локальную резервную копию на узле до изменений:**
   ```sh
   sudo install -d -o root -g root -m 0700 /root/vpn-base-rollback
   test -f /etc/ssh/sshd_config.d/00-vpn-base.conf && \
     sudo cp -p /etc/ssh/sshd_config.d/00-vpn-base.conf /root/vpn-base-rollback/00-vpn-base.conf
   test -f /etc/vpn-base/firewall.nft && \
     sudo cp -p /etc/vpn-base/firewall.nft /root/vpn-base-rollback/firewall.nft
   ```
5. **Запустите `--check --diff`, затем примените на один узел:**
   ```sh
   cd ansible
   ../.venv/bin/ansible-playbook -i /абс/путь/hosts.yml playbooks/base.yml \
     --limit <узел> --check --diff
   ../.venv/bin/ansible-playbook -i /абс/путь/hosts.yml playbooks/base.yml \
     --limit <узел>
   ```
6. **Подтвердите изменения новым прямым подключением** (старая сессия и
   `established,related` не доказывают новую политику):
   - свежий прямой вход ключом администратора (`ProxyJump=none`,
     `ProxyCommand=none`) + `sudo -n true`;
   - отказ входа по паролю и под `root`;
   - состояние `ssh.socket` и `ssh.service` (см. инвариант 10 в
     [INVARIANTS.md](INVARIANTS.md): выключенный `ssh.service` при активном
     `ssh.socket` — норма);
   - повторный запуск `--limit <узел>` с `changed=0`.
7. Только после подтверждения переходите к следующему узлу.

## Ротация ключей администратора без потери доступа

Роль `base` **только дописывает** отсутствующие ключи в
`~/.ssh/authorized_keys` и намеренно не удаляет существующие строки. Поэтому
безопасная ротация выполняется в два явных этапа:

1. Сгенерируйте новый ключ (`ssh-keygen -t ed25519` или аппаратный
   `sk-ssh-ed25519@openssh.com`) строго **вне репозитория** с правами `0600`.
2. **Добавьте** новый публичный ключ в `base_admin_users[*].authorized_keys`
   рядом со старым и примените `playbooks/base.yml` по одному узлу
   (`--limit <узел>`).
3. Проверьте **новым** прямым подключением (`-F /dev/null`, `ProxyJump=none`,
   `ProxyCommand=none`, `IdentitiesOnly=yes`, `-i <новый-ключ>`) вход и
   `sudo -n true` на **каждом** узле, сохраняя открытую сессию со старым ключом.
4. Переведите приватный inventory / `bootstrap_admin_private_key_file` на новый
   ключ и убедитесь, что повторный запуск проходит с новым ключом (`changed=0`).
5. **Отзыв старого ключа:** удалите старый ключ из `base_admin_users`, затем
   вручную удалите его строку из `/home/<admin>/.ssh/authorized_keys` на каждом
   узле (при открытой сессии новым ключом). Проверьте, что новый ключ входит
   свежим соединением, а старый ключ получает `Permission denied (publickey)`.

## Аварийное восстановление

### 1. Сохранена открытая административная сессия

Не закрывайте сессию. Проверьте фактическое состояние:

```sh
sudo sshd -t
sudo sshd -T | grep -E '^(port|hostkey|authenticationmethods|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|hostbasedauthentication|permitrootlogin|maxauthtries|logingracetime|x11forwarding|permituserenvironment) '
sudo systemctl status ssh.socket ssh.service --no-pager
sudo nft list table inet vpn_base
sudo journalctl -u ssh.service -u ssh.socket -n 50 --no-pager
```

После диагностики выполните точный откат из раздела ниже и проверьте **новым**
прямым подключением, не закрывая текущую сессию.

### 2. Доступен резервный ключ или второй разрешённый адрес

Подключитесь напрямую с другого адреса из `base_ssh_trusted_cidrs` или другим
разрешённым ключом администратора, затем выполните диагностику и откат.

### 3. Консоль провайдера (VNC / serial / KVM out-of-band)

Если все SSH-сессии потеряны (например, сменился внешний IP администратора вне
`base_ssh_trusted_cidrs`, повреждён конфиг `sshd` или оборвалась настройка
firewall):

1. Войдите через out-of-band консоль провайдера (учётные данные консоли
   хранятся вне репозитория).
2. Проверьте, слушает ли `sshd` и не мешает ли `nftables`:
   ```sh
   ss -H -l -n -t | grep ':22\b'
   systemctl status ssh.socket ssh.service --no-pager
   sshd -t
   nft list table inet vpn_base
   ls -la /root/vpn-base-rollback /run/vpn-base-firewall-* 2>/dev/null || true
   ```
3. Восстановите прежний `00-vpn-base.conf` и/или `firewall.nft` по процедуре
   отката ниже; если сменился IP администратора, обновите `base_ssh_trusted_cidrs`
   в приватном inventory и примените обновлённую таблицу `inet vpn_base` с
   узким CIDR вместо открытия `0.0.0.0/0`.
4. Убедитесь, что **новое** прямое SSH-подключение с рабочей станции проходит с
   проверкой host key и `sudo -n true`, и только затем выходите из консоли.
5. Никогда не оставляйте после восстановления включённый вход по паролю,
   `PermitRootLogin yes` или широкий SSH ACL.

## Точный откат при неудачном изменении SSH или firewall

Откат репозитория — отдельный PR с отменой squash-коммита; он **не** изменяет
уже настроенные узлы. На узле (из сохранённой сессии или консоли провайдера):

### Откат политики SSH

```sh
# Если ранее существовал рабочий drop-in — вернуть его; иначе удалить новый.
if [ -f /root/vpn-base-rollback/00-vpn-base.conf ]; then
  sudo install -o root -g root -m 0644 \
    /root/vpn-base-rollback/00-vpn-base.conf /etc/ssh/sshd_config.d/00-vpn-base.conf
else
  sudo rm -f /etc/ssh/sshd_config.d/00-vpn-base.conf
fi
sudo sshd -t
sudo systemctl try-reload-or-restart ssh.service
```

Если `sshd` работает через `ssh.socket`, `try-reload-or-restart ssh.service`
безопасно ничего не ломает, а новые подключения сразу читают восстановленную
конфигурацию.

### Откат таблицы firewall (если блокируется источник SSH)

```sh
sudo nft -c -f /root/vpn-base-rollback/firewall.nft
sudo nft -f /root/vpn-base-rollback/firewall.nft
sudo install -o root -g root -m 0644 \
  /root/vpn-base-rollback/firewall.nft /etc/vpn-base/firewall.nft
sudo systemctl reload vpn-base-firewall.service
```

Полное снятие управления (если прежней таблицы `inet vpn_base` не было) описано
в [BASE_ROLE.md](BASE_ROLE.md). После любого отката обязательно откройте **новое**
прямое SSH-подключение по команде из раздела «Проверка прямого пути одной
командой» и подтвердите `id -un`, `sudo -n true` и отказ входа без ключа.

## Граница проверок

- Статически и локально (без изменения хостов) проверяются: синтаксис
  playbook, unit-тесты фильтров и рендера `sshd-vpn-base.conf.j2` /
  `firewall.nft.j2`, локальные отказы `base` на `localhost`, фильтры `bootstrap`
  (включая fail-closed очистку прокси-аргументов `bootstrap_direct_ssh_args`),
  статический SSH break-glass контракт в `validate_inventory.py` для каждого
  объявленного узла и `make check`.
- В CI на одноразовом GitHub-hosted Linux guest `ansible/roles/base/tests/runtime_vm.sh`
  проверяет один хост: key-only SSH по IPv4/IPv6, отказ без ключа, source ACL,
  сохранение существующего ключа и не-административного пользователя.
- Многоузловой одноразовый тест с отключением entrance/overlay/CP и проверкой
  прямого SSH к каждому объявленному узлу выделен в следующий срез issue #75 и
  пока не реализован и не выполнялся. На production-узлах проверки и
  развёртывание не проводились.
