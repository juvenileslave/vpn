# Ansible: контракт inventory

Документ описывает этап 0.3 [архитектурного плана](ARCHITECTURE_PLAN.md):
структуру inventory, контракт переменных и его проверку. **Развёртывание не
реализовано.** В репозитории нет playbook'ов, ролей и коллекций; `make -C ansible`
ничего не подключает к серверам и не меняет инфраструктуру. Успешная проверка
означает только, что файлы inventory соответствуют контракту.

## Структура

```text
ansible/
├── ansible.cfg                    # inventory по умолчанию — example
├── Makefile                       # bootstrap, validate, test
├── requirements-ansible.txt       # закреплённые ansible-core и PyYAML
├── inventories/
│   ├── example/                   # синтетическая топология, публикуется
│   │   ├── hosts.yml
│   │   ├── group_vars/{all,exit,relay,cp}.yml
│   │   └── host_vars/{exit,relay,cp}-example.yml
│   └── production/                # только локально, в .gitignore
└── scripts/
    ├── validate_inventory.py      # проверка контракта
    └── tests/test_validate_inventory.py
```

`hosts.yml` содержит под `all.children` ровно три группы: `exit`, `relay`, `cp`.
Хосты задаются только внутри этих групп; один хост не может входить в две группы.
Переменные групп и хостов хранятся в файлах `group_vars/<группа>.yml` и
`host_vars/<хост>.yml` рядом с `hosts.yml`; каталоги вида `group_vars/<группа>/`
валидатор не поддерживает.

`ansible.cfg` включает проверку SSH host key (`host_key_checking = True`) и делает
неразбираемый inventory фатальной ошибкой. Вывод в YAML настроен встроенным
callback `ansible.builtin.default` с `callback_result_format = yaml`: короткое имя
`stdout_callback = yaml` относится к `community.general` и без этой коллекции
ломает запуск `ansible-playbook`.

## Контракт переменных

Переменные хоста — `ansible_host` (адрес SSH), `public_ipv4`, `public_ipv6` и
`node_role`. Они обязательны для `exit`, `relay` и для `cp` в режиме
`dedicated`. `node_role` должен соответствовать группе: `exit`, `relay` или
`control_plane` для `cp`. Если переменная задана и в `hosts.yml`, и в
`host_vars`, значения должны совпадать.

| Переменная | Допустимые значения | Где задаётся |
| --- | --- | --- |
| `cp_placement` | `exit`, `dedicated` | только `group_vars/all` |
| `client_family` | `v4`, `dual` | `all`, `relay` |
| `s2s_family` | `v6_prefer`, `v4_only`, `v6_only` | `all`, `relay` |
| `egress_family` | `v4_prefer`, `v6_prefer`, `v4_only` | `all`, `exit` |
| `egress_slots` | целое от 1 до 6 (слоты `egress-0…egress-5`) | `all`, `exit` |
| `slot_fanout` | `sni`, `ports` | `all` |
| `node_port_allow` | список CIDR без установленных битов хоста | `all` |
| `reality_sni` | DNS-имя | `all` или `host_vars` |
| `reality_target` | `host:port` или `[ipv6]:port`, порт 1–65535 | `all` или `host_vars` |
| `xhttp_path` | начинается с `/`, без пробелов | `all` или `host_vars` |
| `xhttp_mode` | `auto`, `packet-up`, `stream-up`, `stream-one` | `all` или `host_vars` |
| `image_tags` | mapping «компонент → тег», строки | `group_vars/all` |
| `panel_bind` | адрес привязки панели | `cp` |

Правила топологии:

- в `exit` и в `relay` ровно по одному хосту;
- `cp_placement: dedicated` — в `cp` ровно один хост, отличный от exit;
- `cp_placement: exit` — группа `cp` пустая: control plane работает на exit;
- все публичные адреса всех хостов уникальны (сравниваются в нормализованном виде).

Значения применяются в порядке приоритета ansible-core: переменные групп из
`hosts.yml`, затем `group_vars/all`, `group_vars/<группа>`, переменные хоста из
`hosts.yml` и `host_vars/<хост>`.

## Только синтетический пример

`inventories/example/` — обезличенная топология для проверки контракта, а не
описание рабочих серверов. Для каталога с именем `example` валидатор
дополнительно требует:

- адреса только из документационных диапазонов `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24` и `2001:db8::/32`;
- `ansible_host` равен документационному `public_ipv4` хоста;
- `reality_sni` оканчивается на `.example.com`;
- `node_port_allow` — только документационные или частные диапазоны
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`).

Не добавляйте в пример реальные имена хостов, адреса, домены, ключи, токены и
другие учётные данные.

## Рабочий inventory

Реальный inventory размещается только локально в
`ansible/inventories/production/`. Этот путь указан в `.gitignore`, а
`scripts/check_repository.py` блокирует публикацию путей inventory с `production`,
`prod` или `live`. **Никогда не коммитьте рабочий inventory**, даже частично или
временно: `.gitignore` не защищает уже добавленные в индекс файлы. Секреты в
inventory не хранятся.

Проверка локального рабочего inventory, без подключения к узлам:

```sh
.venv/bin/python ansible/scripts/validate_inventory.py \
  --inventory ansible/inventories/production/hosts.yml
```

Для него действуют общие правила контракта; правила примера не применяются.
Валидатор не печатает значения адресов в сообщениях об ошибках, но вывод с путями
рабочего inventory всё равно не публикуйте.

## Добавление хоста

1. Добавьте хост в нужную группу `hosts.yml` с `ansible_host`, `public_ipv4`,
   `public_ipv6` и `node_role`.
2. При необходимости создайте `host_vars/<хост>.yml` с теми же значениями адресов
   и роли или с переопределениями переменных узла.
3. Для `cp` проверьте `cp_placement` в `group_vars/all.yml`: хост в `cp`
   допустим только в режиме `dedicated`.
4. Выполните проверку из следующего раздела.

Контракт допускает ровно один exit и один relay; второй узел той же роли
потребует отдельного изменения контракта и валидатора.

## Локальная проверка

Нужны Python 3.11 или новее. Команды используют общую `.venv` в корне
репозитория; отдельное окружение в `ansible/` не создаётся.

```sh
make -C ansible bootstrap
make -C ansible validate
make -C ansible test
```

| Команда | Назначение |
| --- | --- |
| `make -C ansible bootstrap` | Создаёт `.venv`, если её нет, и устанавливает `requirements-ansible.txt`. |
| `make -C ansible validate` | `ansible-inventory -i inventories/example/hosts.yml --list` как проверка разбора, затем `validate_inventory.py`. |
| `make -C ansible test` | Unit-тесты валидатора на временных YAML-фикстурах; сеть не используется. |

При ошибке валидатор выводит путь к файлу и переменной и завершается с кодом 1.

## CI

Workflow [`.github/workflows/ansible.yml`](../.github/workflows/ansible.yml)
с job `Ansible inventory` запускается для каждого pull request и для push в
`master`. Он использует закреплённые по SHA `actions/checkout` и
`actions/setup-python`, права `contents: read`, не обращается к secrets и
выполняет `make -C ansible bootstrap`, затем `make -C ansible validate test`.
Job не входит в обязательные проверки защиты `master` (`Repository checks`,
`Secret scan`) и не заменяет их.
