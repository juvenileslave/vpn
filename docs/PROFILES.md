# Профили Xray для exit

Документ описывает задачи 3.2, 3.3 и 3.5 [архитектурного плана](ARCHITECTURE_PLAN.md)
(issue #23): Git-шаблоны профилей Xray для узла `exit`, их локальный рендер и
проверку. **Профили не загружаются в панель и не применяются на серверах.**
Playbook работает только на машине оператора (`connection: local`): нет SSH,
нет обращений к API панели, нет изменений firewall или сервисов. Успешный рендер
и `xray -test` означают синтаксически корректную конфигурацию, а не работающий VPN.

## Состав

```text
ansible/
├── playbooks/profiles.yml               # локальный рендер для группы exit
├── roles/profiles/
│   ├── defaults/main.yml                # каталог вывода; список обязательных переменных
│   ├── vars/main.yml                    # фиксированные значения и маппинг egress_family
│   ├── tasks/{main,validate,render}.yml # проверка входов, затем рендер
│   └── templates/
│       ├── exit.json.j2                 # inbound direct (3.2)
│       ├── transit.json.j2              # inbound'ы transit-v4/transit-v6 (3.3)
│       └── partials/common.j2           # XHTTP+REALITY, freedom, routing (3.5)
└── scripts/tests/test_render_profiles.py
```

В плане для 3.2 указан путь `ansible/files/profiles/exit.json.j2`; по issue #23
шаблоны живут в роли `profiles`. Рендерятся два самостоятельных Xray-конфига:
`exit.json` и `transit.json`. Оба содержат одинаковые `outbounds` и `routing`.
Как они станут Config Profile в Remnawave (отдельные профили или объединение
inbound'ов), решается в задаче развёртывания профилей.

## Входные данные

Из контракта inventory ([ANSIBLE.md](ANSIBLE.md)): `reality_sni`, `reality_target`,
`xhttp_path`, `xhttp_mode`, `egress_family`, `egress_slots`. Дополнительно
обязательны без значений по умолчанию:

| Переменная | Значение |
| --- | --- |
| `exit_direct_port` | порт inbound `direct`, 1–65535 |
| `transit_port` | порт inbound'ов `transit-v4`/`transit-v6`, 1–65535, отличен от `exit_direct_port` |

Секреты передаются только извне Git — зашифрованным vault-файлом или
extra-vars-файлом за пределами репозитория:

| Переменная | Формат |
| --- | --- |
| `reality_private_key` | приватный ключ X25519 в base64url, 43 символа (`xray x25519`) |
| `reality_short_ids` | непустой список уникальных hex-строк чётной длины, 2–16 символов, нижний регистр |
| `exit_direct_client_ids` | непустой список уникальных UUID клиентов `direct` |
| `transit_client_ids` | ровно `egress_slots` уникальных UUID: `egress-0` … `egress-<egress_slots-1>` |

Перед рендером роль проверяет все значения и останавливается с точным
сообщением, ничего не записав. Отклоняются, в частности: порт вне 1–65535 или не
число; одинаковые `exit_direct_port` и `transit_port`; `reality_target` на
loopback-адресе с портом одного из inbound'ов (петля); `egress_slots` вне 1–6;
число `transit_client_ids`, не равное `egress_slots`; `egress_family` вне
`v4_prefer`, `v6_prefer`, `v4_only`; `xhttp_mode`, отличный от `stream-one`;
общие UUID у `direct` и `transit`. В сообщениях о секретах значения не выводятся.
Задачи рендера выполняются с `no_log` и без diff.

## Запуск

```sh
make -C ansible bootstrap
cd ansible
../.venv/bin/ansible-playbook playbooks/profiles.yml \
  -e '{"exit_direct_port": 8443, "transit_port": 8444}' \
  -e @/путь/вне/репозитория/profiles-secrets.yml --ask-vault-pass
```

Порты удобнее передавать JSON-формой `-e`: форма `key=value` даёт строки (они
тоже принимаются, если состоят из цифр). По умолчанию результат пишется в
`artifacts/profiles/<хост>/{exit,transit}.json` в корне репозитория: каталог
`/artifacts/` в `.gitignore` и запрещён политикой `make check`. Другой каталог
задаётся `-e profiles_output_dir=...`; выбирайте путь вне репозитория или
игнорируемый. Каталог создаётся с правами `0700`, файлы — `0600`.

Рендер детерминирован: JSON строится из структуры данных и выводится через
`to_nice_json` с сортировкой ключей, поэтому одинаковые входы дают побайтно
одинаковые файлы, а повторный запуск завершается с `changed=0`.

## Содержимое профилей

**`exit.json`, inbound `direct` (3.2).** VLESS на `0.0.0.0:<exit_direct_port>`,
`decryption: none`, клиенты `direct-<n>` без `flow`. Транспорт — XHTTP:
`xhttpSettings.path` из `xhttp_path`, `mode: stream-one`,
`xPaddingBytes: "100-1000"`. Безопасность — `security: reality` с
`dest` = `reality_target`, `serverNames` = [`reality_sni`], `privateKey`,
`shortIds`, `show: false`, `xver: 0`. Fingerprint `firefox` относится к хосту
подписки (клиентская сторона) и в серверный профиль не входит.

**`transit.json`, inbound'ы `transit-v4` и `transit-v6` (3.3).** Те же VLESS,
XHTTP и REALITY на одном `transit_port`: `transit-v4` слушает `0.0.0.0`,
`transit-v6` — `::` с `sockopt.v6only: true`, чтобы IPv6-сокет не занимал
IPv4-порт. Клиенты — служебные пользователи `egress-0` … `egress-<egress_slots-1>`
с UUID оператора и без `flow`. Профиль **не** ограничивает адреса источников:
доступ к `transit_port` только с адресов relay обеспечивает nftables на exit
(по плану — роль `base`, задача 1.2; в репозитории она ещё не реализована),
а не Xray. Сейчас все слоты выходят через `egress`; правила
«пользователь → outbound» для слотов 1…N появятся вместе с outbound'ами
апстримов (этап 7).

**Выход и маршрутизация (3.5), общие для обоих профилей.** На всех inbound'ах
включён sniffing (`http`, `tls`, `quic`, `routeOnly: true`); сниффер BitTorrent
Xray запускает при любом включённом sniffing. Outbound по умолчанию — `freedom`
с тегом `egress`, второй — `blackhole` с тегом `block`. Routing с
`domainStrategy: IPIfNonMatch` и правилами:

1. `ip: ["geoip:private"]` → `block`;
2. `protocol: ["bittorrent"]` → `block`.

Дополнительно `freedom.settings.finalRules` блокирует `geoip:private` уже после
разрешения имени, так что домен, указывающий в частную сеть, тоже не проходит.

Маппинг `egress_family` (поля проверены по исходникам и `xray -test` v26.11.9):

| `egress_family` | `streamSettings.sockopt.domainStrategy` у `freedom` | `finalRules` (`block`) |
| --- | --- | --- |
| `v4_prefer` | `UseIPv4v6` — A и AAAA, предпочтение IPv4 | `geoip:private` |
| `v6_prefer` | `UseIPv6v4` — A и AAAA, предпочтение IPv6 | `geoip:private` |
| `v4_only` | `ForceIPv4` — только A | `geoip:private`, `::/0` |

В v26.11.9 `freedom.settings.domainStrategy` и `targetStrategy` устарели: Xray
переносит их в `sockopt.domainStrategy` с предупреждением, поэтому шаблон сразу
использует `sockopt`. `domainStrategy` влияет только на домены; IPv6-литералы при
`v4_only` отсекает правило `::/0` в `finalRules`.

## Закреплённый Xray

| Версия | Архив | SHA2-256 |
| --- | --- | --- |
| [v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9) | `Xray-linux-64.zip` | `b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82` |
| v26.11.9 | `Xray-macos-arm64-v8a.zip` | `233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26` |

Суммы взяты из опубликованных файлов `.dgst` релиза; те же значения закреплены в
`test_render_profiles.py`. Бинарь в Git не добавляется: архив кладётся в
игнорируемый `.cache/xray/` (или путь задаётся `XRAY_ARCHIVE`).

```sh
mkdir -p .cache/xray
curl -fL -o .cache/xray/Xray-linux-64.zip \
  https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip
```

## Проверка

```sh
make -C ansible test
```

`test_render_profiles.py` запускает настоящий playbook на синтетическом example
inventory с секретами, сгенерированными на время теста во временном каталоге.
Тесты разбирают отрендеренный JSON и проверяют протоколы, `listen` и порты
inbound'ов, XHTTP `path`/`mode`/`xPaddingBytes`, REALITY `dest`/`serverNames`,
отсутствие `flow`, число клиентов `transit`, правила routing и выбранную
стратегию `egress` для каждого `egress_family`. Повторный рендер сравнивается
побайтно. Негативные случаи (порт, число слотов, семейство и другие) должны
завершаться ошибкой до записи файлов. Во всех запусках проверяется, что
значения секретов не попали в вывод Ansible.

`XrayRuntimeTest` сверяет SHA-256 архива с закреплённым, распаковывает его во
временный каталог и выполняет `xray -test -config` для `exit.json` и
`transit.json` при каждом `egress_family`, требуя `Configuration OK` без
предупреждений об устаревших полях. Если архива для платформы нет, тест
пропускается (`skipped`) — такую проверку нужно указывать как незапущенную.
CI-workflow не скачивает архив, поэтому в CI этот тест пропускается.
