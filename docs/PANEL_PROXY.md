# Loopback-эндпоинт панели: роль `panel_proxy`

Документ описывает роль `ansible/roles/panel_proxy` и playbook
`ansible/playbooks/panel_proxy.yml`. Роль ставит перед панелью Remnawave
nginx-vhost, который слушает **только loopback** и передаёт панели заголовки,
без которых она отклоняет запросы. Публичного адреса у эндпоинта нет: вход
остаётся через SSH-туннель, как требует [архитектурный план](ARCHITECTURE_PLAN.md).

## Зачем это нужно

Панель 3.4.10 отвечает на прямой запрос к `http://127.0.0.1:3000` пустым
ответом (curl получает код `000`), а с заголовками `X-Forwarded-For` и
`X-Forwarded-Proto: https` — `200`. Поэтому между оператором и панелью нужен
reverse proxy. Держать его на клиенте (python-скрипт, самоподписанный CA,
ручной запуск) — лишняя связка: роль переносит эту обязанность на сам хост,
где уже есть nginx из роли `cp_proxy`.

## Что разворачивается

| Объект | Содержимое |
| --- | --- |
| `/etc/nginx/sites-available/panel_proxy.conf` | vhost с одним `listen <loopback>:<port> ssl` и `proxy_pass` на панель. |
| `/etc/panel-proxy/tls/ca.pem` | Приватный CA (публичный материал, `0644`). |
| `/etc/panel-proxy/tls/ca.key` | Ключ CA (`0600`, остаётся на хосте). |
| `/etc/panel-proxy/tls/server.pem`, `server.key` | Листовой сертификат для `IP:127.0.0.1`/`DNS:localhost`, ключ `0600`. |
| `/usr/local/lib/panel-proxy/panel_proxy_tls.py` | Идемпотентный выпуск и продление сертификата. |
| `panel-proxy-cert-renew.{service,timer}` | Ежемесячная проверка срока; при выпуске — reload nginx. |

Заголовки, которые vhost передаёт панели, **перезаписываются**, а не
дополняются: `X-Forwarded-For $remote_addr` (клиент не может подставить свой
адрес), `X-Forwarded-Proto https`, `X-Forwarded-Host`, `X-Forwarded-Port`,
`X-Remnawave-Client-Type`. WebSocket/SSE работают через `Upgrade`/`Connection`.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `panel_proxy_bind` | `127.0.0.1` | Только `127.0.0.0/8` или `::1`; иное отклоняется. |
| `panel_proxy_port` | `7443` | Порт loopback-эндпоинта, 1–65535. |
| `panel_proxy_upstream` | `127.0.0.1:3000` | Контракт `panel_bind:panel_port` роли `remnawave_panel`. |
| `panel_proxy_server_name` | `localhost` | Имя в сертификате и `server_name`. |
| `panel_proxy_client_type` | `browser` | Значение `X-Remnawave-Client-Type`. |
| `panel_proxy_tls_dir` | `/etc/panel-proxy/tls` | Каталог TLS-материала, `0750`. |
| `panel_proxy_ca_days` | `3650` | Срок жизни CA. |
| `panel_proxy_certificate_days` | `397` | Срок жизни листового сертификата. |
| `panel_proxy_renew_before_days` | `30` | Окно продления; должно быть меньше срока сертификата. |
| `panel_proxy_client_max_body_size` | `16m` | Лимит тела запроса. |
| `panel_proxy_verify` | `true` | Проверять `https://<bind>:<port>/` собственным CA после рендера. |

Роль отказывается работать, если `panel_proxy_upstream` равен адресу
прослушивания: это означало бы прокси на самого себя.

## Порядок выполнения и откат

1. Проверка переменных (loopback, диапазоны, пути, окно продления).
2. Установка пакета `nginx`, если его нет.
3. Выпуск TLS-материала; повторный запуск без истечения срока и смены identity
   даёт `changed=false`.
4. Рендер vhost с `backup: true`, `nginx -t` и reload. При отказе `nginx -t`
   файл восстанавливается (или удаляется, если он новый), nginx не
   перезагружается — та же схема, что в роли `cp_proxy`.
5. Проверка: `curl --cacert ca.pem https://<bind>:<port>/` должен вернуть `200`.

Откат: удалить `sites-enabled/panel_proxy.conf`, выполнить `nginx -t` и
`systemctl reload nginx`; TLS-каталог и таймер удалить отдельным действием.
Панель от этого не меняется — роль её не касается.

## Проверка

```sh
.venv/bin/python -m unittest discover -s ansible/roles/panel_proxy/tests -p 'test_*.py' -v
cd ansible && ../.venv/bin/ansible-playbook -i inventories/example/hosts.yml \
  playbooks/panel_proxy.yml --syntax-check
```

Тесты проверяют решения о продлении, SAN и приватность ключей, идемпотентность
выпуска, а также строки самого vhost: loopback-only `listen`, перезапись
`X-Forwarded-For`, WebSocket-заголовки и скобки для IPv6.

Рабочий запуск на подготовленном хосте:

```sh
cd ansible
../.venv/bin/ansible-playbook -i inventories/production/hosts.yml \
  playbooks/panel_proxy.yml --check --diff
# после просмотра diff — тот же запуск без --check --diff
```

Вход с рабочей машины:

```sh
ssh -L 7443:127.0.0.1:7443 <cp-host>
# сертификат CA один раз импортируется в trust store клиента
scp <cp-host>:/etc/panel-proxy/tls/ca.pem ./panel-ca.pem
open https://127.0.0.1:7443/
```

## Чего роль не делает и что не проверено

- Не публикует панель наружу и не меняет firewall и SSH роли `base`.
- Не настраивает второй фактор и не заменяет защиту панели: доступ остаётся
  сетевым (SSH-туннель), а не публичным.
- Не выполняет автоматическую проверку на настоящем nginx в CI: unit-тесты
  статичны, `nginx -t` и `curl`-проверка выполняются только при реальном
  запуске на хосте.
