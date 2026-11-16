# Loopback-эндпоинт панели: роль `panel_proxy`

Документ описывает роль `ansible/roles/panel_proxy` и playbook
`ansible/playbooks/panel_proxy.yml`. Роль ставит перед панелью Remnawave
nginx-vhost, который слушает **только loopback** и передаёт панели заголовки,
без которых она отклоняет запросы. Публичного адреса у эндпоинта нет, TLS не
терминируется: вход идёт через SSH-туннель, как требует
[архитектурный план](ARCHITECTURE_PLAN.md).

## Зачем это нужно

Панель 3.4.10 отвечает на прямой запрос к `http://127.0.0.1:3000` пустым
ответом (curl получает код `000`), а с заголовками `X-Forwarded-For` и
`X-Forwarded-Proto: https` — `200`. Поэтому между оператором и панелью нужен
reverse proxy. Держать его на клиенте (python-скрипт и ручной запуск) — лишняя
связка: роль переносит эту обязанность на сам хост, где уже есть nginx из роли
`cp_proxy`.

## Почему без сертификата

Проверено на стенде: панель **не выставляет cookie** при логине (токен живёт в
localStorage), а `X-Forwarded-Proto: http` она отвергает так же, как отсутствие
заголовка. Значит нужен ровно один элемент — заголовок `https` от прокси.
Сертификат для этого не требуется: `http://127.0.0.1` — доверенный контекст
браузера, транспорт шифрует SSH-туннель, а CA в хранилище клиента не
добавляется вовсе. Первая редакция роли выпускала собственный CA и
короткоживущий лист; от этого отказались, и роль удаляет свои прежние
артефакты (см. ниже).

## Что разворачивается

| Объект | Содержимое |
| --- | --- |
| `/etc/nginx/sites-available/panel_proxy.conf` | vhost с одним `listen <loopback>:<port>` и `proxy_pass` на панель. |

Заголовки, которые vhost передаёт панели, **перезаписываются**, а не
дополняются: `X-Forwarded-For $remote_addr` (клиент не может подставить свой
адрес), `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port`,
`X-Remnawave-Client-Type`. WebSocket/SSE работают через `Upgrade`/`Connection`.

Роль удаляет артефакты прежней TLS-редакции, если они есть:
`/etc/panel-proxy` (включая приватные ключи), `/usr/local/lib/panel-proxy` и
юниты `panel-proxy-cert-renew.*`. Это собственность роли, а не операторские
файлы.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `panel_proxy_bind` | `127.0.0.1` | Только `127.0.0.0/8` или `::1`; иное отклоняется. |
| `panel_proxy_port` | `7443` | Порт loopback-эндпоинта, 1–65535. |
| `panel_proxy_upstream` | `127.0.0.1:3000` | Контракт `panel_bind:panel_port` роли `remnawave_panel`. |
| `panel_proxy_server_name` | `localhost` | `server_name` в vhost. |
| `panel_proxy_client_type` | `browser` | Значение `X-Remnawave-Client-Type`. |
| `panel_proxy_forwarded_proto` | `https` | `X-Forwarded-Proto`; панель принимает только `https`. |
| `panel_proxy_client_max_body_size` | `16m` | Лимит тела запроса. |
| `panel_proxy_verify` | `true` | Проверять `http://<bind>:<port>/` после рендера. |

Роль отказывается работать, если `panel_proxy_upstream` равен адресу
прослушивания: это означало бы прокси на самого себя.

## Порядок выполнения и откат

1. Проверка переменных (loopback, диапазоны, значения заголовков).
2. Установка пакета `nginx`, если его нет.
3. Удаление артефактов retired TLS-варианта.
4. Рендер vhost с `backup: true`, `nginx -t` и reload. При отказе `nginx -t`
   файл восстанавливается (или удаляется, если он новый), nginx не
   перезагружается — та же схема, что в роли `cp_proxy`.
5. Проверка: `curl http://<bind>:<port>/` должен вернуть `200`.

Откат: удалить `sites-enabled/panel_proxy.conf`, выполнить `nginx -t` и
`systemctl reload nginx`. Панель роль не меняет.

## Проверка

```sh
.venv/bin/python -m unittest discover -s ansible/roles/panel_proxy/tests -p 'test_*.py' -v
cd ansible && ../.venv/bin/ansible-playbook -i inventories/example/hosts.yml \
  playbooks/panel_proxy.yml --syntax-check
```

Тесты проверяют инварианты vhost: loopback-only `listen`, отсутствие любых
`ssl_*`-директив, перезапись `X-Forwarded-For` вместо `$proxy_add_x_forwarded_for`,
WebSocket-заголовки и скобки для IPv6.

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
open http://127.0.0.1:7443/
```

## Чего роль не делает и что не проверено

- Не публикует панель наружу и не меняет firewall и SSH роли `base`.
- Не завершает TLS и не трогает хранилище сертификатов клиента.
- Не настраивает второй фактор: доступ остаётся сетевым (SSH-туннель).
- Не выполняет проверку на настоящем nginx в CI: unit-тесты статичны,
  `nginx -t` и `curl`-проверка выполняются только при реальном запуске на хосте.
