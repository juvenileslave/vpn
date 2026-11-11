# Роль `cp_proxy`: прокси страницы подписки

Документ описывает задачу 2.2 [архитектурного плана](ARCHITECTURE_PLAN.md):
роль `ansible/roles/cp_proxy` и playbook `ansible/playbooks/cp_proxy.yml`.
Роль настраивает на хосте группы `cp` один nginx-vhost для отдельного имени
подписки: он завершает TLS и проксирует **только** префикс подписки на
loopback-адрес панели. Всё остальное, включая админку и API, отдаёт 404.

**Статус.** Роль проверена в одноразовом Ubuntu 24.04 с самоподписанным
сертификатом и stub-upstream (см. «Что проверено»). На реальном сервере,
с реальным DNS-именем, Let's Encrypt или работающей панелью она не запускалась.
Запуск playbook'а меняет nginx на целевом хосте: это production-действие,
и оно требует отдельного разрешения владельца.

## Зависимость от панели

Upstream — контракт роли панели из issue #20: панель слушает только
`panel_bind:panel_port` на loopback. `cp_proxy_upstream` должен совпадать с этим
адресом; роль принимает только `127.0.0.0/8` и `[::1]`. Роль не проверяет,
что панель действительно запущена: без неё префикс отвечает 502.

## Запуск

```sh
cd ansible
../.venv/bin/ansible-playbook --syntax-check playbooks/cp_proxy.yml
../.venv/bin/ansible-playbook -i <inventory> playbooks/cp_proxy.yml --check --diff
../.venv/bin/ansible-playbook -i <inventory> playbooks/cp_proxy.yml
```

Роль подключается по пути (`{{ playbook_dir }}/../roles/cp_proxy`), потому что
общий `ansible.cfg` не задаёт `roles_path`. Переменные роли задаются в рабочем
inventory (`host_vars`) или через `-e`; example inventory их не содержит,
поэтому запуск на нём останавливается на проверке переменных.

## Переменные

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `cp_proxy_server_name` | — (обязательна) | DNS-имя vhost: строчные буквы, минимум одна точка; без wildcard, IP, порта и завершающей точки. |
| `cp_proxy_upstream` | — (обязательна) | `127.x.y.z:port` или `[::1]:port` — `panel_bind:panel_port` панели. |
| `cp_proxy_path_prefix` | `/sub/` | Публичный префикс; начинается и заканчивается `/`, без `.`/`..`; не может начинаться с `/api/`, `/admin/`, `/.well-known/`. |
| `cp_proxy_upstream_path` | = `cp_proxy_path_prefix` | Путь на upstream, в который отображается префикс (например, `/api/sub/`). |
| `cp_proxy_acme` | `false` | Режим сертификата (см. ниже). |
| `cp_proxy_certificate_path`, `cp_proxy_key_path` | `""` | Абсолютные пути к готовым сертификату (fullchain) и ключу; только при `cp_proxy_acme: false`. |
| `cp_proxy_acme_email` | `""` | Email ACME-аккаунта; обязателен при `cp_proxy_acme: true`. |
| `cp_proxy_acme_agree_tos` | `false` | Явное согласие с условиями Let's Encrypt; должно быть строго `true`. |
| `cp_proxy_acme_staging` | `false` | `--test-cert` (staging-сервер Let's Encrypt). |
| `cp_proxy_acme_expected_ipv4` | `public_ipv4` хоста | Адрес, на который обязано указывать имя (A). Переопределяется, только если HTTP-01 принимает задокументированный внешний прокси/DNAT. |
| `cp_proxy_acme_expected_ipv6` | `public_ipv6` хоста или `""` | Допустимый AAAA. Если пусто, AAAA-записей быть не должно. |
| `cp_proxy_acme_nss_service` | `dns` | Источник для `getent -s`: `dns` игнорирует `/etc/hosts`. `files` — только для тестов. |
| `cp_proxy_acme_webroot` | `/var/www/cp_proxy-acme` | Каталог для `/.well-known/acme-challenge/`. |
| `cp_proxy_listen_ipv6` | `true` | Слушать также `[::]:80` и `[::]:443`. |
| `cp_proxy_hsts` / `cp_proxy_hsts_max_age` | `false` / `31536000` | HSTS выключен по умолчанию. |
| `cp_proxy_client_max_body_size` | `64k` | Лимит тела запроса. |
| `cp_proxy_proxy_connect_timeout` / `_send_timeout` / `_read_timeout` | `5s` / `30s` / `30s` | Таймауты upstream. |

Порты 80/443 и пути файлов сайта фиксированы в `vars/main.yml`.

## Режимы сертификата

**`cp_proxy_acme: false` (по умолчанию).** Оператор заранее кладёт сертификат и
ключ на хост; роль их только проверяет и никогда не создаёт ключи. Проверки до
изменения nginx: оба файла существуют и являются обычными файлами; сертификат
без права записи для группы и остальных; ключ принадлежит root и имеет режим
`0600` или `0640`; сертификат не истёк (`openssl x509 -checkend 0`) и покрывает
`cp_proxy_server_name` (`openssl x509 -checkhost`). Соответствие ключа
сертификату проверяет `nginx -t`. Обращений к ACME нет, certbot не ставится.

**`cp_proxy_acme: true`.** Порядок:

1. Проверка переменных: пути сертификата пусты, задан email,
   `cp_proxy_acme_agree_tos: true`, задан ожидаемый IPv4.
2. DNS preflight через `getent -s dns ahostsv4|ahostsv6`: набор A-записей
   должен быть ровно `[cp_proxy_acme_expected_ipv4]`, AAAA — пуст или ровно
   `[cp_proxy_acme_expected_ipv6]`. При несовпадении play останавливается
   **до** установки certbot и любого запроса к ACME.
3. Установка `certbot` из пакетов дистрибутива.
4. Если `/etc/letsencrypt/live/<имя>/fullchain.pem` ещё нет: временный
   HTTP-only сайт (только challenge, остальное 404), reload, затем
   `certbot certonly --webroot` строго для одного `--domain <имя>` с
   `--email`, `--agree-tos`, `--non-interactive`, `--keep-until-expiring` и
   deploy-hook `nginx -t && service nginx reload`. `--standalone` не
   используется, имена кроме `cp_proxy_server_name` не запрашиваются.
5. Рендер полного TLS-сайта с файлами из `/etc/letsencrypt/live/<имя>/`.

Продление выполняет таймер пакета certbot; роль его не настраивает.

## Что делает vhost

- HTTP (80): `/.well-known/acme-challenge/` отдаётся из webroot (во всех
  режимах), всё остальное — `301` на `https://<имя><uri>`.
- HTTPS (443): TLS 1.2/1.3, шифры ECDHE с AEAD (Mozilla intermediate),
  без session tickets, `server_tokens off`, HSTS только при `cp_proxy_hsts`.
- `location ^~ <префикс>` → `proxy_pass http://<upstream><upstream_path>` с
  `Host`, `X-Real-IP`, `X-Forwarded-For` (перезаписывается адресом клиента),
  `X-Forwarded-Proto: https`, `X-Forwarded-Host`, `X-Forwarded-Port`;
  ограниченные таймауты и тело; кеширование выключено, `Cache-Control`
  upstream заменяется на `no-store`. Разрешены только `GET`/`HEAD`
  (остальное — 403). Явный URI в `proxy_pass` заставляет nginx передавать
  нормализованный путь, поэтому `/sub/../api/x` не уходит в upstream.
- Запрос без завершающего `/` (`/sub`) nginx перенаправляет на `/sub/` —
  стандартное поведение для такого `location`.
- Все остальные пути, включая админку и API, — 404. Запрос на HTTPS с чужим
  `Host` — 421 (vhost может оказаться сервером по умолчанию для порта 443).

Ограничение nginx: `ssl_protocols` для порта берётся из сервера по умолчанию
этого порта. Если другой vhost объявлен `default_server` на 443, минимальная
версия TLS определяется его настройками.

## Чужие vhost'ы и конфликты

Роль владеет только `/etc/nginx/sites-available/cp_proxy.conf` и ссылкой
`/etc/nginx/sites-enabled/cp_proxy.conf`. `sites-enabled/default`, `conf.d` и
другие сайты не меняются. Перед записью модуль роли
`cp_proxy_nginx_preflight` разбирает вывод `nginx -T` (без файлов роли) и
останавливает play, если:

- текущая конфигурация nginx невалидна;
- файл сайта уже существует без маркера `Managed by Ansible role cp_proxy`;
- другой `server` в `http` на порту 80/443 обслуживает то же имя (точное,
  `*.domain`, `.domain`, `name.*` или regex);
- другой сервер слушает 443 без `ssl`, 80 с `ssl`, использует
  `proxy_protocol` на этих портах или `stream`-сервер занимает эти порты.

Конфликт не исправляется автоматически: оператор решает его вручную.

## Применение, идемпотентность и откат

Шаблон записывается атомарно (временный файл и rename) с резервной копией
`cp_proxy.conf.<pid>.<время>~` в `sites-available` (nginx её не подключает).
После изменения файла или ссылки выполняется `nginx -t` для всей конфигурации.
Если проверка не проходит, роль сама восстанавливает предыдущий файл (или
удаляет только что созданные файл и ссылку) и завершается ошибкой; reload не
выполняется, работающий nginx продолжает обслуживать старую конфигурацию.
Reload — только handler по изменению. Повторный запуск без изменений даёт
`changed=0`.

Ручной откат к предыдущей версии сайта:

```sh
ls -t /etc/nginx/sites-available/cp_proxy.conf.*~ | head -1   # последняя копия
cp -p /etc/nginx/sites-available/cp_proxy.conf.<pid>.<время>~ /etc/nginx/sites-available/cp_proxy.conf
nginx -t && systemctl reload nginx
```

Полное отключение сайта: `rm /etc/nginx/sites-enabled/cp_proxy.conf`, затем
`nginx -t && systemctl reload nginx`. Сертификаты, ACME-аккаунт и пакеты при
откате не трогаются. Откат репозитория — отдельный PR с revert squash-коммита.

## Что проверено

В одноразовом контейнере Ubuntu 24.04 (nginx 1.24 из пакетов, ansible-core
2.19.15, `ansible_connection: local`), без реального DNS и сети ACME:

- сертификат и ключ генерировались `openssl req -x509` во время теста вне
  репозитория; заранее существовал чужой vhost (80 и 443 ssl) и
  `sites-enabled/default`;
- первый запуск — `changed=4`, повторный и `--check` — `changed=0`;
  `nginx -t` проходит;
- `curl --resolve`: HTTP → `301 https://…`; challenge-файл по HTTP — 200;
  `/sub/abc123?x=1` проксируется на stub с ожидаемыми `Host` и
  `X-Forwarded-*`, ответ с `Cache-Control: no-store`; `/`, `/admin`,
  `/api/…`, `/api/sub/…`, challenge по HTTPS, `/sub/../api/x` — 404;
  `POST` — 403; чужой `Host` — 421; TLS 1.1 отклоняется сервером
  (`alert protocol version`), TLS 1.2 работает; HSTS отсутствует;
- чужой vhost и сайт по умолчанию отвечают как раньше, их файлы не изменены;
- отказ без изменений: дубль `server_name`, wildcard `*.domain`, `listen 443`
  без `ssl`, неуправляемый файл на месте сайта, wildcard-имя, не-loopback
  upstream, префикс `/api/`, ключ с режимом `0644`, сертификат на другое имя;
- несовпадение ключа и сертификата: `nginx -t` падает, предыдущий файл
  восстановлен (хеш совпадает), nginx продолжает отвечать;
- ACME: несовпадение DNS (имя в `/etc/hosts` при
  `cp_proxy_acme_nss_service: files`) и отсутствие `agree_tos` останавливают
  play; certbot после этого не установлен, `/etc/letsencrypt` не создан.

## Ограничения проверки ACME

Успешная ветка ACME не выполнялась: не было запросов к Let's Encrypt (включая
staging), реального DNS-имени и публичного адреса. Не проверены: выпуск
сертификата, HTTP-only bootstrap с последующим переключением на TLS, deploy-hook
и продление, поведение preflight с реальным DNS (`-s dns`) и за внешним
прокси. Не проверен и запуск под systemd: в тестовом контейнере nginx
управлялся SysV-скриптом. Отображение префикса на реальный путь подписки
панели (`cp_proxy_upstream_path`) требует проверки с работающей панелью.
