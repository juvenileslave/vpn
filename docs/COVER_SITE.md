# Приватный статический TLS-сайт

Роль `ansible/roles/cover_site` устанавливает **настоящий nginx static origin**
за REALITY. Это не reverse proxy перед Xray и не самостоятельное доказательство
работоспособности VPN или защиты IP от блокировки. Публичный пользовательский
путь проверяется интеграцией профилей отдельно.

## Платформа и граница владения

Поддерживается Ubuntu 24.04 с nginx upstream **1.24.0**, включая обновления
безопасности пакета дистрибутива. Роль проверяет upstream version и наличие
модулей SSL/H2; другой nginx отклоняется. Используется синтаксис
`listen 127.0.0.1:<port> ssl http2`, применимый к 1.24.0, а не новая директива
`http2 on` из 1.25.1. TLS разрешён только 1.2/1.3. UDP, QUIC, H3 и Alt-Svc нет.

TLS слушает **только `127.0.0.1` в host network namespace**. Xray/RemnaNode
обязан работать в той же сетевой namespace (`network_mode: host`); loopback
в отдельной bridge namespace — другой адрес. Роль не открывает публичный
TLS backend и не исправляет несовместимую namespace публикацией порта.

Роль владеет:

- `/etc/nginx/sites-enabled/cover-site.conf` — атомарная ссылка на checked release;
- `/etc/cover-site/` — inputs и отдельный Certbot account/lineage;
- `/var/lib/cover-site/` — staging, immutable releases, active/previous и journal;
- `/var/www/cover-site-acme/.well-known/acme-challenge/` — HTTP-01 webroot;
- `/usr/local/libexec/cover-site/` — validation/lifecycle;
- `cover-site-renew.service`, `cover-site-renew.timer`, `cover-site-recover.service`.

Другие vhosts, `nginx.conf`, default site, firewall и DNS не переписываются.
Настройка под тем же hostname на TCP/80, другой listener на private TLS port,
TCP/80 stream/TLS/PROXY protocol, чужой owned-path или невалидная текущая
nginx configuration приводят к отказу **до записи site configuration**.
Входные данные и статический контент проверяются до установки пакетов.
Preflight читает существующие listeners/nginx через временные helper-файлы в
`/run` до установки пакетов и изменения persistent inputs. Candidate inputs
отделены от checked `/etc/cover-site/settings.json`: renewal получает новые
настройки только после проверенной активации. Отказ и rollback сохраняют
настройки предыдущего release вместе с его сайтом и сертификатом.

## Входные данные

| Переменная | Контракт |
|---|---|
| `reality_sni` | Существующая общая authority: одно lowercase DNS-имя, без wildcard/IP. Второго имени роли нет |
| `cover_tls_port` | Настоящее целое число 1–65535, default `9443`; boolean, SSH/80 и конфликты listener отклоняются |
| `cover_site_source` | Абсолютная директория на Ansible controller с законченным статическим сайтом |
| `cover_acme_email` | Локальный operator contact; реальные данные не помещать в Git/логи |
| `cover_acme_agree_tos` | Явное `true`: оператор принимает условия CA |
| `cover_acme_http_reachable` | Явное `true`: оператор подтвердил DNS и маршрутизацию public TCP/80 |
| `cover_acme_directory` | По умолчанию production ACME directory Let's Encrypt; публичный staging также допускается, но его не доверенный system CA сертификат не активируется |
| `cover_certificate_min_lifetime` | Не менее 3600 секунд; default 86400, проверяется до активации/health |

Статический `index.html` должен содержать title и содержательный текст; все
ссылки/ресурсы — локальные и существующие. Не допускаются symlinks, hidden files,
ключи, server-side executable files, iframe/object/form и внешние trackers.
Публичные примеры и CI содержат только вымышленный журнал. Ответственность
оператора — проверить весь предоставленный сайт: не включать VPN branding,
семейные/личные данные, panel/node/exporter links или subscription material.
Валидатор не заменяет содержательный security/content review.

Минимальные **синтетические** host vars (сам сайт оператор предоставляет отдельно):

```yaml
reality_sni: cover.example.test
cover_tls_port: 9443
cover_site_source: /srv/operator/approved-static-site
cover_acme_email: operator@example.test
cover_acme_agree_tos: true
cover_acme_http_reachable: true
```

`.example.test` не подходит для public issuance. Здесь он показывает только
форму inputs; CI использует локальный ACME. Для разрешённого rollout оператор
передаёт настоящий hostname/contact вне публичного репозитория. Playbook:
`ansible/playbooks/cover_site.yml`, группа `exit:relay`; роль также вызывается
по role path из интеграционного playbook. Production запуск требует отдельного
разрешения владельца на конкретную инфраструктуру.

## HTTP-01 и сертификаты

Public TCP/80 — rollout prerequisite, а не firewall policy этой роли. Оператор
заранее обеспечивает A/AAAA и входящий HTTP-01 до данного host. Challenge
обслуживается выделенным webroot без вмешательства в другие сайты.
Остальные запросы **к owned HTTP vhost** перенаправляются на фиксированное
`https://<reality_sni>$request_uri`; arbitrary Host/X-Forwarded-Host не становятся
redirect target. Неизвестный hostname на shared TCP/80 остаётся обычным nginx
vhost selection, включая прежний default site.

Bootstrap активирует checked HTTP-only configuration: несуществующих TLS files
и self-signed public fallback нет. Реальный Certbot `certonly --webroot` хранит
account/lineage отдельно в `/etc/cover-site/acme`. Проверяются срок, ровно один
DNS SAN, hostname/issuer chain, соответствие certificate/private key и
fullchain. Private key — root/0600; private snapshot directory — root/0700.
Ключи не копируются на controller, не печатаются lifecycle или Ansible tasks.

nginx читает **копию проверенного certificate/key из immutable release**, не
подвижные `live` symlinks Certbot. Поэтому неудачный renewal/deploy hook не
заменяет ранее активный сертификат даже при уже обновлённом Certbot lineage.

## Stage → check → activate и откат

Роль создаёт content snapshot по точному controller manifest: удалённый исходный
файл не остаётся публичным из-за старой staging copy. Fingerprint включает
content, inputs и certificate. Неизменный release не переключается и не reload.

Кандидат сначала проверяется `nginx -t` на копии **всей текущей nginx
configuration с другими sites**. Затем journal `pending.json` сохраняет
previous checked release, атомарно переключается owned enabled link, снова
выполняется `nginx -t`, и только после этого — настоящий systemd reload/start.
Успешность подтверждают новый leaf certificate, точное содержимое index по H1
и negotiated H2. Только после service health активный release становится
checked; journal удаляется. Reload refusal/невалидный кандидат восстанавливают
предыдущую configuration, content и certificate; health проверяет настоящий
старый сервис, а не результат фиктивного reload.

`cover-site-recover.service` enabled и ordered `Before=nginx.service`:
незаконченная транзакция восстанавливается перед запуском nginx при boot.
Не удаляйте checked snapshots/Certbot archives вручную при аварийном откате.
Роль не удаляет предыдущие releases; их объём и retention контролирует оператор.

Команды на **разрешённом host**, от root:

```sh
/usr/local/libexec/cover-site/lifecycle.py health
/usr/local/libexec/cover-site/lifecycle.py rollback
/usr/local/libexec/cover-site/lifecycle.py renew
```

`health` выдаёт JSON hostname/port/TLS/H2/expiry без ключей. Это вход для будущей
диагностики; существующий bot/alert command не предполагается. `rollback`
проверяет previous configuration и переключает предыдущий checked release;
повторный rollback позволяет вернуть второй retained release.

Renewal timer запускается дважды в сутки с randomized delay. Deployment hook
проходит ту же stage/check/reload/health транзакцию. Certbot может завершиться
с кодом 0 при отказе deploy hook: lifecycle дополнительно проверяет, что
сертификат active snapshot совпал с новым lineage, и сигнализирует ошибку при
расхождении. Hook не полагается на один только exit code Certbot.

## Baseline и негативные запросы

На отдельном TLS listener есть один обычный static vhost:

| Запрос | Проверяемый baseline для pinned nginx |
|---|---|
| GET `/`, HEAD `/` | 200; GET содержит точный операторский index |
| Unknown path, `/panel`, `/sub`, `/metrics` без таких static files | 404 |
| POST/OPTIONS к существующему static `/` | 405 |
| Missing Host с HTTP/1.1 | 400 |
| Unknown Host на TLS listener | Обычный default vhost, static 200 для `/` |
| Missing/unknown SNI | Сертификат owned hostname; при verification другого имени — hostname mismatch |
| Absolute-form GET внутреннего URL | nginx static handling; внутренний canary upstream не вызывается |
| CONNECT к внутреннему адресу | Неуспех >=400; canary upstream не вызывается |

Это не искусственные универсальные ответы 200 и не forward proxy. Missing/SNI
probe может аутентифицировать owned certificate hostname отдельно от отправленного
SNI через `openssl -verify_return_error -verify_hostname`; chain и hostname
verification не отключаются. Штатные H1/H2/TLS probes проверяют CA и hostname.
Baseline не переносится автоматически на внешний REALITY endpoint.

## Точные проверки и ограничения среды

Быстрые role-local проверки контента/nginx parser:

```sh
python3 -m unittest discover -s ansible/roles/cover_site/tests -p 'test_*.py'
```

Полный service/certificate сценарий **только в свежем disposable
GitHub-hosted Ubuntu 24.04 systemd guest**, после `make -C ansible bootstrap`:

```sh
sudo env PATH="$PATH" HOME="$HOME" \
  GITHUB_ACTIONS="$GITHUB_ACTIONS" RUNNER_ENVIRONMENT="$RUNNER_ENVIRONMENT" \
  VPN_COVER_SITE_DISPOSABLE_GUEST=yes \
  bash ansible/roles/cover_site/tests/runtime_vm.sh
```

Driver отказывает без guard/hosted identity/root/systemd или при существующих
owned paths. Он устанавливает public packages и pinned **Pebble v2.6.0**,
генерирует временную API CA, получает generated Pebble issuer root, использует
local DNS/ACME с **реальным HTTP-01 TCP/80**. `PEBBLE_VA_ALWAYS_VALID` удаляется
из окружения, authorization reuse отключён. Public CA, public DNS и реальный
email не нужны. Два явных trust inputs разрешены только в этом guard:
`cover_acme_test_ca` для HTTPS ACME API и `cover_certificate_trust` для issuer
chain/origin; `cover_disposable_test: true` и directory
`https://localhost:14000/dir`. Нет `--no-verify-ssl`, `curl -k` или unverified TLS.

Проверяются H1/H2/GET/HEAD/TLS 1.2/1.3, реальный canary против internal proxy,
host namespace reachability и отрицательный доступ из veth netns по IPv4/IPv6
с положительным HTTP control, first issuance, forced renewal/deploy, failed
HTTP-01, invalid config/certificate/reload, idempotence и unrelated sites.

Driver также вызывает `ansible/roles/cover_site/tests/reboot_guest.sh`: свежий
Ubuntu rootfs через debootstrap, isolated `systemd-nspawn --boot` guest,
реальный `machinectl reboot` только этого randomly named guest, **новый boot ID**,
восстановление pending transaction перед nginx и повторные TLS/H2/unrelated-site
checks. Это **guest userspace reboot, не reboot host kernel или runner**.
Helper отдельно вызывается под тем же guard после применения synthetic
`.example.test` cover-site; не копирует CA account, panel/node credentials.
Это проверка устойчивости сайта; не доказательство reboot всей Xray/Docker stack.

После интеграции владелец проверки запускает `make -C ansible validate test` и
однократный финальный `make check`. Реально выполненные результаты публикуются
в PR; наличие entry points/CI configuration само по себе не означает PASS.
Linux guest proof не разрешает production rollout и не заменяет отдельный
pilot на целевой платформе/сети.

## Источники синтаксиса и lifecycle

- [nginx listen/virtual server](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen): `listen ... ssl http2`, default vhost behaviour.
- [nginx HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html): ALPN/H2 и новая директива с 1.25.1.
- [nginx HTTPS](https://nginx.org/en/docs/http/configuring_https_servers.html): certificate/key и TLS protocol configuration.
- [Certbot webroot/renewal/custom CA](https://eff-certbot.readthedocs.io/en/stable/using.html): HTTP-01, deploy hook, отдельные directories, REQUESTS_CA_BUNDLE и hook exit semantics.
- [Pebble](https://github.com/letsencrypt/pebble/tree/v2.6.0): disposable ACME server, реальные challenges, issuer roots, AUTHZREUSE.
- [systemd container integration](https://systemd.io/WRITING_VM_AND_CONTAINER_MANAGERS/): isolated booted guest и machine-scoped systemd commands.
