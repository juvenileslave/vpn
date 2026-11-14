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
- `/var/www/cover-site-acme/` — отдельный HTTP-01 webroot;
- `/usr/local/libexec/cover-site/` — validation/lifecycle;
- `/var/log/cover-site/` — отдельные Certbot logs;
- `cover-site-renew.service`, `cover-site-renew.timer`, `cover-site-recover.service`.

Другие vhosts, `nginx.conf`, default site, firewall и DNS не переписываются.
Настройка под тем же hostname на TCP/80, другой listener на private TLS port,
TCP/80 stream/TLS/PROXY protocol, чужой owned-path или невалидная текущая
nginx configuration приводят к отказу **до установки пакетов и persistent writes**.
Входные данные и статический контент проверяются на controller до host changes.
Read-only preflight использует временные helper-файлы только в `/run` и проверяет
**все** перечисленные persistent roots, helpers, units, enable links и sidecars.
Существующая директория принимается только с root-owned regular marker
`.cover-site-owner.json`, содержащим `owner: cover_site`, `schema: 1` и точный root.
Helpers и units дополнительно имеют явный `# Managed by cover_site`; проверяются
типы файлов/директорий, отсутствие symlink ancestors, неизвестных sidecars,
unit drop-ins и не принадлежащих роли enable links. Certbot live symlinks могут
ссылаться только на собственный archive; active/previous/enabled — на законченные
immutable releases с согласованным fingerprint. Чужие paths не становятся owned
из-за похожего имени. Неотмеченные старые установки автоматически не принимаются:
оператор отдельно разбирает их происхождение и сохраняет usable state, а не
использует роль как команду принудительного захвата ресурсов.

После полного preflight отсутствующие roots создаются через private staging,
fsync marker/directory и атомарный rename. Поэтому прерывание и повторный запуск
не оставляют root без durable ownership marker и не меняют чужие mode/content.
Модули, дочерние директории и units могут ещё отсутствовать при повторном входе;
роль достраивает только уже явно owned installation. Candidate inputs отделены
от checked `/etc/cover-site/settings.json`: renewal получает новые настройки
только после проверенной активации. Отказ и rollback сохраняют старые настройки
вместе с проверенными сайтом и сертификатом.

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

До первого bootstrap роль устанавливает и включает recovery unit, загружает
systemd configuration и запускает read-only/repair recovery. Bootstrap активирует
checked **HTTP-only** configuration: несуществующих TLS files и self-signed public
fallback нет. Этот промежуточный release никогда не предлагается как previous
TLS rollback target. Реальный Certbot `certonly --webroot` хранит account/lineage
отдельно в `/etc/cover-site/acme`. Проверяются срок, ровно один DNS SAN,
hostname/issuer chain, соответствие certificate/private key и fullchain.
Private key — root/0600; private snapshot directory — root/0700.
Ключи не копируются на controller, не печатаются lifecycle или Ansible tasks.

nginx читает **копию проверенного certificate/key из immutable release**, не
подвижные `live` symlinks Certbot. Поэтому неудачный renewal/deploy hook не
заменяет ранее активный сертификат даже при уже обновлённом Certbot lineage.

## Stage → check → activate и откат

Роль создаёт content snapshot по точному controller manifest: удалённый исходный
файл не остаётся публичным из-за старой staging copy. Fingerprint включает
content, inputs и certificate. Полностью записанный/fsync snapshot публикуется
атомарным rename из `.stage-*`; незавершённый staging не становится release и
не препятствует повторному входу. Неизменный release не переключается и не reload.

Кандидат сначала проверяется `nginx -t` на копии **всей текущей nginx
configuration с другими sites**. Затем journal `pending.json` durable-сохраняет
**active и distinct previous** (`old`, `previous`, `candidate`), атомарно
переключается owned enabled link, снова выполняется `nginx -t`, и только после
этого — настоящий systemd reload/start. Успешность подтверждают новый leaf
certificate, точное содержимое index по H1 и negotiated H2. Только после service
health активный release и renewal settings становятся checked; journal удаляется
с fsync directory. Reload refusal/невалидный кандидат восстанавливают active,
previous, settings, configuration, content и certificate; health проверяет
настоящий старый сервис, а не результат фиктивного reload. Прерывание между
записью previous и commit не теряет отдельный более старый rollback target.

`cover-site-recover.service` устанавливается/enabled **до первого HTTP/TLS
переключения**, ordered `Before=nginx.service` и required by nginx:
незаконченная транзакция восстанавливается перед запуском nginx при boot.
При первом interrupted install без checked active восстанавливается отсутствие
owned site; unchecked candidate не загружается. Ошибка recovery блокирует запуск
nginx через dependency, а не позволяет тихо загрузить незавершённый candidate.
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
допускает только previous **TLS** release, проверяет certificate/configuration,
reload и H1/H2 health и восстанавливает его настройки. После первой TLS установки
валидного previous ещё нет: команда отказывает без удаления TLS listener.
После двух проверенных TLS версий повторный rollback возвращает второй retained
release вместе с его certificate/content/settings. HTTP bootstrap не является
успешным откатом TLS-сайта.

Renewal timer включается только после checked TLS, запускается дважды в сутки
и сохраняет `RandomizedDelaySec=3600`. Managed `certbot renew` использует
`--no-random-sleep-on-renew`: собственная случайная пауза Certbot, даже в
noninteractive mode, иначе может исчерпать 180-секундный process deadline.
Рандомизацию уже обеспечивает owned timer; timeout не увеличен и renewal
не пропускается. Deployment hook проходит ту же stage/check/reload/health
транзакцию. Certbot может завершиться с кодом 0 при отказе deploy hook:
lifecycle дополнительно сверяет active snapshot с новым lineage и сигнализирует
ошибку при расхождении. Hook не полагается на один только exit code Certbot.

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

Internal canary считает **каждое принятое TCP connection**, а не только GET.
До negative probes отдельное настоящее direct TCP connection обязано попасть
в счётчик; затем positive control очищается. CONNECT, абсолютный URL и любые
методы/ошибки не могут незаметно обратиться к canary, просто не вызвав GET handler.

## Точные проверки и ограничения среды

Быстрые role-local проверки контента/nginx parser и filesystem-транзакций:

```sh
python3 -m unittest discover -s ansible/roles/cover_site/tests -p 'test_*.py'
```

`test_lifecycle.py` проверяет прерывания при записи previous/active/settings,
восстановление absence на first install, два TLS rollback targets и checked
settings, отказ HTTP rollback и read-only ownership/type validation.
Внешние сервисные команды в этих unit tests изолированы: это не nginx/ACME proof.

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

Проверяются H1/H2/GET/HEAD/TLS 1.2/1.3, реальный TCP canary против internal proxy,
host namespace reachability и отрицательный доступ из veth netns по IPv4/IPv6
с положительным HTTP control, first issuance, forced renewal/deploy, failed
HTTP-01, invalid config/certificate/reload, idempotence и unrelated sites.
`ownership_probe.py` вызывает настоящий Ansible playbook с чужими roots,
helpers, units, symlinks и sidecars, как до установки, так и в marked installation.
Негативные результаты требуют неизменности bytes, mode/uid/gid, inode/mtime и
набора ресурсов owned paths, nginx/systemd configuration и dpkg/apt state.
После first issuance rollback обязан отказать с сохранением настоящего TLS/H2.
Две content/settings версии и renewal snapshots проходят двусторонний TLS rollback.

Driver также вызывает `ansible/roles/cover_site/tests/reboot_guest.sh`: свежий
Ubuntu rootfs через debootstrap, isolated `systemd-nspawn --boot` guest и настоящие
`machinectl reboot` только этого randomly named guest, каждый с **новым boot ID**.
`interrupt_activation.py` запускает реальную lifecycle-транзакцию с настоящими
nginx validation/reload и network health; единственная test instrumentation —
process exit после durable link write. Driver отдельно проверяет first HTTP
switch (boot восстанавливает absence), first TLS commit (checked HTTP bootstrap,
без TLS rollback target) и later commit после замены previous pointer:
на boot восстанавливаются checked TLS, distinct older previous и settings.
Guest создаёт ещё две настоящие checked content/settings версии, включая другой
приватный порт, и проверяет их двусторонний rollback по TLS/H2 и unrelated site.
Синтетические certificate snapshots лишь дают guest-local lineage для staging;
это **не ACME доказательство**: real HTTP-01/renewal выполняет `runtime_vm.sh`.
Это **guest userspace reboot, не reboot host kernel или runner**. Helper отдельно
вызывается под тем же guard после применения synthetic `.example.test` site;
CA account, panel/node credentials не копируются. Это устойчивость сайта,
не доказательство reboot всей Xray/Docker stack.

Teardown booted guest запрещает новый restart через собственный stop marker.
Python supervisor владеет дочерним `systemd-nspawn` и передаёт stop даже при
in-flight launch до регистрации machine. Cleanup посылает сигнал только этому
проверенному direct-child supervisor через pidfd и ждёт его завершения, не убивая
ожидающий shell поверх работающего guest. Registered machine дополнительно
обязана иметь соответствующий owned rootfs.
Pidfd дочернего процесса удерживается от создания до reaping: пересылка stop
не адресует числовой PID, который мог быть переиспользован. Гонка нормального
выхода supervisor с проверкой identity/сигналом принимается только когда тот же
pidfd подтверждает exit; live identity mismatch по-прежнему отклоняется.
После этого проверяется отсутствие machine, обычным `umount` убираются только
канонические mounts внутри собственного временного каталога (сначала вложенные),
и лишь затем удаляется каталог. Force/lazy unmount и игнорирование cleanup ошибок
не используются. Ownership marker привязан к path/device/inode. Итоговый PASS
печатается **после** подтверждённого process/mount/directory cleanup; timeout либо
остаточный ресурс возвращает FAIL, а не преждевременное обещание успеха.


После интеграции владелец проверки запускает `make -C ansible validate test` и
однократный финальный `make check`. Реально выполненные результаты публикуются
в PR; наличие entry points/CI configuration само по себе не означает PASS.
Linux guest proof не разрешает production rollout и не заменяет отдельный
pilot на целевой платформе/сети.

Внешние gates исправленного сценария: свежий GitHub-hosted Ubuntu 24.04 с root,
systemd, netns/veth, systemd-nspawn/machinectl и разрешёнными cgroups; сеть до
public Ubuntu mirrors и pinned Go/Pebble modules. Нельзя подменять эти gates
existing VM, production DNS/CA или фиктивным service proof. Переиспользованный
CI-host с уже существующим owned state отклоняется. Сами исправления не являются
повторным успешным renewal/reboot прогоном; интегратор публикует фактический
результат полного driver и обязательных repository/secret checks.

## Источники синтаксиса и lifecycle

- [nginx listen/virtual server](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen): `listen ... ssl http2`, default vhost behaviour.
- [nginx HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html): ALPN/H2 и новая директива с 1.25.1.
- [nginx HTTPS](https://nginx.org/en/docs/http/configuring_https_servers.html): certificate/key и TLS protocol configuration.
- [Certbot webroot/renewal/custom CA](https://eff-certbot.readthedocs.io/en/stable/using.html): HTTP-01, deploy hook, отдельные directories, REQUESTS_CA_BUNDLE и hook exit semantics.
- [Certbot CLI renew flag](https://github.com/certbot/certbot/blob/main/certbot/src/certbot/_internal/cli/__init__.py): `--no-random-sleep-on-renew` устанавливает `random_sleep_on_renew=false`; jitter остаётся в owned systemd timer.
- [Pebble](https://github.com/letsencrypt/pebble/tree/v2.6.0): disposable ACME server, реальные challenges, issuer roots, AUTHZREUSE.
- [systemd container integration](https://systemd.io/WRITING_VM_AND_CONTAINER_MANAGERS/): isolated booted guest и machine-scoped systemd commands.
