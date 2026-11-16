#!/usr/bin/env bash
# End-to-end bootstrap check on a DISPOSABLE Debian/Ubuntu guest.
# It installs packages, removes any preinstalled Docker to exercise the pinned
# role install, changes sshd, users, the firewall, Docker and starts the panel.
# Never run it on a real node or the owner's machine.
#
# Usage: sudo VPN_BOOTSTRAP_DISPOSABLE_GUEST=yes \
#          GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
#          bash ansible/roles/bootstrap/tests/runtime_vm.sh key|password
set -euo pipefail

[[ "${VPN_BOOTSTRAP_DISPOSABLE_GUEST:-}" == "yes" ]] \
  || { echo "Только для одноразовой VM: задайте VPN_BOOTSTRAP_DISPOSABLE_GUEST=yes." >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "Нужен root." >&2; exit 2; }
[[ -d /run/systemd/system ]] || { echo "Нужен systemd." >&2; exit 2; }
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] \
  || { echo "Нужен явно обозначенный одноразовый GitHub-hosted Linux guest." >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo "Нужен Linux." >&2; exit 2; }

MODE=${1:-}
case "$MODE" in
  key|password) ;;
  *) echo "usage: runtime_vm.sh key|password" >&2; exit 2 ;;
esac

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ANSIBLE_DIR=$ROOT/ansible
AP=$ROOT/.venv/bin/ansible-playbook
PLAYBOOK=$ANSIBLE_DIR/playbooks/bootstrap.yml
WORK=$(mktemp -d)
CHOME=$WORK/controller-home
KNOWN=$CHOME/.ssh/known_hosts
INV=$WORK/inventory.yml
ACK=$WORK/ack.json
ADMIN=bootadmin
PANEL_HOST=cp-example
PANEL_PORT=13000
SSH_PORT=22

ROOT_PASSWORD=""
APP_SECRET=""
METRICS_PASS=""
POSTGRES_PASSWORD=""

step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }

cleanup() {
  rm -f /etc/sudoers.d/zz-ci-bootstrap-deny
  rm -rf "$WORK"
}
trap cleanup EXIT

redact() {  # file [secret ...]
  local file=$1 text
  shift
  text=$(cat "$file")
  for secret in "$@"; do
    [[ -n $secret ]] && text=${text//$secret/[redacted]}
  done
  printf '%s\n' "$text"
}
show_log() { redact "$1" "$ROOT_PASSWORD" "$APP_SECRET" "$METRICS_PASS" "$POSTGRES_PASSWORD"; }

SSH_BASE=(-o ConnectTimeout=10 -o IdentitiesOnly=yes
          -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=yes)
SSH_KEY=("${SSH_BASE[@]}" -o BatchMode=yes -o PasswordAuthentication=no
         -o KbdInteractiveAuthentication=no)
root_key_ssh() {
  ssh "${SSH_KEY[@]}" -i "$WORK/root_key" -p "$SSH_PORT" "root@127.0.0.1" "$@"
}
root_password_ssh() {
  SSHPASS="$ROOT_PASSWORD" sshpass -e ssh "${SSH_BASE[@]}" \
    -o PubkeyAuthentication=no -o PreferredAuthentications=password \
    -o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=1 \
    -p "$SSH_PORT" "root@127.0.0.1" "$@"
}
admin_ssh() {
  ssh "${SSH_KEY[@]}" -i "$WORK/admin_key" -p "$SSH_PORT" "$ADMIN@127.0.0.1" "$@"
}

assert_root_access() {
  if [[ $MODE == password ]]; then
    root_password_ssh true || fail "первоначальный root-доступ по паролю недоступен"
  else
    root_key_ssh true || fail "первоначальный root-доступ по ключу недоступен"
  fi
  ok "первоначальный root-доступ (${MODE}) работает"
}

assert_root_denied() {
  root_key_ssh true >/dev/null 2>&1 && fail "root-вход по ключу всё ещё разрешён"
  root_password_ssh true >/dev/null 2>&1 && fail "root-вход по паролю всё ещё разрешён"
  for setting in 'permitrootlogin no' 'passwordauthentication no' \
                 'kbdinteractiveauthentication no' 'pubkeyauthentication yes'; do
    sshd -T | grep -qix "$setting" || fail "sshd -T не подтверждает: $setting"
  done
  ok "root key/password закрыты, key-only администратор разрешён"
}

assert_admin_access() {
  local out uid
  out=$(admin_ssh 'id -un; id -u; sudo -n true') \
    || fail "новый key-only вход администратора или sudo -n не работает"
  [[ $(sed -n 1p <<<"$out") == "$ADMIN" ]] || fail "новый вход выполнен не тем пользователем"
  uid=$(sed -n 2p <<<"$out")
  [[ $uid =~ ^[0-9]+$ ]] || fail "UID администратора не получен"
  (( uid >= 1000 && uid != 0 )) || fail "UID администратора некорректен: $uid"
  ok "новый SSH-ключ $ADMIN, UID $uid, sudo -n"
}

assert_fresh() {
  getent passwd "$ADMIN" >/dev/null 2>&1 && fail "администратор создан при неверном вводе"
  [[ ! -e /etc/sudoers.d/vpn-base ]] || fail "sudoers создан при неверном вводе"
  [[ ! -e /etc/ssh/sshd_config.d/00-vpn-base.conf ]] || fail "SSH drop-in создан при неверном вводе"
  nft list table inet vpn_base >/dev/null 2>&1 && fail "firewall создан при неверном вводе"
  [[ ! -e /opt/remnawave ]] || fail "каталог панели создан при неверном вводе"
  assert_root_access >/dev/null
  ok "неверный ввод не изменил хост"
}

ansible_env=(env HOME="$CHOME" ANSIBLE_CONFIG="$ANSIBLE_DIR/ansible.cfg" ANSIBLE_NOCOLOR=1)
ap() {
  timeout "${AP_TIMEOUT:-2400}" "${ansible_env[@]}" \
    "$AP" -i "$INV" -e "@$ACK" "$@" "$PLAYBOOK"
}
ask_pass() {  # password log [args ...]
  local password=$1 log=$2 command rc
  shift 2
  command=$(printf '%q ' timeout "${AP_TIMEOUT:-2400}" "${ansible_env[@]}" \
    "$AP" --ask-pass -i "$INV" -e "@$ACK" "$@" "$PLAYBOOK")
  { sleep 4; printf '%s\n' "$password"; } | script -q -e -c "$command" /dev/null >"$log" 2>&1
  rc=$?
  sed -i 's/\r$//' "$log"
  return "$rc"
}
run_bootstrap() {  # log [args ...]
  local log=$1
  shift
  if [[ $MODE == password ]]; then
    ask_pass "$ROOT_PASSWORD" "$log" "$@"
  else
    ap "$@" >"$log" 2>&1
  fi
}

recap() { grep -E "^$1 +: ok=" "$2" | tail -1 || true; }
expect_all_changed_zero() {  # host log
  local lines
  lines=$(grep -E "^$1 +: ok=" "$2" || true)
  [[ -n $lines ]] || { show_log "$2"; fail "нет recaps для $1"; }
  if grep -Evq 'changed=0 +unreachable=0 +failed=0' <<<"$lines"; then
    show_log "$2"
    fail "не все plays на $1 идемпотентны"
  fi
  ok "все plays на $1: changed=0"
}
expect_changed() {  # host log count
  local line
  line=$(recap "$1" "$2")
  [[ -n $line ]] || { show_log "$2"; fail "нет recap для $1"; }
  grep -Eq "changed=$3 +unreachable=0 +failed=0" <<<"$line" \
    || { show_log "$2"; fail "ожидался changed=$3: $line"; }
  ok "$line"
}

docker_state() {
  local ids
  ids=$(docker ps -q --filter label=com.docker.compose.project=remnawave | sort)
  [[ -n $ids ]] || { echo "no-containers"; return 0; }
  # IDs are hex; word splitting is intentional.
  # shellcheck disable=SC2086
  docker inspect --format '{{.Id}} {{.State.StartedAt}}' $ids | sort
}

assert_panel() {
  local statuses eth_ip db_port
  statuses=$(docker ps --filter label=com.docker.compose.project=remnawave \
    --format '{{.Status}}')
  [[ $(grep -c '(healthy)' <<<"$statuses") -eq 3 ]] \
    || { printf '%s\n' "$statuses" >&2; fail "не все три сервиса healthy"; }
  ss -H -ltn | grep -q "127.0.0.1:$PANEL_PORT " \
    || fail "панель не слушает 127.0.0.1:$PANEL_PORT"
  if ss -H -ltn | grep -Eq "(0\.0\.0\.0|\[::\]):$PANEL_PORT "; then
    fail "порт панели опубликован на wildcard-адресе"
  fi
  if ss -H -ltn | grep -Eq ':(5432|6379) '; then
    fail "PostgreSQL или Valkey опубликованы на host-порту"
  fi
  curl -fsS --noproxy '*' --max-time 10 -o /dev/null \
    -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' \
    -H 'X-Remnawave-Client-Type: browser' "http://127.0.0.1:$PANEL_PORT/" \
    || fail "приватный loopback-эндпоинт панели не вернул 200"
  eth_ip=$(ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]; exit}')
  [[ -n $eth_ip ]] || fail "у гостя нет глобального IPv4 для проверки приватности"
  if curl -fsS --noproxy '*' --max-time 3 -o /dev/null \
       -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' \
       "http://$eth_ip:$PANEL_PORT/"; then
    fail "панель доступна с не-loopback адреса $eth_ip"
  fi
  for db_port in 5432 6379; do
    if timeout 3 bash -c "exec 3<>/dev/tcp/$eth_ip/$db_port" 2>/dev/null; then
      fail "порт $db_port доступен с $eth_ip"
    fi
  done
  [[ $(stat -c %a /opt/remnawave/panel.env) == 600 ]] || fail "panel.env не 0600"
  [[ $(stat -c %a /opt/remnawave/db.env) == 600 ]] || fail "db.env не 0600"
  grep -q "на $PANEL_HOST;" "$WORK/success.log" || fail "отчёт не назвал panel host"
  grep -q -- "-L $PANEL_PORT:127.0.0.1:$PANEL_PORT" "$WORK/success.log" \
    || fail "отчёт не дал команду SSH-туннеля"
  ok "панель healthy, только loopback, HTTP 200, БД/Valkey без host-портов"
}

step "Проверка предусловий одноразового гостя"
[[ -x $AP ]] || fail "сначала выполните make -C ansible bootstrap"
for tool in script sshpass ssh-keygen ssh-keyscan curl; do
  command -v "$tool" >/dev/null 2>&1 || fail "нужен $tool"
done
if [[ -r /etc/ufw/ufw.conf ]] \
   && grep -Eq '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/ufw/ufw.conf; then
  fail "UFW включён (ENABLED=yes); bootstrap не отключает чужой firewall"
fi
if systemctl is-active --quiet firewalld.service; then fail "firewalld активен; bootstrap не отключает чужой firewall"; fi
getent passwd "$ADMIN" >/dev/null 2>&1 && fail "гость не чистый: $ADMIN уже существует"
[[ ! -e /etc/sudoers.d/vpn-base ]] || fail "гость не чистый: /etc/sudoers.d/vpn-base"
[[ ! -e /etc/ssh/sshd_config.d/00-vpn-base.conf ]] || fail "гость не чистый: 00-vpn-base.conf"
nft list table inet vpn_base >/dev/null 2>&1 && fail "гость не чистый: inet vpn_base"
[[ ! -e /opt/remnawave ]] || fail "гость не чистый: /opt/remnawave"
ok "гость и инструменты готовы"

step "Подготовка тестового гостя"
apt-get update -q
apt-get install -y -q openssh-server iproute2 curl sshpass >/dev/null

# The GitHub image ships its own Docker. Purge it so the pinned docker role
# performs a real install; this is test preparation on a disposable guest.
step "Удаление предустановленного Docker (только одноразовый гость)"
systemctl stop docker.socket docker.service 2>/dev/null || true
if command -v snap >/dev/null 2>&1 && snap list docker >/dev/null 2>&1; then
  snap remove docker >/dev/null 2>&1 || fail "не удалось удалить snap Docker"
fi
for pkg in docker.io docker-ce docker-ce-cli docker-ce-rootless-extras \
           containerd.io containerd runc docker-buildx-plugin docker-scan-plugin \
           docker-compose-plugin docker-compose-v2 docker-compose podman-docker; do
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'ok installed'; then
    apt-get purge -y "$pkg" >/dev/null
  fi
done
rm -f /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.sources \
      /etc/docker/daemon.json
if grep -rlq 'download\.docker\.com' /etc/apt 2>/dev/null; then
  grep -rl 'download\.docker\.com' /etc/apt | xargs -r rm -f
fi
rm -rf /var/lib/docker /var/lib/containerd
command -v docker >/dev/null 2>&1 && fail "Docker всё ещё в PATH после очистки"
ok "предустановленный Docker удалён"

step "Настройка sshd и временных ключей (только гость)"
install -d -m 0755 /run/sshd
ssh-keygen -A
sed -i -E 's/^[[:space:]]*(PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication)[[:space:]].*/# bootstrap CI: &/' \
  /etc/ssh/sshd_config
cat > /etc/ssh/sshd_config.d/50-ci-bootstrap.conf <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
EOF
chmod 0644 /etc/ssh/sshd_config.d/50-ci-bootstrap.conf
sshd -t
sshd -T | grep -qix 'permitrootlogin yes' || fail "sshd не разрешает root для теста"
sshd -T | grep -qix 'passwordauthentication yes' || fail "sshd не разрешает пароль для теста"
systemctl enable ssh.service >/dev/null 2>&1 || true
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh.service
for _ in $(seq 20); do
  ss -H -ltn | grep -q ":$SSH_PORT " && break
  sleep 0.5
done
ss -H -ltn | grep -q ":$SSH_PORT " || fail "sshd не слушает $SSH_PORT"

ssh-keygen -q -t ed25519 -N '' -C ci-bootstrap-root -f "$WORK/root_key"
ssh-keygen -q -t ed25519 -N '' -C ci-bootstrap-admin -f "$WORK/admin_key"
chmod 600 "$WORK/root_key" "$WORK/admin_key"
install -d -m 0700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qF "$(cat "$WORK/root_key.pub")" /root/.ssh/authorized_keys \
  || cat "$WORK/root_key.pub" >> /root/.ssh/authorized_keys

install -d -m 0700 "$CHOME" "$CHOME/.ssh"
ssh-keyscan -T 10 -p "$SSH_PORT" 127.0.0.1 >"$KNOWN" 2>/dev/null
chmod 600 "$KNOWN"
[[ -s $KNOWN ]] || fail "ssh-keyscan не получил host key; неизвестный ключ не принимается автоматически"

ROOT_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
printf 'root:%s\n' "$ROOT_PASSWORD" | chpasswd
ok "sshd на $SSH_PORT, host key принят явно, root key/password готовы"

step "Генерация синтетических секретов панели вне репозитория"
APP_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
METRICS_PASS=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
POSTGRES_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
install -m 0600 /dev/null "$WORK/panel.env"
cat > "$WORK/panel.env" <<EOF
APP_SECRET=$APP_SECRET
METRICS_USER=metrics
METRICS_PASS=$METRICS_PASS
POSTGRES_USER=remnawave
POSTGRES_DB=remnawave
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
EOF
chmod 0600 "$WORK/panel.env"
ok "panel.env создан вне checkout с режимом 0600 (значения не печатаются)"

step "Синтетический inventory на 127.0.0.1:$SSH_PORT"
ROOT_KEY_LINE=""
ROOT_AUTH_ARGS=""
if [[ $MODE == key ]]; then
  ROOT_KEY_LINE="       ansible_ssh_private_key_file: \"$WORK/root_key\""
else
  # Force the password path for the initial root phase; administrator phases
  # put PubkeyAuthentication=yes first and ignore this inventory option.
  ROOT_AUTH_ARGS=" -o PubkeyAuthentication=no"
fi
cat >"$INV" <<EOF
all:
  vars:
       cp_placement: dedicated
       ansible_port: $SSH_PORT
       ansible_python_interpreter: /usr/bin/python3
       ansible_ssh_common_args: "-o UserKnownHostsFile=$KNOWN -o ConnectTimeout=10$ROOT_AUTH_ARGS"
$ROOT_KEY_LINE
       base_admin_users:
         - name: $ADMIN
           sudo: true
           authorized_keys:
             - "$(cat "$WORK/admin_key.pub")"
       bootstrap_admin_name: $ADMIN
       bootstrap_admin_private_key_file: $WORK/admin_key
       base_admin_sudo_nopasswd: true
       base_ssh_enabled: true
       base_firewall_enabled: true
       base_ssh_port: $SSH_PORT
       base_ssh_permit_root_login: "no"
       base_ssh_trusted_cidrs: ["198.51.100.0/24", "2001:db8:100::/64"]
       base_firewall_vpn_ports: []
       base_firewall_source_ports: []
       base_chrony_enabled: false
       base_unattended_upgrades_enabled: false
       base_bbr_enabled: false
       base_swap_enabled: false
       image_tags:
         remnawave_panel: "3.4.10"
         postgres: "18.6"
         valkey: "9.1.3-alpine"
       panel_bind: 127.0.0.1
       panel_port: $PANEL_PORT
       remnawave_panel_sub_public_domain: "sub.example.com"
       remnawave_panel_front_end_domain: "*"
       remnawave_panel_env_file: "$WORK/panel.env"
  children:
    exit:
      hosts:
        exit-example:
          ansible_host: 127.0.0.1
          public_ipv4: 192.0.2.10
          public_ipv6: 2001:db8:10::10
          node_role: exit
    relay:
      hosts:
        relay-example:
          ansible_host: 127.0.0.1
          public_ipv4: 198.51.100.20
          public_ipv6: 2001:db8:20::20
          node_role: relay
    cp:
      hosts:
        cp-example:
          ansible_host: 127.0.0.1
          public_ipv4: 203.0.113.30
          public_ipv6: 2001:db8:30::30
          node_role: control_plane
EOF

# The base firewall refuses to close undeclared listeners. On this disposable
# guest the remaining host services are acknowledged as intentionally closed.
step "Сбор портов, которые firewall закроет (явное подтверждение для гостя)"
python3 - "$ACK" <<'PY'
import json
import subprocess
import sys

output = subprocess.check_output(["ss", "-H", "-l", "-n", "-t", "-u"], text=True)
acknowledged = set()
for line in output.splitlines():
    fields = line.split()
    if len(fields) < 5:
        continue
    proto, local = fields[0], fields[4]
    host, _, port = local.rpartition(":")
    if not port.isdigit():
        continue
    if host.startswith("127.") or host in {"::1", "[::1]", "localhost"}:
        continue
    if proto == "tcp" and port == "22":
        continue
    acknowledged.add("%s/%s" % (proto, port))
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"base_firewall_acknowledged_closed_ports": sorted(acknowledged)}, handle)
print("Подтверждено закрытие:", ", ".join(sorted(acknowledged)) or "нет")
PY

step "Неверная конфигурация не начинает опасные изменения"
printf '%s\n' '{"image_tags": {"remnawave_panel": "latest", "postgres": "18.6", "valkey": "9.1.3-alpine"}}' \
  >"$WORK/bad-tags.json"
if AP_TIMEOUT=120 ap -e @"$WORK/bad-tags.json" >"$WORK/bad-tags.log" 2>&1; then
  show_log "$WORK/bad-tags.log"; fail "неверный image_tags принят"
fi
assert_fresh

printf '%s\n' '{"cp_placement": "exit"}' >"$WORK/bad-topology.json"
if AP_TIMEOUT=120 ap -e @"$WORK/bad-topology.json" >"$WORK/bad-topology.log" 2>&1; then
  show_log "$WORK/bad-topology.log"; fail "неверная topology принята"
fi
assert_fresh

printf '%s\n' '{"bootstrap_admin_private_key_file": "/nonexistent/bootstrap/key"}' \
  >"$WORK/bad-key.json"
if AP_TIMEOUT=120 ap -e @"$WORK/bad-key.json" >"$WORK/bad-key.log" 2>&1; then
  show_log "$WORK/bad-key.log"; fail "несуществующий admin key принят"
fi
assert_fresh

step "Отказ sudo нового администратора оставляет root и не включает hardening"
cat >/etc/sudoers.d/zz-ci-bootstrap-deny <<EOF
$ADMIN ALL=(ALL:ALL) !ALL
EOF
chmod 0440 /etc/sudoers.d/zz-ci-bootstrap-deny
visudo -cf /etc/sudoers.d/zz-ci-bootstrap-deny >/dev/null || fail "невалидный deny sudoers"
if run_bootstrap "$WORK/sudo-deny.log"; then
  show_log "$WORK/sudo-deny.log"; fail "bootstrap прошёл при запрещённом sudo администратора"
fi
getent passwd "$ADMIN" >/dev/null \
  || { show_log "$WORK/sudo-deny.log"; fail "администратор не был создан до gate"; }
assert_root_access
[[ ! -e /etc/ssh/sshd_config.d/00-vpn-base.conf ]] || fail "hardening применён после отказа"
nft list table inet vpn_base >/dev/null 2>&1 && fail "firewall применён после отказа"
[[ ! -e /opt/remnawave ]] || fail "панель установлена после отказа"
rm -f /etc/sudoers.d/zz-ci-bootstrap-deny
ok "отказ нового доступа не закрыл root и не начал hardening/панель"

step "Успешный bootstrap ($MODE)"
run_bootstrap "$WORK/success.log" || { show_log "$WORK/success.log"; fail "успешный bootstrap"; }
assert_admin_access
assert_root_denied
assert_panel

step "Повторный запуск при запрещённом root использует администратора"
docker_before=$(docker_state)
env_before=$(stat -c %Y /opt/remnawave/panel.env)
if [[ $MODE == password ]]; then
  ask_pass "wrong-$ROOT_PASSWORD" "$WORK/rerun.log" \
    || { show_log "$WORK/rerun.log"; fail "повторный запуск не прошёл через администратора"; }
else
  ap >"$WORK/rerun.log" 2>&1 \
    || { show_log "$WORK/rerun.log"; fail "повторный запуск не прошёл через администратора"; }
fi
expect_all_changed_zero "$PANEL_HOST" "$WORK/rerun.log"
[[ $(docker_state) == "$docker_before" ]] || fail "повторный запуск перезапустил контейнеры"
[[ $(stat -c %Y /opt/remnawave/panel.env) == "$env_before" ]] || fail "повторный запуск переписал panel.env"
assert_admin_access
assert_root_denied
ok "root не включался, администратор использован, changed=0 и без рестарта"

step "--check не меняет хост и не объявляет PASS без runtime-проверок"
if [[ $MODE == password ]]; then
  ask_pass "$ROOT_PASSWORD" "$WORK/check.log" --check --diff \
    || { show_log "$WORK/check.log"; fail "check mode"; }
else
  ap --check --diff >"$WORK/check.log" 2>&1 \
    || { show_log "$WORK/check.log"; fail "check mode"; }
fi
expect_changed "$PANEL_HOST" "$WORK/check.log" 0
[[ $(docker_state) == "$docker_before" ]] || fail "check mode перезапустил контейнеры"
assert_admin_access
ok "check mode: panel play changed=0, контейнеры и доступ не изменены"

step "Секреты не попали в вывод задач"
for secret in "$ROOT_PASSWORD" "$APP_SECRET" "$METRICS_PASS" "$POSTGRES_PASSWORD"; do
  [[ -n $secret ]] || continue
  if grep -R -F -l -- "$secret" "$WORK"/*.log >/dev/null 2>&1; then
    fail "секретное значение найдено в логах (значение не печатается)"
  fi
done
ok "root-пароль и секреты панели отсутствуют в логах"

step "ИТОГ"
echo "Bootstrap $MODE: root-key/password -> администратор -> hardening -> Docker -> private panel проверены."
