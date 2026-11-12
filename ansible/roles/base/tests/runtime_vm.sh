#!/usr/bin/env bash
# End-to-end check of the base role on a DISPOSABLE Debian/Ubuntu VM.
# It installs packages, creates users, enables the firewall and swap, and
# restarts nftables.service. Never run it on a real node.
set -euo pipefail

if [[ "${VPN_BASE_DISPOSABLE_GUEST:-}" != "yes" ]]; then
  echo "Только для одноразовой VM: задайте VPN_BASE_DISPOSABLE_GUEST=yes." >&2
  exit 2
fi
[[ $EUID -eq 0 ]] || { echo "Нужен root." >&2; exit 2; }
[[ -d /run/systemd/system ]] || { echo "Нужен systemd." >&2; exit 2; }
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] \
  || { echo "Нужен явно обозначенный одноразовый GitHub-hosted Linux guest." >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo "Нужен Linux." >&2; exit 2; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ANSIBLE_DIR=$ROOT/ansible
PLAYBOOK=$ANSIBLE_DIR/playbooks/base.yml
AP=$ROOT/.venv/bin/ansible-playbook
WORK=$(mktemp -d)
SERVICE=$ROOT/ansible/roles/base/tests/runtime_service.py
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for ns in trusted untrusted nated pmtu-router pmtu-client; do ip netns delete "$ns" 2>/dev/null || true; done
  # A fault-injection wrapper must never survive the scenario.
  if [[ -e $WORK/nft.real ]]; then mv "$WORK/nft.real" /usr/sbin/nft; fi
  if [[ -e $WORK/systemctl.real ]]; then mv "$WORK/systemctl.real" /usr/bin/systemctl; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
export ANSIBLE_CONFIG=$ANSIBLE_DIR/ansible.cfg ANSIBLE_NOCOLOR=1 DEBIAN_FRONTEND=noninteractive

# Documentation ranges only (RFC 5737 / RFC 3849).
HOST4=198.51.100.1 TRUST4=198.51.100.2 UNTRUST4=198.51.100.3
HOST6=2001:db8:100::1 TRUST6=2001:db8:100::2 UNTRUST6=2001:db8:100::3
VPN_TCP=18080 CLOSED_TCP=19090 SOURCE_TCP=18443 SOURCE_UDP=18444 V4_ONLY_TCP=18445
NAT4=198.51.100.5 NAT6=2001:db8:100::5

step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }
recap() { grep -E '^(localhost|guest) +: ok=' "$1" | tail -1; }
expect_changed() {  # log, expected changed count
  recap "$1" | grep -Eq "changed=$2 +unreachable=0 +failed=0" \
    || { cat "$1"; fail "ожидался changed=$2: $(recap "$1")"; }
  ok "$(recap "$1")"
}
local_play() { "$AP" -i localhost, -c local -e ansible_python_interpreter=/usr/bin/python3 "$@" "$PLAYBOOK"; }
in_ns() { ip netns exec "$@"; }
tcp_open() { in_ns "$1" timeout 5 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; }
http_get() { in_ns "$1" python3 "$SERVICE" get "$2" "$3" "${@:4}" >/dev/null 2>&1; }
udp_get() { in_ns "$1" python3 "$SERVICE" udp "$2" "$3" >/dev/null 2>&1; }
assert_access() {
  local addr
  for addr in "$HOST4" "$HOST6"; do
    http_get trusted "$addr" "$SOURCE_TCP" || fail "restricted TCP denied allowed source"
    http_get untrusted "$addr" "$SOURCE_TCP" && fail "restricted TCP exposed"
    udp_get trusted "$addr" "$SOURCE_UDP" || fail "restricted UDP denied allowed source"
    udp_get untrusted "$addr" "$SOURCE_UDP" && fail "restricted UDP exposed"
    http_get untrusted "$addr" "$VPN_TCP" || fail "public listener denied"
    tcp_open trusted "$addr" 22 || fail "trusted SSH denied"
    tcp_open untrusted "$addr" 22 && fail "untrusted SSH exposed"
  done
  http_get trusted "$HOST4" "$V4_ONLY_TCP" || fail "IPv4-only ACL denied IPv4"
  http_get trusted "$HOST6" "$V4_ONLY_TCP" && fail "IPv4-only ACL opened IPv6"
  ok "real TCP/UDP IPv4/IPv6 ACLs, public listener and SSH"
}
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=5 -o IdentitiesOnly=yes
          -o UserKnownHostsFile="$WORK/known_hosts" -o StrictHostKeyChecking=yes)

snapshot() {
  sysctl -n net.ipv4.ip_forward net.ipv6.conf.all.forwarding
  swapon --show=NAME --noheadings | sort
  nft list table inet canary
  nft list tables | grep -v 'inet vpn_base' | sort || true
  # The unattended-upgrades task owns the apt periodic files; they are not
  # part of the unrelated-state snapshot.
  for file in /etc/sysctl.conf /etc/ssh/sshd_config \
              /home/legacyop/.ssh/authorized_keys /etc/fstab; do
    if [[ -e $file ]]; then sha256sum "$file"; fi
  done
  getent passwd legacyop vpnadmin | cut -d: -f1,7
  getent shadow vpnadmin | cut -d: -f2
  systemctl is-active docker.service ufw.service 2>&1 || true
  if command -v ufw >/dev/null; then ufw status | head -1; fi
}

step "Подготовка тестовой VM"
. /etc/os-release
echo "Гость: $PRETTY_NAME, ядро $(uname -r)"
apt-get update -q
apt-get install -y -q openssh-server iproute2 iputils-ping nftables tcpdump ethtool >/dev/null
systemctl start ssh.service
ssh-keygen -q -t ed25519 -N '' -C ci-new -f "$WORK/admin_new"
ssh-keygen -q -t ed25519 -N '' -C ci-old -f "$WORK/admin_old"
ssh-keygen -q -t ed25519 -N '' -C ci-legacy -f "$WORK/legacy"
# Pre-existing accounts whose shell, password state and keys must survive.
useradd -m -s /bin/sh vpnadmin
useradd -m -s /bin/bash legacyop
for user in vpnadmin legacyop; do install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"; done
install -m 600 -o vpnadmin -g vpnadmin "$WORK/admin_old.pub" /home/vpnadmin/.ssh/authorized_keys
printf 'from="%s/24" %s\n' "${HOST4%.*}.0" "$(cat "$WORK/legacy.pub")" \
  | install -m 600 -o legacyop -g legacyop /dev/stdin /home/legacyop/.ssh/authorized_keys
nft add table inet canary
nft add chain inet canary input '{ type filter hook input priority 10; policy accept; }'
nft add rule inet canary input tcp dport 9 counter accept

ip link add vbr-test type bridge
ip link set vbr-test up
ip addr add "$HOST4/24" dev vbr-test
ip -6 addr add "$HOST6/64" dev vbr-test nodad
for ns in trusted untrusted; do
  ip netns add "$ns"
  ip link add "v-$ns" type veth peer name eth0 netns "$ns"
  ip link set "v-$ns" master vbr-test up
  ip -n "$ns" link set lo up
  ip -n "$ns" link set eth0 up
done
ip -n trusted addr add "$TRUST4/24" dev eth0
ip -n trusted -6 addr add "$TRUST6/64" dev eth0 nodad
ip -n untrusted addr add "$UNTRUST4/24" dev eth0
ip -n untrusted -6 addr add "$UNTRUST6/64" dev eth0 nodad
for _ in $(seq 20); do
  in_ns untrusted ping -c1 -W1 "$HOST4" >/dev/null 2>&1 && in_ns untrusted ping -c1 -W1 "$HOST6" >/dev/null 2>&1 && break
  sleep 1
done
in_ns trusted ssh-keyscan -T 5 "$HOST4" "$HOST6" > "$WORK/known_hosts" 2>/dev/null
[[ -s $WORK/known_hosts ]] || fail "ssh-keyscan не получил host key"
python3 "$SERVICE" serve --tcp "$VPN_TCP" "$SOURCE_TCP" "$V4_ONLY_TCP" --udp "$SOURCE_UDP" >/dev/null 2>&1 &
PIDS+=("$!")
for _ in {1..20}; do http_get trusted "$HOST4" "$VPN_TCP" && break; sleep 0.2; done
http_get trusted "$HOST4" "$SOURCE_TCP" || fail "restricted listener did not start"
snapshot > "$WORK/state.before"
# Preserving existing swap is only testable when the guest already has swap.
SWAP_PRESENT=false
if [[ -n $(swapon --noheadings) ]]; then SWAP_PRESENT=true; fi
SWAP_VARS='{"base_swap_enabled": true, "base_swap_file": "/var/tmp/vpn-base-ci.swap", "base_swap_size_mb": 128}'

cat > "$WORK/vars.json" <<EOF
{
  "base_admin_users": [{"name": "vpnadmin", "authorized_keys": ["$(cat "$WORK/admin_new.pub")"]}],
  "base_ssh_enabled": true,
  "base_firewall_enabled": true,
  "base_ssh_trusted_cidrs": ["$TRUST4/32", "$TRUST6/128"],
  "base_firewall_vpn_ports": [{"proto": "tcp", "port": $VPN_TCP}, {"proto": "udp", "port": 51820}],
  "base_firewall_source_ports": [
    {"proto": "tcp", "port": $SOURCE_TCP, "source_cidrs": ["$TRUST4/32", "$TRUST6/128", "$NAT4/32", "$NAT6/128"]},
    {"proto": "udp", "port": $SOURCE_UDP, "source_cidrs": ["$TRUST4/32", "$TRUST6/128"]},
    {"proto": "tcp", "port": $V4_ONLY_TCP, "source_cidrs": ["$TRUST4/32"]}
  ],
  "base_swap_enabled": $SWAP_PRESENT
}
EOF

step "Отказ при другой службе времени"
if dpkg-query -W -f='${Status}' systemd-timesyncd 2>/dev/null | grep -q 'ok installed'; then
  local_play -e '{"base_ssh_enabled": false, "base_firewall_enabled": false}' > "$WORK/timesync.log" 2>&1 \
    && { cat "$WORK/timesync.log"; fail "роль не отказала при systemd-timesyncd"; }
  grep -q 'роль не удаляет' "$WORK/timesync.log" || { cat "$WORK/timesync.log"; fail "нет сообщения об отказе"; }
  recap "$WORK/timesync.log" | grep -q 'changed=0' || fail "отказ после изменений"
  ok "chrony не заменяет systemd-timesyncd без оператора"
  # Test preparation only: replace the time daemon on this disposable VM.
  apt-get install -y -q chrony >/dev/null
else
  echo "systemd-timesyncd не установлен — сценарий отказа не применим."
fi

step "Отказ закрыть незаявленные слушающие порты"
local_play -e @"$WORK/vars.json" -e '{"base_firewall_vpn_ports": [], "base_firewall_source_ports": []}' > "$WORK/listeners.log" 2>&1 \
  && { cat "$WORK/listeners.log"; fail "роль не отказала при незаявленном порте"; }
recap "$WORK/listeners.log" | grep -q 'changed=0' || fail "отказ после изменений"
mapfile -t uncovered < <(grep -o 'слушающие порты [^.]*' "$WORK/listeners.log" | head -1 \
  | sed 's/слушающие порты //' | tr -d ' ' | tr ',' '\n')
printf '%s\n' "${uncovered[@]}" | grep -qx "tcp/$VPN_TCP" || { cat "$WORK/listeners.log"; fail "tcp/$VPN_TCP не обнаружен"; }
nft list table inet vpn_base >/dev/null 2>&1 && fail "таблица создана несмотря на отказ"
ok "незаявленные порты: ${uncovered[*]}"
# Remaining host listeners are acknowledged as closed for this test.
ack=$( { printf '%s\n' "${uncovered[@]}" | grep -Ev "^(tcp/($VPN_TCP|$SOURCE_TCP|$V4_ONLY_TCP)|udp/$SOURCE_UDP)$" || true; printf '%s\n' "tcp/$CLOSED_TCP"; } \
  | sort -u | sed 's/.*/"&"/' | paste -sd, -)
printf '{"base_firewall_acknowledged_closed_ports": [%s]}\n' "$ack" > "$WORK/ack.json"

# Use the real firewall role without unrelated package/user changes for faults.
cat > "$WORK/firewall-only.yml" <<EOF
---
- hosts: localhost
  gather_facts: false
  become: true
  tasks:
    - ansible.builtin.include_role:
        name: $ANSIBLE_DIR/roles/base
        tasks_from: firewall
EOF

step "Ошибка настоящего loader при первом применении удаляет только новое состояние"
[[ ! -e /etc/systemd/system/vpn-base-firewall.service && ! -L /etc/systemd/system/vpn-base-firewall.service ]] \
  || fail "одноразовый стенд уже содержит owned loader"
[[ ! -e /etc/vpn-base/firewall.nft ]] || fail "одноразовый стенд уже содержит owned policy file"
cat > "$WORK/loader-bad.nft" <<'EOF'
table inet vpn_base { chain input { type filter hook input priority filter; policy bogus; } }
EOF
cp -a "$ANSIBLE_DIR/roles/base" "$WORK/loader-failure-role"
cat >> "$WORK/loader-failure-role/templates/vpn-base-firewall.service.j2" <<EOF

[Service]
ExecStart=
ExecStart=/usr/sbin/nft -f $WORK/loader-bad.nft
EOF
cat > "$WORK/loader-failure.yml" <<EOF
---
- hosts: localhost
  gather_facts: false
  become: true
  tasks:
    - ansible.builtin.include_role:
        name: $WORK/loader-failure-role
        tasks_from: firewall
EOF
loader_since=$(date '+%Y-%m-%d %H:%M:%S')
if "$AP" -i localhost, -c local -e @"$WORK/vars.json" "$WORK/loader-failure.yml" > "$WORK/first-loader-failure.log" 2>&1; then
  fail "роль проигнорировала реальную ошибку ExecStart loader"
fi
grep -q 'Ошибка firewall на этапе Enable and start firewall loader' "$WORK/first-loader-failure.log" \
  || { cat "$WORK/first-loader-failure.log"; fail "отказ не достиг старта loader"; }
journalctl -u vpn-base-firewall.service --since "$loader_since" --no-pager > "$WORK/first-loader-journal.log"
grep -q 'status=1/FAILURE' "$WORK/first-loader-journal.log" \
  || { cat "$WORK/first-loader-journal.log"; fail "нет реального отказа процесса nft в loader"; }
nft list table inet vpn_base >/dev/null 2>&1 && fail "новая owned table осталась после отказа loader"
[[ ! -e /etc/vpn-base/firewall.nft ]] || fail "новый owned policy file остался после отказа loader"
[[ ! -e /etc/systemd/system/vpn-base-firewall.service && ! -L /etc/systemd/system/vpn-base-firewall.service ]] \
  || fail "новый owned loader остался после отказа"
systemctl is-active --quiet vpn-base-firewall.service && fail "новый loader остался активным"
systemctl is-enabled --quiet vpn-base-firewall.service && fail "новый loader остался enabled"
for addr in "$HOST4" "$HOST6"; do
  http_get untrusted "$addr" "$SOURCE_TCP" || fail "после first-loader rollback осталась ограничивающая политика"
  in_ns trusted ssh "${SSH_OPTS[@]}" -i "$WORK/admin_old" "vpnadmin@$addr" true || fail "SSH потерян после first-loader rollback"
done
snapshot > "$WORK/first-loader-state.after"
diff -u "$WORK/state.before" "$WORK/first-loader-state.after" || fail "loader failure изменил постороннее состояние"
ok "настоящий ExecStart отказал; новое состояние удалено, прежний доступ и SSH сохранены"

step "Первое применение (локально)"
local_play -e @"$WORK/vars.json" -e @"$WORK/ack.json" > "$WORK/apply1.log" 2>&1 \
  || { cat "$WORK/apply1.log"; fail "первое применение"; }
assert_access
grep -q 'Активный swap уже есть' "$WORK/apply1.log" && echo "Существующий swap сохранён без создания нового."
ok "$(recap "$WORK/apply1.log")"

cat > "$WORK/inventory.yml" <<EOF
all:
  hosts:
    guest:
      ansible_host: $HOST4
      ansible_user: vpnadmin
      ansible_ssh_private_key_file: $WORK/admin_new
      ansible_ssh_common_args: -o UserKnownHostsFile=$WORK/known_hosts -o IdentitiesOnly=yes
      ansible_python_interpreter: /usr/bin/python3
EOF
remote_play() { in_ns trusted "$AP" -i "$WORK/inventory.yml" -e @"$WORK/vars.json" -e @"$WORK/ack.json" "$@" "$PLAYBOOK"; }

step "Второе применение по SSH из доверенной сети"
remote_play > "$WORK/apply2.log" 2>&1 || { cat "$WORK/apply2.log"; fail "второе применение"; }
expect_changed "$WORK/apply2.log" 0

step "Check/diff по SSH"
remote_play --check --diff > "$WORK/check.log" 2>&1 || { cat "$WORK/check.log"; fail "check mode"; }
expect_changed "$WORK/check.log" 0

step "Свежие SSH-входы"
in_ns trusted ssh "${SSH_OPTS[@]}" -i "$WORK/admin_new" "vpnadmin@$HOST4" 'sudo -n true' || fail "новый ключ IPv4 + sudo"
ok "новый ключ IPv4 + sudo"
in_ns trusted ssh "${SSH_OPTS[@]}" -i "$WORK/admin_new" "vpnadmin@$HOST6" true || fail "новый ключ IPv6"
ok "новый ключ IPv6"
in_ns trusted ssh "${SSH_OPTS[@]}" -i "$WORK/admin_old" "vpnadmin@$HOST4" true || fail "существующий ключ"
ok "существующий ключ сохранён"
in_ns trusted ssh "${SSH_OPTS[@]}" -i "$WORK/legacy" "legacyop@$HOST4" true || fail "посторонний пользователь"
ok "посторонний пользователь сохранён"
if in_ns trusted ssh "${SSH_OPTS[@]}" -o PubkeyAuthentication=no \
     -o PreferredAuthentications=password,keyboard-interactive "vpnadmin@$HOST4" true 2> "$WORK/pw.err"; then
  fail "вход без ключа"
fi
grep -q 'Permission denied (publickey)' "$WORK/pw.err" || { cat "$WORK/pw.err"; fail "sshd предлагает не только publickey"; }
ok "sshd предлагает только publickey"
sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|permitemptypasswords) '

step "Поведение firewall IPv4/IPv6"
mkdir "$WORK/public-empty"
python3 -m http.server "$CLOSED_TCP" --bind :: --directory "$WORK/public-empty" >/dev/null 2>&1 &
PIDS+=("$!")
sleep 1
for addr in "$HOST4" "$HOST6"; do
  tcp_open untrusted "$addr" 22 && fail "SSH открыт недоверенному адресу ($addr)"
  tcp_open untrusted "$addr" "$VPN_TCP" || fail "VPN-порт закрыт ($addr)"
  tcp_open untrusted "$addr" "$CLOSED_TCP" && fail "незаявленный порт открыт ($addr)"
  tcp_open trusted "$addr" "$CLOSED_TCP" && fail "незаявленный порт открыт доверенному ($addr)"
  tcp_open trusted "$addr" 22 || fail "SSH закрыт доверенному ($addr)"
  ok "$addr: SSH только из доверенной сети, VPN-порт открыт, прочее закрыто"
done
ip -n untrusted neigh flush all
in_ns untrusted ping -c2 -W2 "$HOST4" >/dev/null || fail "ICMPv4 echo"
in_ns untrusted ping -c2 -W2 "$HOST6" >/dev/null || fail "ICMPv6 echo/ND после сброса neighbor cache"
ok "ICMPv4 и ICMPv6 (включая ND) проходят"
assert_access

step "Проверка заявленного NAT egress реальными источниками соединений"
ip netns add nated
ip link add v-nated type veth peer name eth0 netns nated
ip link set v-nated master vbr-test up
ip -n nated link set lo up
ip -n nated link set eth0 up
ip -n nated addr add 198.51.100.4/24 dev eth0
ip -n nated addr add "$NAT4/24" dev eth0
ip -n nated -6 addr add 2001:db8:100::4/64 dev eth0 nodad
ip -n nated -6 addr add "$NAT6/64" dev eth0 nodad
http_get nated "$HOST4" "$SOURCE_TCP" --source-address 198.51.100.4 && fail "undeclared pre-NAT IPv4 source admitted"
http_get nated "$HOST6" "$SOURCE_TCP" --source-address 2001:db8:100::4 && fail "undeclared pre-NAT IPv6 source admitted"
in_ns nated python3 "$SERVICE" peer "$HOST4" "$VPN_TCP" 198.51.100.4 --source-address 198.51.100.4
in_ns nated python3 "$SERVICE" peer "$HOST6" "$VPN_TCP" 2001:db8:100::4 --source-address 2001:db8:100::4
in_ns nated nft -f - <<EOF
table ip relay_nat {
  chain postrouting { type nat hook postrouting priority srcnat; policy accept;
    ip saddr 198.51.100.4 snat to $NAT4
  }
}
table ip6 relay_nat {
  chain postrouting { type nat hook postrouting priority srcnat; policy accept;
    ip6 saddr 2001:db8:100::4 snat to $NAT6
  }
}
EOF
in_ns nated python3 "$SERVICE" peer "$HOST4" "$SOURCE_TCP" "$NAT4" --source-address 198.51.100.4
in_ns nated python3 "$SERVICE" peer "$HOST6" "$SOURCE_TCP" "$NAT6" --source-address 2001:db8:100::4
ok "наблюдаемые NAT egress совпадают с явно заявленными /32 и /128"

step "Реальный IPv4/IPv6 PMTU и передача данных через уменьшенный MTU"
bash "$ROOT/ansible/roles/base/tests/runtime_pmtu.sh" "$WORK" "$VPN_TCP" "$SERVICE"

step "Сохранение постороннего состояния"
snapshot > "$WORK/state.after"
diff -u "$WORK/state.before" "$WORK/state.after" || fail "постороннее состояние изменилось"
ok "форвардинг, swap, таблицы nftables, файлы, пользователи и службы без изменений"

step "Эффективная конфигурация"
nft -c -f /etc/vpn-base/firewall.nft || fail "nft -c"
ok "nft -c"
systemctl is-enabled vpn-base-firewall.service
[[ $(sysctl -n net.ipv4.tcp_congestion_control) == bbr ]] || fail "BBR не активен"
ok "BBR"
systemctl is-active chrony.service
# unattended-upgrade may return 120 when another apt client holds a lock on
# the disposable runner; the configuration output is what this check needs.
unattended-upgrade --dry-run --debug > "$WORK/unattended.log" 2>&1 || true
grep -m1 'Allowed origins are' "$WORK/unattended.log" || fail "нет Allowed origins"
apt-config dump APT::Periodic::Unattended-Upgrade

step "Некорректный кандидат и ошибка применения сохраняют рабочее состояние"
cp /etc/vpn-base/firewall.nft "$WORK/previous.nft"
before=$(nft list table inet vpn_base | sha256sum)
file_before=$(sha256sum /etc/vpn-base/firewall.nft)
cat > "$WORK/bad.nft" <<'EOF'
table inet vpn_base
delete table inet vpn_base
table inet vpn_base { chain input { type filter hook input priority filter; policy bogus; } }
EOF
nft -c -f "$WORK/bad.nft" 2>/dev/null && fail "nft -c accepted invalid candidate"
nft -f "$WORK/bad.nft" 2>/dev/null && fail "nft applied invalid candidate"
[[ $(nft list table inet vpn_base | sha256sum) == "$before" ]] || fail "active policy changed"
[[ $(sha256sum /etc/vpn-base/firewall.nft) == "$file_before" ]] || fail "persistent policy changed"
assert_access

step "Неверные ACL и nft-кандидат отклоняются до замены конфигурации"
for invalid in \
  '{"base_firewall_source_ports": [{"proto": "tcp", "port": 18443, "source_cidrs": []}]}' \
  '{"base_firewall_source_ports": [{"proto": "tcp", "port": 18443, "source_cidrs": ["198.51.100.77/24"]}]}' \
  '{"base_firewall_source_ports": [{"proto": "tcp", "port": 18080, "source_cidrs": ["198.51.100.77/32"]}]}'; do
  if local_play -e @"$WORK/vars.json" -e @"$WORK/ack.json" -e "$invalid" > "$WORK/invalid-input.log" 2>&1; then
    fail "invalid ACL accepted"
  fi
  recap "$WORK/invalid-input.log" | grep -q 'changed=0' || fail "invalid ACL mutated host"
  grep -q '198.51.100.77' "$WORK/invalid-input.log" && fail "operator source leaked"
  [[ $(nft list table inet vpn_base | sha256sum) == "$before" ]] || fail "invalid ACL changed live policy"
  [[ $(sha256sum /etc/vpn-base/firewall.nft) == "$file_before" ]] || fail "invalid ACL changed file"
done
# A temporary copy changes only the test candidate. All transaction tasks and
# real nft validation are the production role's implementation.
cp -a "$ANSIBLE_DIR/roles/base" "$WORK/invalid-role"
cp "$WORK/bad.nft" "$WORK/invalid-role/templates/firewall.nft.j2"
cat > "$WORK/invalid-candidate.yml" <<EOF
---
- hosts: localhost
  gather_facts: false
  become: true
  tasks:
    - ansible.builtin.include_role:
        name: $WORK/invalid-role
        tasks_from: firewall
EOF
if "$AP" -i localhost, -c local -e @"$WORK/vars.json" "$WORK/invalid-candidate.yml" > "$WORK/invalid-candidate.log" 2>&1; then
  fail "role accepted invalid nft candidate"
fi
recap "$WORK/invalid-candidate.log" | grep -q 'changed=0' || fail "invalid candidate changed persistent state"
[[ $(nft list table inet vpn_base | sha256sum) == "$before" ]] || fail "invalid candidate changed live policy"
[[ $(sha256sum /etc/vpn-base/firewall.nft) == "$file_before" ]] || fail "invalid candidate changed file"
assert_access

# Exercise the real role transaction with one real nft failure AFTER a valid
# nft -c. The wrapper delegates all commands to the installed nft binary; only
# the first candidate apply is sent an invalid batch. This is fault injection,
# not a substitute firewall implementation or a passing mocked nft result.
printf '{"base_firewall_allow_icmp_echo": false}\n' > "$WORK/change.json"
mv /usr/sbin/nft "$WORK/nft.real"
cat > /usr/sbin/nft <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ \$# == 2 && \$1 == -f && \$2 == /run/vpn-base-firewall-*/candidate.nft && ! -e $WORK/failed-once ]]; then
  touch $WORK/failed-once
  exec $WORK/nft.real -f $WORK/bad.nft
fi
exec $WORK/nft.real "\$@"
EOF
chmod 755 /usr/sbin/nft
if "$AP" -i localhost, -c local -e @"$WORK/vars.json" -e @"$WORK/change.json" "$WORK/firewall-only.yml" > "$WORK/apply-failure.log" 2>&1; then
  fail "role ignored candidate application failure"
fi
mv "$WORK/nft.real" /usr/sbin/nft
[[ -e $WORK/failed-once ]] || { cat "$WORK/apply-failure.log"; fail "application fault not exercised"; }
[[ $(nft list table inet vpn_base | sha256sum) == "$before" ]] || fail "rollback lost live policy"
[[ $(sha256sum /etc/vpn-base/firewall.nft) == "$file_before" ]] || fail "rollback lost configuration"
assert_access

step "Отказ reload loader восстанавливает предыдущую active/enabled политику"
cp -a "$ANSIBLE_DIR/roles/base" "$WORK/reload-failure-role"
printf '\n# Disposable loader revision for the real daemon-reload fault.\n' >> "$WORK/reload-failure-role/templates/vpn-base-firewall.service.j2"
cat > "$WORK/reload-failure.yml" <<EOF
---
- hosts: localhost
  gather_facts: false
  become: true
  tasks:
    - ansible.builtin.include_role:
        name: $WORK/reload-failure-role
        tasks_from: firewall
EOF
cp -p /etc/systemd/system/vpn-base-firewall.service "$WORK/previous.service"
# Like the nft fault, this delegates to the real installed binary. Only the
# first daemon-reload executes a genuinely invalid systemctl command; rescue
# must perform a successful real daemon-reload, not receive a fake status.
inject_reload_failure() {
  rm -f "$WORK/reload-failed-once"
  mv /usr/bin/systemctl "$WORK/systemctl.real"
  cat > /usr/bin/systemctl <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ \$# == 1 && \$1 == daemon-reload && ! -e $WORK/reload-failed-once ]]; then
  touch $WORK/reload-failed-once
  exec $WORK/systemctl.real vpn-base-invalid-reload-verb
fi
exec $WORK/systemctl.real "\$@"
EOF
  chmod 755 /usr/bin/systemctl
}
for policy in "$WORK/change.json" "$WORK/vars.json"; do
  inject_reload_failure
  if "$AP" -i localhost, -c local -e @"$WORK/vars.json" -e @"$policy" "$WORK/reload-failure.yml" > "$WORK/reload-failure.log" 2>&1; then
    fail "роль проигнорировала реальную ошибку daemon-reload"
  fi
  mv "$WORK/systemctl.real" /usr/bin/systemctl
  [[ -e $WORK/reload-failed-once ]] || { cat "$WORK/reload-failure.log"; fail "reload fault не был выполнен"; }
  grep -q 'Ошибка firewall на этапе Reload systemd units' "$WORK/reload-failure.log" \
    || { cat "$WORK/reload-failure.log"; fail "отказ не достиг daemon-reload"; }
  [[ $(nft list table inet vpn_base | sha256sum) == "$before" ]] || fail "loader rollback потерял предыдущую live policy"
  [[ $(sha256sum /etc/vpn-base/firewall.nft) == "$file_before" ]] || fail "loader rollback потерял предыдущую persistent policy"
  cmp "$WORK/previous.service" /etc/systemd/system/vpn-base-firewall.service || fail "loader rollback потерял прежний unit"
  systemctl is-active --quiet vpn-base-firewall.service || fail "loader rollback потерял active state"
  systemctl is-enabled --quiet vpn-base-firewall.service || fail "loader rollback потерял enabled state"
  assert_access
  for addr in "$HOST4" "$HOST6"; do
    in_ns trusted ssh "${SSH_OPTS[@]}" -i "$WORK/admin_new" "vpnadmin@$addr" 'sudo -n true' || fail "свежий SSH после loader rollback"
  done
done
ok "изменение policy и loader-only отказ сохраняют прежние unit, active/enabled, ACL и SSH"

step "UDP/546: source ACL не обходится unconditional DHCPv6 allowance"
# A real UDP echo listener exercises the input policy, not a DHCP client.
python3 "$SERVICE" serve-udp 546 > "$WORK/udp546-server.log" 2>&1 &
UDP546_PID=$!
PIDS+=("$UDP546_PID")
ip -6 addr add fe80::1/64 dev vbr-test nodad
ip -n untrusted -6 addr add fe80::3/64 dev eth0 nodad
udp546_linklocal() {
  in_ns untrusted python3 "$SERVICE" udp fe80::1%eth0 546 --source-address "${1:-fe80::3%eth0}" --source-port 547 >/dev/null 2>&1
}
for _ in {1..20}; do udp546_linklocal && break; sleep 0.2; done
udp546_linklocal || fail "исходный DHCPv6 allowance не пропускает настоящий link-local UDP/547→546"
for family in "$TRUST4/32" "$TRUST6/128"; do
  if local_play -e @"$WORK/vars.json" -e @"$WORK/ack.json" \
      -e "{\"base_firewall_allow_dhcpv6_client\":true,\"base_firewall_source_ports\":[{\"proto\":\"udp\",\"port\":546,\"source_cidrs\":[\"$family\"]}]}" \
      > "$WORK/udp546-invalid.log" 2>&1; then
    fail "source-restricted UDP/546 принят при unconditional DHCPv6 allowance"
  fi
  recap "$WORK/udp546-invalid.log" | grep -q 'changed=0' || fail "UDP/546 conflict изменил хост"
  grep -q 'base_firewall_allow_dhcpv6_client' "$WORK/udp546-invalid.log" || fail "нет сообщения о DHCPv6 conflict"
  grep -Fq "$family" "$WORK/udp546-invalid.log" && fail "UDP/546 source попал в журнал"
  [[ $(nft list table inet vpn_base | sha256sum) == "$before" ]] || fail "UDP/546 conflict изменил live policy"
  udp546_linklocal || fail "UDP/546 conflict удалил прежний DHCPv6 allowance"
done
python3 - "$WORK/vars.json" "$WORK/udp546-safe.json" "$TRUST4" <<'PY'
import json, sys
with open(sys.argv[1]) as source:
    config = json.load(source)
config["base_firewall_allow_dhcpv6_client"] = False
config["base_firewall_source_ports"].append({"proto": "udp", "port": 546,
                                          "source_cidrs": [sys.argv[3] + "/32"]})
with open(sys.argv[2], "w") as output:
    json.dump(config, output)
PY
"$AP" -i localhost, -c local -e @"$WORK/udp546-safe.json" "$WORK/firewall-only.yml" > "$WORK/udp546-safe.log" 2>&1 \
  || { cat "$WORK/udp546-safe.log"; fail "safe UDP/546 при DHCPv6 allowance=false отклонён"; }
udp_get trusted "$HOST4" 546 || fail "IPv4 source UDP/546 не разрешён"
udp_get untrusted "$HOST4" 546 && fail "IPv4 UDP/546 открыт undeclared source"
udp_get trusted "$HOST6" 546 && fail "IPv4-only UDP/546 открыл IPv6"
# Use a fresh source tuple: established/related is intentionally preserved.
ip -n untrusted -6 addr add fe80::4/64 dev eth0 nodad
udp546_linklocal fe80::4%eth0 && fail "новый link-local UDP/547→546 обошёл IPv4-only source ACL при allowance=false"
"$AP" -i localhost, -c local -e @"$WORK/vars.json" "$WORK/firewall-only.yml" > "$WORK/udp546-restored.log" 2>&1 \
  || { cat "$WORK/udp546-restored.log"; fail "восстановление исходного DHCPv6 allowance"; }
udp546_linklocal fe80::4%eth0 || fail "исходный DHCPv6 allowance не восстановлен"
kill "$UDP546_PID"
wait "$UDP546_PID" 2>/dev/null || true
assert_access
ok "DHCPv6 precedence конфликт отклонён до изменений; allowance=false сохраняет family-specific ACL"

step "Изменение ACL и восстановление предыдущей собственной политики"
python3 - "$WORK/vars.json" "$WORK/alternate.json" "$UNTRUST4" "$UNTRUST6" <<'PY'
import json, sys
config = json.load(open(sys.argv[1]))
config['base_firewall_source_ports'][0]['source_cidrs'] = [sys.argv[3] + '/32', sys.argv[4] + '/128']
with open(sys.argv[2], 'w') as output:
    json.dump(config, output)
PY
local_play -e @"$WORK/alternate.json" -e @"$WORK/ack.json" > "$WORK/alternate.log" 2>&1 \
  || { cat "$WORK/alternate.log"; fail "alternate ACL apply"; }
for addr in "$HOST4" "$HOST6"; do
  http_get untrusted "$addr" "$SOURCE_TCP" || fail "alternate allowed source denied"
  http_get trusted "$addr" "$SOURCE_TCP" && fail "previous source still allowed"
done
nft -c -f "$WORK/previous.nft"
nft -f "$WORK/previous.nft"
install -m 644 "$WORK/previous.nft" /etc/vpn-base/firewall.nft
assert_access
remote_play > "$WORK/restored.log" 2>&1 || { cat "$WORK/restored.log"; fail "restored policy idempotence"; }
expect_changed "$WORK/restored.log" 0

step "Reload/restart сохраняют исходную политику доступа"
systemctl reload vpn-base-firewall.service
assert_access
systemctl restart vpn-base-firewall.service
assert_access
systemctl restart nftables.service
# PartOf propagation starts the owned unit asynchronously after nftables.
for _ in {1..20}; do
  nft list table inet vpn_base >/dev/null 2>&1 && break
  sleep 0.5
done
nft list table inet vpn_base >/dev/null || fail "owned table lost after nftables restart"
assert_access
for addr in "$HOST4" "$HOST6"; do
  in_ns trusted ssh "${SSH_OPTS[@]}" -i "$WORK/admin_new" "vpnadmin@$addr" 'sudo -n true' || fail "fresh SSH after restart"
done
ok "packet access and fresh SSH survive reload/restart"

step "Создание swap-файла при отсутствии swap"
swapoff -a
local_play -e @"$WORK/vars.json" -e @"$WORK/ack.json" -e "$SWAP_VARS" \
  > "$WORK/swap1.log" 2>&1 || { cat "$WORK/swap1.log"; fail "создание swap"; }
swapon --show=NAME --noheadings | grep -qx /var/tmp/vpn-base-ci.swap || fail "swap не активен"
grep -q '^/var/tmp/vpn-base-ci.swap ' /etc/fstab || fail "нет записи fstab"
local_play -e @"$WORK/vars.json" -e @"$WORK/ack.json" -e "$SWAP_VARS" \
  > "$WORK/swap2.log" 2>&1 || { cat "$WORK/swap2.log"; fail "повтор swap"; }
expect_changed "$WORK/swap2.log" 0

step "Все проверки пройдены"
