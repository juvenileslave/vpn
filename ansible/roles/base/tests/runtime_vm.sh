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

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
ANSIBLE_DIR=$ROOT/ansible
PLAYBOOK=$ANSIBLE_DIR/playbooks/base.yml
AP=$ROOT/.venv/bin/ansible-playbook
WORK=$(mktemp -d)
export ANSIBLE_CONFIG=$ANSIBLE_DIR/ansible.cfg ANSIBLE_NOCOLOR=1 DEBIAN_FRONTEND=noninteractive

# Documentation ranges only (RFC 5737 / RFC 3849).
HOST4=198.51.100.1 TRUST4=198.51.100.2 UNTRUST4=198.51.100.3
HOST6=2001:db8:100::1 TRUST6=2001:db8:100::2 UNTRUST6=2001:db8:100::3
VPN_TCP=18080 CLOSED_TCP=19090

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
apt-get install -y -q openssh-server iproute2 iputils-ping >/dev/null
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
python3 -m http.server "$VPN_TCP" --bind :: --directory "$WORK" >/dev/null 2>&1 &
sleep 1
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
local_play -e @"$WORK/vars.json" -e '{"base_firewall_vpn_ports": []}' > "$WORK/listeners.log" 2>&1 \
  && { cat "$WORK/listeners.log"; fail "роль не отказала при незаявленном порте"; }
recap "$WORK/listeners.log" | grep -q 'changed=0' || fail "отказ после изменений"
mapfile -t uncovered < <(grep -o 'слушающие порты [^.]*' "$WORK/listeners.log" | head -1 \
  | sed 's/слушающие порты //' | tr -d ' ' | tr ',' '\n')
printf '%s\n' "${uncovered[@]}" | grep -qx "tcp/$VPN_TCP" || { cat "$WORK/listeners.log"; fail "tcp/$VPN_TCP не обнаружен"; }
nft list table inet vpn_base >/dev/null 2>&1 && fail "таблица создана несмотря на отказ"
ok "незаявленные порты: ${uncovered[*]}"
# Remaining host listeners are acknowledged as closed for this test.
ack=$( (printf '%s\n' "${uncovered[@]}" | grep -vx "tcp/$VPN_TCP" || true) | sed 's/.*/"&"/' | paste -sd, -)
printf '{"base_firewall_acknowledged_closed_ports": [%s]}\n' "$ack" > "$WORK/ack.json"

step "Первое применение (локально)"
local_play -e @"$WORK/vars.json" -e @"$WORK/ack.json" > "$WORK/apply1.log" 2>&1 \
  || { cat "$WORK/apply1.log"; fail "первое применение"; }
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
python3 -m http.server "$CLOSED_TCP" --bind :: --directory "$WORK" >/dev/null 2>&1 &
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

step "Некорректный кандидат не меняет активную таблицу"
before=$(nft list table inet vpn_base | sha256sum)
sed 's/policy drop;/policy bogus;/' /etc/vpn-base/firewall.nft > "$WORK/bad.nft"
nft -c -f "$WORK/bad.nft" 2>/dev/null && fail "nft -c принял некорректный кандидат"
nft -f "$WORK/bad.nft" 2>/dev/null && fail "nft применил некорректный кандидат"
[[ $(nft list table inet vpn_base | sha256sum) == "$before" ]] || fail "таблица изменилась"
ok "предыдущая таблица осталась активной"

step "Перезапуск nftables.service не теряет таблицу"
systemctl restart nftables.service
nft list table inet vpn_base >/dev/null || fail "таблица потеряна после flush ruleset"
in_ns trusted ssh "${SSH_OPTS[@]}" -i "$WORK/admin_new" "vpnadmin@$HOST4" true || fail "SSH после restart nftables"
ok "таблица восстановлена, SSH работает"

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
