#!/usr/bin/env bash
# Acceptance changes ONLY an explicitly designated fresh GitHub-hosted guest.
set -euo pipefail
[[ ${VPN_PROFILES_DISPOSABLE_GUEST:-} == yes && ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
  echo 'Refusing non-disposable profile runtime.' >&2; exit 2;
}
[[ $EUID == 0 && -d /run/systemd/system ]] || { echo 'Root/systemd required.' >&2; exit 2; }
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Ubuntu 24.04 required.' >&2; exit 2; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
[[ -x $ROOT/.venv/bin/python ]] || { echo 'Run make -C ansible bootstrap first.' >&2; exit 2; }
export VPN_COVER_SITE_DISPOSABLE_GUEST=yes VPN_REMNAWAVE_NODE_DISPOSABLE_GUEST=yes
export ANSIBLE_CONFIG="$ROOT/ansible/ansible.cfg" ANSIBLE_NOCOLOR=1 DEBIAN_FRONTEND=noninteractive
for path in /etc/cover-site /var/lib/cover-site /etc/nginx/sites-enabled/cover-site.conf; do
  [[ ! -e $path && ! -L $path ]] || { echo 'Refusing non-fresh role-owned state.' >&2; exit 2; }
done
apt-get update -q
apt-get install -y -q nginx libnginx-mod-stream certbot openssl openssh-server curl dnsmasq-base iproute2 nftables tcpdump ethtool golang-go > /var/tmp/vpn-profiles-packages.log
systemctl start ssh
exec "$ROOT/.venv/bin/python" "$ROOT/ansible/roles/profiles/tests/runtime_vm.py"
