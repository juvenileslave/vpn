#!/usr/bin/env bash
set -euo pipefail
if [[ ${VPN_REMNAWAVE_NODE_DISPOSABLE_GUEST:-} != yes || ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted || $(uname -s) != Linux || $EUID -ne 0 ]]; then
  printf '%s\n' 'Refusing runtime: requires explicitly guarded GitHub-hosted disposable Linux guest as root.' >&2
  exit 1
fi
root=$(git rev-parse --show-toplevel)
[[ -x "$root/.venv/bin/ansible-playbook" ]] || { printf '%s\n' 'Run make -C ansible bootstrap first.' >&2; exit 1; }
apt-get update -qq
apt-get install -y -qq nftables iproute2 openssl curl python3
exec "$root/.venv/bin/python" "$root/ansible/roles/remnawave_node/tests/runtime_vm.py" "$root"
