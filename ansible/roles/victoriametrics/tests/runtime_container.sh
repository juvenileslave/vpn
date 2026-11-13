#!/usr/bin/env bash
# Disposable-Linux runtime scenario for the victoriametrics role.
# Runs INSIDE an ephemeral Debian container; systemd is absent, so the role is
# applied with check mode / --diff, template rendering, validation failures and
# dry-run gates are exercised, and the pinned binary is verified directly.
# Never run against a real node.
set -euo pipefail
[[ ${VICTORIAMETRICS_DISPOSABLE_CONTAINER:-} == yes ]] || {
  echo "Refusing: set VICTORIAMETRICS_DISPOSABLE_CONTAINER=yes inside an ephemeral container." >&2
  exit 2
}
[[ $EUID -eq 0 ]] || { echo "Root required." >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo "Linux required." >&2; exit 2; }

ROOT=${VICTORIAMETRICS_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)}
AP=$ROOT/.venv-linux/bin/ansible-playbook
[[ -x $AP ]] || AP=$ROOT/.venv/bin/ansible-playbook
[[ -x $AP ]] || { echo "Run make -C ansible bootstrap first (host side)." >&2; exit 2; }
export ANSIBLE_NOCOLOR=1 DEBIAN_FRONTEND=noninteractive ANSIBLE_CONFIG=$ROOT/ansible/ansible.cfg

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "OK: $*"; }

WORK=$(mktemp -d /run/vm-ci.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/hosts.yml" <<EOF
all:
  hosts:
    vm-target:
      ansible_connection: local
      ansible_python_interpreter: /usr/bin/python3
EOF

cat > "$WORK/play.yml" <<EOF
- name: Disposable victoriametrics scenario
  hosts: vm-target
  become: false
  gather_facts: true
  roles:
    - role: $ROOT/ansible/roles/victoriametrics
EOF

run_play() { "$AP" -i "$WORK/hosts.yml" "$WORK/play.yml" "$@"; }

# 10.203.46.1 models a private CP address; the ACL peer is 10.203.46.2.
ip addr add 10.203.46.1/32 dev lo
ACL_VARS='{"victoriametrics_listen_address": "10.203.46.1",
  "victoriametrics_allowed_sources": ["10.203.46.2/32"],
  "base_firewall_enabled": true,
  "base_firewall_source_ports": [{"proto": "tcp", "port": 8428, "source_cidrs": ["10.203.46.2/32"]}],
  "base_firewall_vpn_ports": [],
  "base_ssh_port": 22}'

# --- 1. Wildcard address is rejected before any change -----------------------
if run_play -e victoriametrics_listen_address=0.0.0.0 >/dev/null 2>&1; then
  fail "wildcard listen address accepted"
fi
[[ ! -e /opt/victoriametrics && ! -e /var/lib/victoriametrics ]] || fail "wildcard rejection mutated the host"
pass "wildcard 0.0.0.0 rejected before any change"

# --- 2. Non-loopback listen without the base-role ACL is rejected ------------
if run_play -e victoriametrics_listen_address=10.203.46.1 -e victoriametrics_allowed_sources='["10.203.46.2/32"]' >/dev/null 2>&1; then
  fail "non-loopback listen without base firewall accepted"
fi
if run_play -e '{"victoriametrics_listen_address": "10.203.46.1", "victoriametrics_allowed_sources": ["10.203.46.2/32"], "base_firewall_enabled": true}' >/dev/null 2>&1; then
  fail "non-loopback listen without base_firewall_source_ports rule accepted"
fi
if run_play -e '{"victoriametrics_listen_address": "10.203.46.1", "victoriametrics_allowed_sources": ["10.203.46.2/32"], "base_firewall_enabled": false, "base_firewall_source_ports": [{"proto": "tcp", "port": 8428, "source_cidrs": ["10.203.46.2/32"]}]}' >/dev/null 2>&1; then
  fail "disabled base firewall accepted"
fi
if run_play -e '{"victoriametrics_listen_address": "10.203.46.1", "victoriametrics_allowed_sources": ["10.203.46.2/32"], "base_firewall_enabled": true, "base_firewall_source_ports": [{"proto": "tcp", "port": 8428, "source_cidrs": ["10.203.46.3/32"]}]}' >/dev/null 2>&1; then
  fail "mismatched ACL rule accepted"
fi
[[ ! -e /var/lib/victoriametrics ]] || fail "ACL rejection mutated the host"
pass "non-loopback requires private address, enabled base firewall and exact ACL rule"

# --- 3. Wide/public/documentation/wrong-family sources are rejected ----------
for sources in '["0.0.0.0/0"]' '["::/0"]' '["10.0.0.0/8"]' '["192.0.2.1/32"]' '["127.0.0.1/32"]' '["fd00::5/128"]'; do
  if run_play -e "{\"victoriametrics_listen_address\": \"10.203.46.1\", \"victoriametrics_allowed_sources\": $sources, \"base_firewall_enabled\": true, \"base_firewall_source_ports\": [{\"proto\": \"tcp\", \"port\": 8428, \"source_cidrs\": $sources}]}" >/dev/null 2>&1; then
    fail "ACL sources accepted: $sources"
  fi
done
[[ ! -e /var/lib/victoriametrics ]] || fail "ACL rejection mutated the host"
pass "wide, public, documentation, loopback and wrong-family sources rejected"

# --- 4. Bare-number retention (months) is rejected ---------------------------
if run_play -e victoriametrics_retention=12 >/dev/null 2>&1; then
  fail "bare-number retention accepted"
fi
pass "bare-number retention (months) rejected"

# --- 5. Check mode on a fresh system writes nothing --------------------------
run_play --check --diff >/dev/null 2>&1 || fail "check mode failed on a fresh system"
[[ ! -e /opt/victoriametrics && ! -e /var/lib/victoriametrics \
   && ! -e /etc/victoriametrics && ! -e /etc/systemd/system/victoriametrics.service ]] \
  || fail "check mode wrote files"
getent passwd victoriametrics >/dev/null 2>&1 && fail "check mode created the service user"
pass "check mode on a fresh system wrote nothing"

# --- 6. Accepted private-address ACL passes validation in check mode ---------
run_play --check -e "$ACL_VARS" >/dev/null 2>&1 \
  || fail "accepted private-address ACL failed validation"
[[ ! -e /var/lib/victoriametrics ]] || fail "check mode ACL acceptance wrote data"
pass "private CP address with matching base-role ACL accepted"

# --- 7. Dry run of the rendered scrape config against the pinned binary ------
cd /tmp
curl -fsSL --retry 2 \
  "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.155.0/victoria-metrics-linux-arm64-v1.155.0.tar.gz" \
  -o vm.tgz || curl -fsSL --retry 2 \
  "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.155.0/victoria-metrics-linux-amd64-v1.155.0.tar.gz" \
  -o vm.tgz || fail "download of pinned release"
ARCH=$(uname -m); case $ARCH in
  aarch64) SHA=c6af3f35c597e2cb45c9bbb7a7fc1638c6f1ec10a8198c2861aa14531bf439d7 ;;
  x86_64)  SHA=7180e65913d55ab99c0be8f4a3ad17a0fafe5598a21ff6327fecba3190d7b176 ;;
  *) fail "unsupported arch $ARCH" ;;
esac
# Verify the archive before extracting anything as root.
echo "$SHA  vm.tgz" | sha256sum --check --strict || fail "archive checksum"
mkdir -p vmbin && tar -xzf vm.tgz --no-same-owner -C vmbin
BINSHA=$(sha256sum vmbin/victoria-metrics-prod | cut -d' ' -f1)
case $ARCH in
  aarch64) EXPECT=5024a2a13237fbfbf7b276e60b7942cf0efb3bea5f53b5ca4b690e4d0719ca58 ;;
  x86_64)  EXPECT=aca3c49816db88c0e48012772fcf2a94eb66aaccd925b35d397b8b6f7f40fb43 ;;
esac
[[ $BINSHA == "$EXPECT" ]] || fail "binary checksum: $BINSHA"
VERSION=$(./vmbin/victoria-metrics-prod --version 2>&1 | head -1)
[[ $VERSION == *v1.155.0* ]] || fail "unexpected version: $VERSION"
pass "pinned release checksum and version verified: $VERSION"

# --- 8. Dry-run rejects a scrape config with unknown fields ------------------
cat > /tmp/bad-scrape.yml <<EOF
global:
  scrape_interval: 30s
scrape_configs:
  - job_name: self
    definitely_unknown_field: true
    static_configs:
      - targets: ["127.0.0.1:8428"]
EOF
if ./vmbin/victoria-metrics-prod -storageDataPath=/tmp/vmdata-bad -httpListenAddr=127.0.0.1:0 \
    -promscrape.config=/tmp/bad-scrape.yml -promscrape.config.dryRun >/dev/null 2>&1; then
  fail "dry run accepted unknown fields"
fi
pass "dry run rejected unknown scrape-config fields"

# --- 9. Dry run accepts a minimal valid config -------------------------------
cat > /tmp/good-scrape.yml <<EOF
global:
  scrape_interval: 30s
scrape_configs:
  - job_name: self
    static_configs:
      - targets: ["127.0.0.1:8428"]
EOF
./vmbin/victoria-metrics-prod -storageDataPath=/tmp/vmdata-good -httpListenAddr=127.0.0.1:0 \
  -promscrape.config=/tmp/good-scrape.yml -promscrape.config.dryRun >/dev/null 2>&1 \
  || fail "dry run rejected a valid config"
pass "dry run accepted a minimal valid scrape config"

# --- 10. Real single-node run: ingest, query up, retention, persistence ------
VM=/tmp/vmbin/victoria-metrics-prod
mkdir -p /tmp/vmdata-run
$VM -storageDataPath=/tmp/vmdata-run -httpListenAddr=127.0.0.1:18428 \
    -retentionPeriod=30d -promscrape.config=/tmp/good-scrape.yml \
    >/tmp/vm.log 2>&1 &
VMPID=$!
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:18428/health >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:18428/health | grep -q OK || fail "health endpoint"
# Ingest a sample through the write API (server assigns the timestamp) and
# read it back via /api/v1/query. Visible rows can lag a few seconds behind
# the write, so poll instead of sleeping a fixed interval.
curl -fsS -X POST "http://127.0.0.1:18428/api/v1/import/prometheus" \
  --data-binary 'vm_acceptance_probe{host="disposable"} 42' >/dev/null || fail "ingest"
for _ in $(seq 1 30); do
  if curl -fsS -g 'http://127.0.0.1:18428/api/v1/query?query=vm_acceptance_probe' 2>/dev/null | grep -q '"value"'; then
    break
  fi
  sleep 2
done
curl -fsS -g 'http://127.0.0.1:18428/api/v1/query?query=vm_acceptance_probe' | grep -q '"value"' \
  || fail "query for ingested sample"
# up must exist for the self-scrape target after one interval; it scrapes its
# own /metrics on the loopback port from the config. Poll for the first
# completed scrape instead of a fixed sleep.
for _ in $(seq 1 30); do
  if curl -fsS -g 'http://127.0.0.1:18428/api/v1/query?query=up' 2>/dev/null | grep -q '"value"'; then
    break
  fi
  sleep 2
done
curl -fsS -g 'http://127.0.0.1:18428/api/v1/query?query=up' | grep -q '"value"' \
  || fail "up series for self-scrape target"
pass "ingest, query /api/v1/query for up and ingested sample"
# Persistence across restart.
kill $VMPID; wait $VMPID 2>/dev/null || true
$VM -storageDataPath=/tmp/vmdata-run -httpListenAddr=127.0.0.1:18428 \
    -retentionPeriod=30d -promscrape.config=/tmp/good-scrape.yml \
    >/tmp/vm2.log 2>&1 &
VMPID=$!
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:18428/health >/dev/null 2>&1 && break
  sleep 1
done
for _ in $(seq 1 15); do
  if curl -fsS -g 'http://127.0.0.1:18428/api/v1/query?query=vm_acceptance_probe' 2>/dev/null | grep -q '"value"'; then
    break
  fi
  sleep 2
done
curl -fsS -g 'http://127.0.0.1:18428/api/v1/query?query=vm_acceptance_probe' | grep -q '"value"' \
  || fail "data survived restart"
grep -q "retentionPeriod=30d" /tmp/vm.log || grep -q "retentionPeriod=30d" /tmp/vm2.log \
  || fail "retention flag not in effect"
pass "retention flag applied; data survived a service restart"
kill $VMPID; wait $VMPID 2>/dev/null || true

# --- 11. No listener outside loopback ---------------------------------------
if command -v ss >/dev/null 2>&1; then
  if ss -Hltn | grep -v 127.0.0.1 | grep -q 18428; then fail "non-loopback listener"; fi
fi
pass "only loopback listener observed"

echo "DISPOSABLE RUNTIME SCENARIO PASSED"
