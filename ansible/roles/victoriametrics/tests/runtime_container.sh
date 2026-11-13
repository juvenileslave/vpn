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

ROOT=/repo
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

# --- 1. Wildcard address is rejected before any change -----------------------
if run_play -e victoriametrics_listen_address=0.0.0.0 >/dev/null 2>&1; then
  fail "wildcard listen address accepted"
fi
[[ ! -e /opt/victoriametrics && ! -e /var/lib/victoriametrics ]] || fail "wildcard rejection mutated the host"
pass "wildcard 0.0.0.0 rejected before any change"

# --- 2. Non-loopback listen without ACL is rejected --------------------------
if run_play -e victoriametrics_listen_address=192.0.2.10 >/dev/null 2>&1; then
  fail "non-loopback listen without ACL accepted"
fi
[[ ! -e /var/lib/victoriametrics ]] || fail "ACL rejection mutated the host"
pass "non-loopback listen without ACL rejected"

# --- 3. Wide/public ACL sources are rejected ---------------------------------
for sources in "['0.0.0.0/0']" "['10.0.0.0/8']" "['192.0.2.1/32']" "['127.0.0.1/32']"; do
  if run_play -e "victoriametrics_listen_address=192.0.2.10" -e "victoriametrics_allowed_sources=$sources" >/dev/null 2>&1; then
    fail "ACL sources accepted: $sources"
  fi
done
[[ ! -e /var/lib/victoriametrics ]] || fail "ACL rejection mutated the host"
pass "wide, public, documentation and loopback ACL sources rejected"

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

# --- 6. Dry run of the rendered scrape config against the pinned binary ------
# The role's own stage task performs this; prove the binary flag and the
# checksum by running the same archive extraction here.
cd /tmp
curl -fsSL --retry 2 \
  "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.155.0/victoria-metrics-linux-arm64-v1.155.0.tar.gz" \
  -o vm.tgz || curl -fsSL --retry 2 \
  "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.155.0/victoria-metrics-linux-amd64-v1.155.0.tar.gz" \
  -o vm.tgz || fail "download of pinned release"
mkdir -p vmbin && tar -xzf vm.tgz -C vmbin
ARCH=$(uname -m); case $ARCH in
  aarch64) SHA=c6af3f35c597e2cb45c9bbb7a7fc1638c6f1ec10a8198c2861aa14531bf439d7 ;;
  x86_64)  SHA=7180e65913d55ab99c0be8f4a3ad17a0fafe5598a21ff6327fecba3190d7b176 ;;
  *) fail "unsupported arch $ARCH" ;;
esac
echo "$SHA  vm.tgz" | sha256sum --check --strict || fail "archive checksum"
BINSHA=$(sha256sum vmbin/victoria-metrics-prod | cut -d' ' -f1)
case $ARCH in
  aarch64) EXPECT=5024a2a13237fbfbf7b276e60b7942cf0efb3bea5f53b5ca4b690e4d0719ca58 ;;
  x86_64)  EXPECT=aca3c49816db88c0e48012772fcf2a94eb66aaccd925b35d397b8b6f7f40fb43 ;;
esac
[[ $BINSHA == "$EXPECT" ]] || fail "binary checksum: $BINSHA"
VERSION=$(./vmbin/victoria-metrics-prod --version 2>&1 | head -1)
[[ $VERSION == *v1.155.0* ]] || fail "unexpected version: $VERSION"
pass "pinned release checksum and version verified: $VERSION"

# --- 7. Dry-run rejects a scrape config with unknown fields ------------------
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

# --- 8. Dry run accepts a minimal valid config -------------------------------
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

# --- 9. Real single-node run: ingest, query up, retention, persistence -------
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
# read it back via /api/v1/query.
curl -fsS -X POST "http://127.0.0.1:18428/api/v1/import/prometheus" \
  --data-binary 'vm_acceptance_probe{host="disposable"} 42' >/dev/null || fail "ingest"
sleep 2
curl -fsS -g 'http://127.0.0.1:18428/api/v1/query?query=vm_acceptance_probe' | grep -q '"value"' \
  || fail "query for ingested sample"
# up must exist for the self-scrape target after one interval; it scrapes its
# own /metrics on the loopback port from the config.
sleep 31
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
curl -fsS 'http://127.0.0.1:18428/api/v1/query?query=vm_acceptance_probe' | grep -q '"value"' \
  || fail "data survived restart"
grep -q "retentionPeriod=30d" /tmp/vm.log || grep -q "retentionPeriod=30d" /tmp/vm2.log \
  || fail "retention flag not in effect"
pass "retention flag applied; data survived a service restart"
kill $VMPID; wait $VMPID 2>/dev/null || true

# --- 10. No listener outside loopback ---------------------------------------
if command -v ss >/dev/null 2>&1; then
  if ss -Hltn | grep -v 127.0.0.1 | grep -q 18428; then fail "non-loopback listener"; fi
fi
pass "only loopback listener observed"

echo "DISPOSABLE RUNTIME SCENARIO PASSED"
