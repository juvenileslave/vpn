#!/usr/bin/env bash
# Real nginx + Certbot + Pebble acceptance. ONLY a fresh GitHub-hosted Linux guest.
set -euo pipefail
[[ ${VPN_COVER_SITE_DISPOSABLE_GUEST:-} == yes && ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
  echo 'Refusing: explicitly guarded disposable GitHub guest required.' >&2; exit 2;
}
[[ $EUID == 0 && -d /run/systemd/system ]] || { echo 'Root/systemd required.' >&2; exit 2; }
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Ubuntu 24.04 required.' >&2; exit 2; }
for path in /etc/cover-site /usr/local/libexec/cover-site /var/lib/cover-site /var/log/cover-site /var/www/cover-site-acme /etc/nginx/sites-enabled/cover-site.conf /etc/systemd/system/cover-site-{recover.service,renew.service,renew.timer}; do
  [[ ! -e $path && ! -L $path ]] || { echo 'Refusing non-fresh role-owned state.' >&2; exit 2; }
done
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
AP=$ROOT/.venv/bin/ansible-playbook
[[ -x $AP ]] || { echo 'Run make -C ansible bootstrap first.' >&2; exit 2; }
# The real renewal unit has PrivateTmp=true; its test CA must remain visible.
WORK=$(mktemp -d /var/lib/vpn-cover-ci.XXXXXX)
chmod 755 "$WORK"
export ANSIBLE_CONFIG=$ROOT/ansible/ansible.cfg ANSIBLE_NOCOLOR=1 DEBIAN_FRONTEND=noninteractive
HOST=cover.example.test PORT=18443
LIFECYCLE=/usr/local/libexec/cover-site/lifecycle.py
PEBBLE_PID= DNS_PID= CANARY_PID=
cleanup() {
  for pid in "$PEBBLE_PID" "$DNS_PID" "$CANARY_PID"; do [[ -z $pid ]] || kill "$pid" 2>/dev/null || true; done
  ip netns del cover-outside 2>/dev/null || true
  ip link del cover-ci-host 2>/dev/null || true
  rm -f /etc/systemd/system/nginx.service.d/cover-ci-failed-reload.conf
  systemctl daemon-reload
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { printf '\n=== %s\n' "$*"; }
play() { "$AP" -i localhost, -c local -e ansible_python_interpreter=/usr/bin/python3 -e @"$WORK/vars.json" "$@" "$WORK/play.yml"; }
https() { curl --silent --show-error --noproxy '*' --cacert "$WORK/root.pem" --resolve "$HOST:$PORT:127.0.0.1" "$@" "https://$HOST:$PORT/"; }
active() { readlink -f /var/lib/cover-site/active; }
healthy() { "$LIFECYCLE" health; [[ $(curl -s --noproxy '*' http://127.0.0.1:18081/) == unrelated-site ]] || fail 'Unrelated site changed'; }
expect_failure() { if "$@" >"$WORK/negative.log" 2>&1; then fail "Unexpected success: $*"; fi; }

step 'Install public disposable prerequisites'
apt-get update -q
apt-get install -y -q nginx certbot openssl curl dnsmasq-base iproute2 python3 golang-go >"$WORK/packages.log"
# Go module/release is pinned; no production image or mutable latest script.
GOBIN="$WORK/bin" go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.6.0
mkdir -p "$WORK/source" "$WORK/ca"
cat >"$WORK/source/index.html" <<'HTML'
<!doctype html><html lang="en"><head><title>Atlas field journal</title><link rel="stylesheet" href="journal.css"></head><body><h1>Atlas field journal</h1><p>A synthetic archive of observations from imaginary coastlines. This disposable exhibit contains locally stored illustrations and notes about landscape, light, and seasonal weather.</p><a href="notes.html">Read the field notes</a></body></html>
HTML
printf 'body { max-width: 48rem; margin: 3rem auto; color: #243; }\n' >"$WORK/source/journal.css"
printf '<!doctype html><title>Field notes</title><p>Synthetic observations of coastal weather.</p>\n' >"$WORK/source/notes.html"
printf 'Retired synthetic local note.\n' >"$WORK/source/retired.txt"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca/key.pem" -out "$WORK/ca/cert.pem" -days 2 -subj /CN=Disposable-ACME-API-CA >"$WORK/openssl.log" 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/api-key.pem" -out "$WORK/api.csr" -subj /CN=localhost >>"$WORK/openssl.log" 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >"$WORK/api.ext"
openssl x509 -req -in "$WORK/api.csr" -CA "$WORK/ca/cert.pem" -CAkey "$WORK/ca/key.pem" -CAcreateserial -out "$WORK/api.pem" -days 2 -extfile "$WORK/api.ext" >>"$WORK/openssl.log" 2>&1
chmod 600 "$WORK/ca/key.pem" "$WORK/api-key.pem"
cat >"$WORK/pebble.json" <<EOF
{"pebble":{"listenAddress":"127.0.0.1:14000","managementListenAddress":"127.0.0.1:15000","certificate":"$WORK/api.pem","privateKey":"$WORK/api-key.pem","httpPort":80,"tlsPort":5001,"externalAccountBindingRequired":false}}
EOF
dnsmasq --keep-in-foreground --no-resolv --no-hosts --bind-interfaces --listen-address=127.0.0.1 --port=53535 --address=/.example.test/127.0.0.1 >"$WORK/dns.log" 2>&1 & DNS_PID=$!
env -u PEBBLE_VA_ALWAYS_VALID PEBBLE_AUTHZREUSE=0 PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 "$WORK/bin/pebble" -config "$WORK/pebble.json" -dnsserver 127.0.0.1:53535 >"$WORK/pebble.log" 2>&1 & PEBBLE_PID=$!
for _ in {1..60}; do
  if curl -s --cacert "$WORK/ca/cert.pem" https://localhost:15000/roots/0 >"$WORK/root.pem" && [[ -s $WORK/root.pem ]]; then break; fi
  sleep 1
done
[[ -s $WORK/root.pem ]] || fail 'Pebble root unavailable'
cat > /etc/nginx/sites-enabled/cover-ci-unrelated.conf <<'NGINX'
server { listen 127.0.0.1:18081; server_name unrelated.example.test; location / { return 200 "unrelated-site"; } }
NGINX
nginx -t
systemctl start nginx
systemctl reload nginx
sha256sum /etc/nginx/nginx.conf /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/cover-ci-unrelated.conf >"$WORK/unrelated.before"
cat >"$WORK/play.yml" <<EOF
---
- hosts: all
  gather_facts: true
  become: true
  roles:
    - role: "$ROOT/ansible/roles/cover_site"
EOF
cat >"$WORK/vars.json" <<EOF
{"reality_sni":"$HOST","cover_tls_port":$PORT,"cover_site_source":"$WORK/source","cover_acme_email":"operator@example.test","cover_acme_agree_tos":true,"cover_acme_http_reachable":true,"cover_disposable_test":true,"cover_acme_directory":"https://localhost:14000/dir","cover_acme_test_ca":"$WORK/ca/cert.pem","cover_certificate_trust":"$WORK/root.pem"}
EOF

step 'Reject invalid inputs before host state exists'
expect_failure play -e '{"cover_tls_port": true}'
[[ ! -e /etc/cover-site ]] || fail 'Invalid port mutated host'
expect_failure play -e '{"cover_acme_http_reachable": false}'
[[ ! -e /etc/cover-site ]] || fail 'Missing rollout acknowledgement mutated host'
expect_failure play -e '{"cover_disposable_test": false}'
[[ ! -e /etc/cover-site ]] || fail 'Custom trust escaped disposable gate'

step 'Reject every foreign persistent root, helper namespace, unit and sidecar without mutation'
python3 "$ROOT/ansible/roles/cover_site/tests/ownership_probe.py" fresh "$AP" -i localhost, -c local -e ansible_python_interpreter=/usr/bin/python3 -e @"$WORK/vars.json" "$WORK/play.yml"

step 'Real initial Certbot issuance through HTTP-01'
play >"$WORK/apply1.log" 2>&1 || { cat "$WORK/apply1.log"; fail 'First role application'; }
healthy
FIRST=$(active)
openssl x509 -in "$FIRST/certificate/cert.pem" -noout -serial >"$WORK/serial.first"
cp /etc/cover-site/settings.json "$WORK/settings.first.json"
[[ ! -e /var/lib/cover-site/previous && ! -L /var/lib/cover-site/previous ]] || fail 'First TLS installation retained HTTP bootstrap as previous'
expect_failure "$LIFECYCLE" rollback
[[ $(active) == "$FIRST" ]] || fail 'First-install rollback removed TLS'
cmp /etc/cover-site/settings.json "$WORK/settings.first.json"
healthy
# Successful validation must be real: skipping challenges is never enabled.
[[ ${PEBBLE_VA_ALWAYS_VALID:-0} != 1 ]] || fail 'Challenge validation bypassed'

step 'TLS 1.2/1.3, H1/H2, GET/HEAD and actual origin baseline'
for version in 1.2 1.3; do
  https --tlsv"$version" --tls-max "$version" --http1.1 >"$WORK/body"
  cmp "$WORK/body" "$WORK/source/index.html"
done
[[ $(https --http1.1 -o /dev/null -w '%{http_version}') == 1.1 ]] || fail 'No HTTP/1.1'
[[ $(https --http2 -o /dev/null -w '%{http_version}') == 2 ]] || fail 'No HTTP/2'
[[ $(https --head -o /dev/null -w '%{http_code}') == 200 ]] || fail 'HEAD baseline'
for path in absent panel sub metrics 127.0.0.1; do
  code=$(curl -s --noproxy '*' --cacert "$WORK/root.pem" --resolve "$HOST:$PORT:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$HOST:$PORT/$path")
  [[ $code == 404 ]] || fail "Unexpected exposed path: $path"
done
[[ $(https -X POST -o /dev/null -w '%{http_code}') == 405 ]] || fail 'Static POST baseline'
[[ $(https -X OPTIONS -o /dev/null -w '%{http_code}') == 405 ]] || fail 'Static OPTIONS baseline'
[[ $(https -H 'Host: unknown.example.test' -o /dev/null -w '%{http_code}') == 200 ]] || fail 'Normal default-vhost Host baseline'
[[ $(curl -s --noproxy '*' -H "Host: $HOST" -H 'X-Forwarded-Host: arbitrary.example.test' -D - -o /dev/null "http://127.0.0.1/" | tr -d '\r' | grep -i '^Location:') == "Location: https://$HOST/" ]] || fail 'Redirect trusts arbitrary forwarded Host'
# Raw unknown/missing SNI probes still authenticate the owned hostname and CA.
python3 "$ROOT/ansible/roles/cover_site/tests/origin_probe.py" "$WORK/root.pem" "$HOST" "$PORT" "$WORK/source/index.html" >"$WORK/baseline.json"
cat "$WORK/baseline.json"

step 'Host namespace only; unrelated external IPv4 and IPv6 cannot connect'
MASTER=$(cat /run/nginx.pid)
[[ $(readlink /proc/1/ns/net) == "$(readlink "/proc/$MASTER/ns/net")" ]] || fail 'nginx not in host network namespace'
nsenter --net=/proc/1/ns/net curl -s --noproxy '*' --cacert "$WORK/root.pem" --resolve "$HOST:$PORT:127.0.0.1" "https://$HOST:$PORT/" >"$WORK/namespace.body"
cmp "$WORK/namespace.body" "$WORK/source/index.html"
ip netns add cover-outside
ip link add cover-ci-host type veth peer name cover-ci-peer
ip link set cover-ci-peer netns cover-outside
ip addr add 198.51.100.1/30 dev cover-ci-host
ip -6 addr add 2001:db8:45::1/64 dev cover-ci-host nodad
ip link set cover-ci-host up
ip -n cover-outside link set lo up
ip -n cover-outside link set cover-ci-peer up
ip -n cover-outside addr add 198.51.100.2/30 dev cover-ci-peer
ip -n cover-outside -6 addr add 2001:db8:45::2/64 dev cover-ci-peer nodad
for address in 198.51.100.1 '[2001:db8:45::1]'; do
  # Positive HTTP connectivity proves this is not just a broken test network.
  ip netns exec cover-outside curl --noproxy '*' -s --max-time 5 -H "Host: $HOST" "http://$address/" -o /dev/null || fail 'External namespace cannot reach HTTP'
  expect_failure ip netns exec cover-outside curl --noproxy '*' --cacert "$WORK/root.pem" --resolve "$HOST:$PORT:$address" -s --max-time 3 "https://$HOST:$PORT/"
done
expect_failure curl --noproxy '*' --cacert "$WORK/root.pem" --resolve "$HOST:$PORT:[::1]" -s --max-time 3 "https://$HOST:$PORT/"

step 'Idempotence and unchanged unrelated nginx configuration'
play >"$WORK/apply2.log" 2>&1 || { cat "$WORK/apply2.log"; fail 'Second application'; }
grep -E '^localhost +:.*changed=0 .*failed=0' "$WORK/apply2.log" || fail 'Role is not idempotent'
[[ $(active) == "$FIRST" ]] || fail 'Idempotence changed release'
sha256sum -c "$WORK/unrelated.before"
healthy

step 'Reject foreign helpers and sidecars in an established marked installation'
python3 "$ROOT/ansible/roles/cover_site/tests/ownership_probe.py" managed "$AP" -i localhost, -c local -e ansible_python_interpreter=/usr/bin/python3 -e @"$WORK/vars.json" "$WORK/play.yml"
healthy

step 'Actual content replacement and previous-site rollback'
sed 's/Atlas field journal/Atlas coastal journal/g' "$WORK/source/index.html" >"$WORK/source/replacement.html"
mv "$WORK/source/replacement.html" "$WORK/source/index.html"
rm "$WORK/source/retired.txt"
play -e '{"cover_certificate_min_lifetime":7200}' >"$WORK/apply3.log" 2>&1 || { cat "$WORK/apply3.log"; fail 'Content/settings replacement'; }
SECOND=$(active)
[[ $SECOND != "$FIRST" ]] || fail 'Content release did not change'
cp /etc/cover-site/settings.json "$WORK/settings.second.json"
! cmp -s "$WORK/settings.first.json" "$WORK/settings.second.json" || fail 'Settings fixture did not change'
https >"$WORK/body"; cmp "$WORK/body" "$WORK/source/index.html"
[[ $(curl -s --noproxy '*' --cacert "$WORK/root.pem" --resolve "$HOST:$PORT:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$HOST:$PORT/retired.txt") == 404 ]] || fail 'Deleted source file stayed public'
"$LIFECYCLE" rollback
[[ $(active) == "$FIRST" ]] || fail 'Rollback did not select previous site'
cmp /etc/cover-site/settings.json "$WORK/settings.first.json"
healthy
"$LIFECYCLE" rollback
[[ $(active) == "$SECOND" ]] || fail 'Rollback restoration did not preserve both releases'
cmp /etc/cover-site/settings.json "$WORK/settings.second.json"
healthy

step 'Invalid candidate configuration and certificate retain the checked site'
cp -a "$SECOND" "$WORK/bad-release"
printf '\nunknown_cover_directive on;\n' >>"$WORK/bad-release/site.conf"
expect_failure python3 "$ROOT/ansible/roles/cover_site/tests/reject_candidate.py" "$WORK/bad-release"
[[ $(active) == "$SECOND" ]] || fail 'Rejected config changed active release'
healthy
LIVE=/etc/cover-site/acme/live/$HOST
cp -L "$LIVE/fullchain.pem" "$WORK/fullchain.saved"
printf 'invalid certificate\n' >"$(readlink -f "$LIVE/fullchain.pem")"
expect_failure "$LIFECYCLE" apply
[[ $(active) == "$SECOND" ]] || fail 'Invalid certificate replaced site'
cp "$WORK/fullchain.saved" "$(readlink -f "$LIVE/fullchain.pem")"
healthy
python3 "$ROOT/ansible/roles/cover_site/tests/certificate_probe.py"
# A real TLS reload command is rejected, not replaced with a mocked echo.
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/cover-ci-failed-reload.conf <<EOF
[Service]
ExecReload=
ExecReload=/usr/sbin/nginx -s reload -c $WORK/nonexistent-nginx.conf
EOF
systemctl daemon-reload
printf '\n<p>A replacement that must not activate while reload fails.</p>\n' >>"$WORK/source/index.html"
expect_failure play
[[ $(active) == "$SECOND" ]] || fail 'Failed reload replaced previous site'
healthy
rm /etc/systemd/system/nginx.service.d/cover-ci-failed-reload.conf
systemctl daemon-reload

step 'Real forced renewal, deploy-hook certificate replacement, failed renewal'
BEFORE_RENEW=$(active)
"$LIFECYCLE" renew --force-renewal
AFTER_RENEW=$(active)
[[ $AFTER_RENEW != "$BEFORE_RENEW" ]] || fail 'Renewal did not deploy a new certificate'
openssl x509 -in "$AFTER_RENEW/certificate/cert.pem" -noout -serial >"$WORK/serial.renewed"
! cmp -s "$WORK/serial.first" "$WORK/serial.renewed" || fail 'Certificate serial did not change'
healthy
"$LIFECYCLE" rollback
[[ $(active) == "$BEFORE_RENEW" ]] || fail 'Certificate rollback lost the previous checked snapshot'
healthy
"$LIFECYCLE" rollback
[[ $(active) == "$AFTER_RENEW" ]] || fail 'Certificate rollback could not restore renewed snapshot'
healthy
# Deny nginx workers access to the actual webroot challenge while TLS stays live.
# Certbot (root) can create the token, but real Pebble HTTP-01 must receive failure.
chmod 000 /var/www/cover-site-acme/.well-known/acme-challenge
expect_failure "$LIFECYCLE" renew --force-renewal
[[ $(active) == "$AFTER_RENEW" ]] || fail 'Failed ACME renewal changed active release'
healthy
chmod 755 /var/www/cover-site-acme/.well-known/acme-challenge
if ! systemctl start cover-site-renew.service; then
  journalctl --unit=cover-site-renew.service --no-pager --lines=20 --output=cat
  fail 'Renewal service failed inside its actual sandbox'
fi
systemctl is-enabled cover-site-renew.timer
systemctl is-active cover-site-renew.timer

step 'Interrupted activation recovery, reboot ordering and real restart'
# Interrupt the real transaction after service health and its previous-pointer write.
# All nginx checks/reloads/network probes execute normally; only this exit seam is injected.
OLDER_TARGET=$(readlink -f /var/lib/cover-site/previous)
cp /etc/cover-site/settings.json "$WORK/settings.before-interruption.json"
set +e
python3 "$ROOT/ansible/roles/cover_site/tests/interrupt_activation.py" previous "$FIRST"
interruption_status=$?
set -e
[[ $interruption_status == 86 ]] || fail 'Real commit interruption was not reached'
systemctl stop nginx
systemctl restart cover-site-recover.service
[[ ! -e /var/lib/cover-site/pending.json ]] || fail 'Recovery left pending transaction'
[[ $(readlink -f /etc/nginx/sites-enabled/cover-site.conf) == "$AFTER_RENEW/site.conf" ]] || fail 'Recovery failed to restore checked config'
[[ $(readlink -f /var/lib/cover-site/previous) == "$OLDER_TARGET" ]] || fail 'Recovery lost the distinct older rollback target'
cmp /etc/cover-site/settings.json "$WORK/settings.before-interruption.json"
# Enabled recovery unit is ordered before nginx at the next boot; replay it here.
systemctl is-enabled cover-site-recover.service
systemctl show cover-site-recover.service -p Before --value | grep -qw nginx.service
systemctl start nginx
systemctl restart nginx
healthy
"$LIFECYCLE" rollback
[[ $(active) == "$OLDER_TARGET" ]] || fail 'Recovered previous target was unusable'
healthy
"$LIFECYCLE" rollback
[[ $(active) == "$AFTER_RENEW" ]] || fail 'Recovered two-version rollback lost active TLS'
healthy
sha256sum -c "$WORK/unrelated.before"

step 'Actual isolated systemd guest userspace reboot'
bash "$ROOT/ansible/roles/cover_site/tests/reboot_guest.sh"
echo 'PASS: real service, local ACME, TLS/H1/H2, privacy, idempotence, renewal failures and rollback/recovery.'
