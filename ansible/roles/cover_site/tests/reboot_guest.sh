#!/usr/bin/env bash
# Actual isolated systemd guest userspace reboot; NEVER reboot the runner kernel.
set -euo pipefail
[[ ${VPN_COVER_SITE_DISPOSABLE_GUEST:-} == yes && ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
  echo 'Refusing: disposable GitHub-hosted guard required.' >&2; exit 2;
}
[[ $EUID == 0 && -d /run/systemd/system && -L /var/lib/cover-site/active ]] || {
  echo 'Root/systemd and an existing synthetic checked cover release required.' >&2; exit 2;
}
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || exit 2
python3 - <<'PY'
import json, os
value = json.load(open('/etc/cover-site/settings.json'))
assert value['test'] and value['directory'] == 'https://localhost:14000/dir'
assert value['hostname'].endswith('.example.test')
PY
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q debootstrap systemd-container dbus > /dev/null
WORK=$(mktemp -d /var/tmp/vpn-cover-boot.XXXXXX)
GUEST=$WORK/rootfs
MACHINE=cover-reboot-$RANDOM
SUPERVISOR=
cleanup() {
  machinectl terminate "$MACHINE" >/dev/null 2>&1 || true
  if [[ -n $SUPERVISOR ]]; then kill "$SUPERVISOR" 2>/dev/null || true; wait "$SUPERVISOR" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL guest reboot: $*" >&2; exit 1; }
printf '\n=== Build fresh public Ubuntu 24.04 booted guest\n'
debootstrap --variant=minbase noble "$GUEST" http://archive.ubuntu.com/ubuntu >"$WORK/debootstrap.log" 2>&1 || { cat "$WORK/debootstrap.log"; fail debootstrap; }
# Prevent package postinst from starting host-visible daemons in the unbooted chroot.
printf '#!/bin/sh\nexit 101\n' >"$GUEST/usr/sbin/policy-rc.d"
chmod 755 "$GUEST/usr/sbin/policy-rc.d"
cat >"$GUEST/etc/apt/sources.list" <<'APT'
deb http://archive.ubuntu.com/ubuntu noble main universe
deb http://archive.ubuntu.com/ubuntu noble-updates main universe
deb http://security.ubuntu.com/ubuntu noble-security main universe
APT
chroot "$GUEST" apt-get update -q >"$WORK/apt.log" 2>&1
chroot "$GUEST" apt-get install -y -q systemd-sysv dbus python3 nginx curl openssl iproute2 >>"$WORK/apt.log" 2>&1 || { cat "$WORK/apt.log"; fail 'guest packages'; }
rm "$GUEST/usr/sbin/policy-rc.d"
# Copy only temporary synthetic owned snapshots, nginx config and public trust.
# No public-CA account, Certbot key lineage, panel/node or owner credential is copied.
mkdir -p "$GUEST/etc/cover-site" "$GUEST/usr/local/libexec" "$GUEST/var/lib/cover-site" "$GUEST/var/www/cover-site-acme/.well-known/acme-challenge"
cp -a /etc/nginx/. "$GUEST/etc/nginx/"
cp /etc/cover-site/settings.json "$GUEST/etc/cover-site/settings.json"
cp -a /usr/local/libexec/cover-site "$GUEST/usr/local/libexec/"
cp -a /var/lib/cover-site/releases /var/lib/cover-site/active "$GUEST/var/lib/cover-site/"
if [[ -L /var/lib/cover-site/previous ]]; then cp -a /var/lib/cover-site/previous "$GUEST/var/lib/cover-site/"; fi
python3 - "$GUEST" <<'PY'
import json, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
value = json.load(open('/etc/cover-site/settings.json'))
for name in ('trust', 'acme_ca'):
    source = pathlib.Path(value[name])
    target = root / str(source).lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
PY
cp /etc/systemd/system/cover-site-recover.service "$GUEST/etc/systemd/system/"
# The unrelated test site exists in runtime_vm.sh; integrated callers get their
# own synthetic canary rather than a hard-coded successful reload stub.
cat >"$GUEST/etc/nginx/sites-enabled/cover-ci-unrelated.conf" <<'NGINX'
server { listen 127.0.0.1:18081; server_name unrelated.example.test; location / { return 200 "unrelated-site"; } }
NGINX
chroot "$GUEST" systemctl enable nginx cover-site-recover.service >"$WORK/enable.log" 2>&1
# Empty identity makes the guest generate its own machine ID, separate from host.
: >"$GUEST/etc/machine-id"
# Inner systemd owns its PID/mount/net namespaces; --private-network exposes no
# alternate public origin. The supervisor restarts only on actual guest reboot.
(
  while true; do
    set +e
    systemd-nspawn --directory="$GUEST" --machine="$MACHINE" --boot --private-network --register=yes --link-journal=no
    code=$?
    set -e
    [[ $code == 133 ]] || exit "$code"
  done
) >"$WORK/guest.log" 2>&1 & SUPERVISOR=$!
inside() {
  systemd-run --quiet --machine="$MACHINE" --wait --pipe --collect \
    --setenv=VPN_COVER_SITE_DISPOSABLE_GUEST=yes --setenv=GITHUB_ACTIONS=true \
    --setenv=RUNNER_ENVIRONMENT=github-hosted "$@"
}
wait_ready() {
  for _ in {1..120}; do
    if inside /usr/bin/systemctl is-active --quiet nginx >"$WORK/ready.log" 2>&1; then return; fi
    kill -0 "$SUPERVISOR" 2>/dev/null || { cat "$WORK/guest.log"; fail 'guest supervisor exited'; }
    sleep 1
  done
  cat "$WORK/guest.log"; fail 'guest boot did not reach nginx'
}
wait_ready
BOOT1=$(inside /usr/bin/cat /proc/sys/kernel/random/boot_id)
inside /usr/local/libexec/cover-site/lifecycle.py health
inside /usr/bin/bash -c 'test "$(curl -s --noproxy "*" http://127.0.0.1:18081/)" = unrelated-site'
# An interrupted switch is reconstructed inside the actual guest. The normal
# role recovery unit must restore the checked active release on the next boot.
inside /usr/bin/python3 -c 'import json,pathlib; b=pathlib.Path("/var/lib/cover-site"); old=(b/"active").resolve(); candidate=(b/"previous").resolve(); (b/"pending.json").write_text(json.dumps({"old":str(old),"candidate":str(candidate)})); p=pathlib.Path("/etc/nginx/sites-enabled/cover-site.conf"); p.unlink(); p.symlink_to(candidate/"site.conf")'
# machinectl contacts only this randomly named owned guest. It is not host reboot.
machinectl reboot "$MACHINE"
for _ in {1..120}; do
  BOOT2=$(inside /usr/bin/cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
  if [[ -n $BOOT2 && $BOOT2 != "$BOOT1" ]]; then break; fi
  kill -0 "$SUPERVISOR" 2>/dev/null || { cat "$WORK/guest.log"; fail 'supervisor lost guest during reboot'; }
  sleep 1
done
[[ -n ${BOOT2:-} && $BOOT2 != "$BOOT1" ]] || { cat "$WORK/guest.log"; fail 'guest boot ID did not change'; }
wait_ready
inside /usr/bin/test ! -e /var/lib/cover-site/pending.json
inside /usr/bin/python3 -c 'import pathlib; b=pathlib.Path("/var/lib/cover-site"); assert pathlib.Path("/etc/nginx/sites-enabled/cover-site.conf").resolve() == (b/"active").resolve()/"site.conf"'
inside /usr/local/libexec/cover-site/lifecycle.py health
inside /usr/bin/bash -c 'test "$(curl -s --noproxy "*" http://127.0.0.1:18081/)" = unrelated-site'
printf 'PASS actual systemd guest userspace reboot: %s -> %s; TLS/H2 and unrelated site recovered. Host kernel untouched.\n' "$BOOT1" "$BOOT2"
