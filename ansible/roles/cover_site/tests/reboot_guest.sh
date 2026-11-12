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
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
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
for path in /etc/cover-site /var/lib/cover-site /var/www/cover-site-acme; do
  cp "$path/.cover-site-owner.json" "$GUEST$path/.cover-site-owner.json"
done
cp "$ROOT/ansible/roles/cover_site/tests/interrupt_activation.py" "$GUEST/usr/local/libexec/cover-ci-interrupt.py"
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
reboot_checked_guest() {
  local before after=
  before=$(inside /usr/bin/cat /proc/sys/kernel/random/boot_id)
  machinectl reboot "$MACHINE"
  for _ in {1..120}; do
    after=$(inside /usr/bin/cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    if [[ -n $after && $after != "$before" ]]; then break; fi
    kill -0 "$SUPERVISOR" 2>/dev/null || { cat "$WORK/guest.log"; fail 'supervisor lost guest during reboot'; }
    sleep 1
  done
  [[ -n $after && $after != "$before" ]] || { cat "$WORK/guest.log"; fail 'guest boot ID did not change'; }
  wait_ready
  inside /usr/bin/test ! -e /var/lib/cover-site/pending.json
  inside /usr/bin/bash -c 'test "$(curl -s --noproxy "*" http://127.0.0.1:18081/)" = unrelated-site'
  printf 'Actual isolated guest reboot: %s -> %s\n' "$before" "$after"
}
interrupt() {
  local code
  set +e
  inside /usr/bin/python3 /usr/local/libexec/cover-ci-interrupt.py "$@"
  code=$?
  set -e
  [[ $code == 86 ]] || fail 'real activation interruption seam was not reached'
}
wait_ready
inside /usr/local/libexec/cover-site/lifecycle.py health
# Save real checked fixture identities; no account or live external CA is copied.
inside /usr/bin/python3 -c 'import json,pathlib; b=pathlib.Path("/var/lib/cover-site"); tls=(b/"active").resolve(); http=next((b/"releases").glob("*-http")); pathlib.Path("/var/tmp/cover-initial.json").write_text(json.dumps({"tls":str(tls),"http":str(http)}))'
INITIAL_TLS=$(inside /usr/bin/python3 -c 'import json; print(json.load(open("/var/tmp/cover-initial.json"))["tls"])')
INITIAL_HTTP=$(inside /usr/bin/python3 -c 'import json; print(json.load(open("/var/tmp/cover-initial.json"))["http"])')

printf '\n=== Interrupted first HTTP activation reboots into absent owned state\n'
inside /usr/bin/python3 -c 'import sys; sys.path.insert(0,"/usr/local/libexec/cover-site"); import lifecycle; lifecycle.restore(None,None); lifecycle.run(["nginx","-t"]); lifecycle.run(["systemctl","reload","nginx"])'
interrupt enabled "$INITIAL_HTTP"
reboot_checked_guest
inside /usr/bin/python3 -c 'import os,pathlib,socket,json; b=pathlib.Path("/var/lib/cover-site"); assert all(not os.path.lexists(p) for p in (b/"active",b/"previous",pathlib.Path("/etc/cover-site/settings.json"),pathlib.Path("/etc/nginx/sites-enabled/cover-site.conf"))); tls=pathlib.Path(json.load(open("/var/tmp/cover-initial.json"))["tls"]); port=json.load(open(tls/"metadata.json"))["settings"]["port"]; s=socket.socket(); s.settimeout(2); assert s.connect_ex(("127.0.0.1",port)) != 0; s.close()'

# Complete the real HTTP bootstrap before interrupting the first TLS commit.
inside /usr/bin/python3 -c 'import json,pathlib,sys; sys.path.insert(0,"/usr/local/libexec/cover-site"); import lifecycle; lifecycle.activate(pathlib.Path(json.load(open("/var/tmp/cover-initial.json"))["http"]))'
printf '\n=== Interrupted first TLS commit reboots into checked HTTP bootstrap\n'
interrupt active "$INITIAL_TLS"
reboot_checked_guest
inside /usr/bin/python3 -c 'import os,pathlib,socket,json; b=pathlib.Path("/var/lib/cover-site"); initial=json.load(open("/var/tmp/cover-initial.json")); http=pathlib.Path(initial["http"]); assert (b/"active").resolve()==http; assert not os.path.lexists(b/"previous"); assert pathlib.Path("/etc/nginx/sites-enabled/cover-site.conf").resolve()==http/"site.conf"; assert json.load(open("/etc/cover-site/settings.json"))==json.load(open(http/"metadata.json"))["settings"]; tls=pathlib.Path(initial["tls"]); port=json.load(open(tls/"metadata.json"))["settings"]["port"]; s=socket.socket(); s.settimeout(2); assert s.connect_ex(("127.0.0.1",port)) != 0; s.close()'
inside /usr/bin/python3 -c 'import json,pathlib,sys; sys.path.insert(0,"/usr/local/libexec/cover-site"); import lifecycle; lifecycle.activate(pathlib.Path(json.load(open("/var/tmp/cover-initial.json"))["tls"]))'
if inside /usr/local/libexec/cover-site/lifecycle.py rollback; then fail 'first TLS rollback accepted an HTTP/absent target'; fi
inside /usr/local/libexec/cover-site/lifecycle.py health

printf '\n=== Generate two real checked content/settings versions in the guest\n'
# Only copied synthetic certificate snapshots seed a guest-local lineage fixture.
# This is not ACME proof: initial/renewed HTTP-01 is exercised by runtime_vm.sh.
inside /usr/bin/python3 -c '
import json,pathlib,shutil,socket,sys,tempfile
sys.path.insert(0,"/usr/local/libexec/cover-site")
import lifecycle
old=lifecycle.release(); value=json.load(open(old/"metadata.json"))["settings"]
live=pathlib.Path("/etc/cover-site/acme/live")/value["hostname"]; live.mkdir(parents=True)
for source in (old/"certificate").iterdir():
    shutil.copyfile(source,live/source.name); (live/source.name).chmod(0o600 if source.name=="privkey.pem" else 0o644)
with tempfile.TemporaryDirectory(prefix="cover-boot-content-",dir="/var/tmp") as temporary:
    content=pathlib.Path(temporary)/"content"; shutil.copytree(old/"content",content)
    page=content/"index.html"; page.write_text(page.read_text()+"\n<p>Disposable guest version B: coastal observations.</p>\n")
    probe=socket.socket(); probe.bind(("127.0.0.1",0)); port=probe.getsockname()[1]; probe.close()
    lifecycle.stage({**value,"port":port},tls=True,source=content)
    page.write_text(page.read_text()+"\n<p>Disposable guest version C: seasonal field observations.</p>\n")
    lifecycle.stage(value,tls=True,source=content)
pathlib.Path("/var/tmp/cover-expected.json").write_text(json.dumps({"active":str(lifecycle.release()),"previous":str(lifecycle.release(lifecycle.PREVIOUS)),"candidate":str(old),"settings":json.load(open(lifecycle.SETTINGS))}))
'
CANDIDATE=$(inside /usr/bin/python3 -c 'import json; print(json.load(open("/var/tmp/cover-expected.json"))["candidate"])')
printf '\n=== Interrupted commit retains the distinct older rollback target at boot\n'
interrupt previous "$CANDIDATE"
reboot_checked_guest
inside /usr/bin/python3 -c 'import json,pathlib; e=json.load(open("/var/tmp/cover-expected.json")); b=pathlib.Path("/var/lib/cover-site"); assert (b/"active").resolve()==pathlib.Path(e["active"]); assert (b/"previous").resolve()==pathlib.Path(e["previous"]); assert e["active"]!=e["previous"]; assert pathlib.Path("/etc/nginx/sites-enabled/cover-site.conf").resolve()==(b/"active").resolve()/"site.conf"; assert json.load(open("/etc/cover-site/settings.json"))==e["settings"]'
inside /usr/local/libexec/cover-site/lifecycle.py health
inside /usr/local/libexec/cover-site/lifecycle.py rollback
inside /usr/bin/python3 -c 'import json,pathlib; e=json.load(open("/var/tmp/cover-expected.json")); b=pathlib.Path("/var/lib/cover-site"); old=(b/"active").resolve(); assert str(old)==e["previous"]; assert json.load(open("/etc/cover-site/settings.json"))==json.load(open(old/"metadata.json"))["settings"]'
inside /usr/local/libexec/cover-site/lifecycle.py health
inside /usr/local/libexec/cover-site/lifecycle.py rollback
inside /usr/bin/python3 -c 'import json,pathlib; e=json.load(open("/var/tmp/cover-expected.json")); assert str(pathlib.Path("/var/lib/cover-site/active").resolve())==e["active"]; assert json.load(open("/etc/cover-site/settings.json"))==e["settings"]'
inside /usr/local/libexec/cover-site/lifecycle.py health
inside /usr/bin/bash -c 'test "$(curl -s --noproxy "*" http://127.0.0.1:18081/)" = unrelated-site'
printf 'PASS actual guest reboots: first HTTP interruption -> absent, first TLS interruption -> checked HTTP; later commit -> checked TLS/H2, distinct previous and old settings. Host kernel untouched.\n'
