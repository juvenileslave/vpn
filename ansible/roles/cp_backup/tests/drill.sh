#!/usr/bin/env bash
# Backup/restore drill for the cp_backup role in a disposable guest (docs/BACKUP.md).
# Requires root, Docker, network access to GitHub and Docker Hub, and the
# repository .venv (make bootstrap && make -C ansible bootstrap). Starts two
# throwaway PostgreSQL containers, generates a throwaway age identity and
# installs the role on this host. Never run it on a panel host.
set -Eeuo pipefail

repo=$(cd "$(dirname "$0")/../../../.." && pwd)
ansible_dir="$repo/ansible"
playbook="$repo/.venv/bin/ansible-playbook"
pg_image=${DRILL_PG_IMAGE:-postgres:17.6-alpine}
src=cp-backup-drill-src
dst=cp-backup-drill-dst
project=cpdrill
sentinel_rows=42
backup_dir=/var/lib/cp-backup-drill
work=$(mktemp -d /tmp/cp-backup-drill.XXXXXXXX)
results=()

pass() { results+=("PASS $*"); printf 'drill: PASS %s\n' "$*"; }
fail() { printf 'drill: FAIL %s\n' "$*" >&2; exit 1; }
cleanup() {
  docker rm -f "$src" "$dst" >/dev/null 2>&1 || true
  rm -rf -- "$work" "$backup_dir"
}
trap cleanup EXIT

[[ $(id -u) == 0 ]] || fail "run as root in a disposable guest"
command -v docker >/dev/null || fail "docker is required"
[[ -x $playbook ]] || fail "run make bootstrap && make -C ansible bootstrap first"

psql_src() { docker exec "$src" psql -U postgres -v ON_ERROR_STOP=1 -tA "$@"; }
psql_dst() { docker exec "$dst" psql -U postgres -v ON_ERROR_STOP=1 -tA "$@"; }
wait_pg() {
  for _ in $(seq 60); do docker exec "$1" pg_isready -U postgres -q && return 0; sleep 1; done
  fail "$1 did not become ready"
}
artifacts() { find "$backup_dir" -maxdepth 1 -type f -name 'cp-backup-*.pgcustom.age' -printf '%f\n' | LC_ALL=C sort; }
snapshot() { (cd "$backup_dir" && find . -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort | xargs -r sha256sum); }
run_backup() {
  # shellcheck source=/dev/null
  (set -a; . /etc/cp-backup/cp-backup.env; set +a; env "$@" /usr/local/sbin/cp-backup)
}

# Disposable PostgreSQL: source labelled like a compose service, plus a clean target.
pw=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
docker run -d --name "$src" -e POSTGRES_PASSWORD="$pw" \
  --label com.docker.compose.project="$project" --label com.docker.compose.service=postgres \
  "$pg_image" >/dev/null
docker run -d --name "$dst" -e POSTGRES_PASSWORD="$pw" "$pg_image" >/dev/null
wait_pg "$src"
wait_pg "$dst"

# Fixture: database `panel` with sentinel table public.cp_backup_sentinel (42 rows).
psql_src -c 'CREATE DATABASE panel' >/dev/null
psql_src -d panel -c "CREATE TABLE public.cp_backup_sentinel (id integer PRIMARY KEY, label text NOT NULL);
  INSERT INTO public.cp_backup_sentinel SELECT g, 'row-' || g FROM generate_series(1, $sentinel_rows) g;" >/dev/null
fixture_digest=$(psql_src -d panel -c "SELECT md5(string_agg(id || ':' || label, ',' ORDER BY id)) FROM public.cp_backup_sentinel")

# Install the role on this guest. Without systemd as PID 1 the timer
# activation task is skipped; units are still rendered and verified.
printf 'localhost ansible_connection=local ansible_python_interpreter=%s\n' "$(command -v python3)" >"$work/hosts"
skip=()
[[ $(ps -p 1 -o comm=) == systemd ]] || skip=(--skip-tags cp_backup_systemd)
mkdir -p "$work/operator"
cat >"$work/play-age.yml" <<EOF
- hosts: localhost
  gather_facts: true
  tasks:
    - ansible.builtin.include_role:
        name: $ansible_dir/roles/cp_backup
        tasks_from: age
EOF
(cd "$ansible_dir" && "$playbook" -i "$work/hosts" "$work/play-age.yml") >"$work/age.log" || { cat "$work/age.log"; fail "age install"; }
age-keygen -o "$work/operator/identity.txt" 2>/dev/null
age-keygen -y "$work/operator/identity.txt" >"$work/operator/recipients.txt"
pass "pinned age $(age --version) installed with checksum verification"

(cd "$ansible_dir" && "$playbook" -i "$work/hosts" playbooks/backup.yml "${skip[@]}" \
  -e cp_backup_hosts=localhost -e "cp_backup_recipients_file=$work/operator/recipients.txt" \
  -e "cp_backup_dir=$backup_dir" -e cp_backup_compose_project=$project \
  -e cp_backup_db_name=panel -e cp_backup_keep_count=3) >"$work/backup-play.log" \
  || { cat "$work/backup-play.log"; fail "backup.yml"; }
pass "backup.yml applied (${skip[*]:-timer activated})"

systemd-analyze verify /etc/systemd/system/cp-backup.service /etc/systemd/system/cp-backup.timer \
  || fail "systemd-analyze verify"
pass "systemd-analyze verify accepts cp-backup.service and cp-backup.timer"

# 1. Backup with mandatory verification.
run_backup 2>"$work/run1.log" || { cat "$work/run1.log"; fail "first backup"; }
cat "$work/run1.log"
grep -q 'verified: age --decrypt | pg_restore --list ok' "$work/run1.log" || fail "verification did not run"
first=$(artifacts | tail -n1)
[[ -n $first ]] || fail "no artifact"
[[ $(stat -c %a "$backup_dir/$first") == 600 ]] || fail "artifact mode is not 0600"
pass "backup wrote $first (mode 0600) and verified it"

# 2. Operator identity decrypts to a pipe and pg_restore lists the sentinel.
age -d -i "$work/operator/identity.txt" "$backup_dir/$first" \
  | docker exec -i "$dst" pg_restore --list >"$work/toc"
grep -q 'TABLE public cp_backup_sentinel' "$work/toc" || fail "sentinel missing from TOC"
pass "age -d | pg_restore --list succeeds with the operator identity"

# 3. Concurrent run is blocked while the first holds the lock.
psql_src -d panel -c "BEGIN; LOCK TABLE public.cp_backup_sentinel IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(6); COMMIT;" >/dev/null &
locker=$!
sleep 1
run_backup 2>"$work/run-a.log" &
runner=$!
sleep 2
set +e
run_backup 2>"$work/run-b.log"
rc_b=$?
set -e
wait "$runner" || { cat "$work/run-a.log"; fail "first concurrent run failed"; }
wait "$locker"
if [[ $rc_b != 75 ]] || ! grep -q 'refusing to overlap' "$work/run-b.log"; then
  cat "$work/run-b.log"
  fail "second run was not blocked (rc=$rc_b)"
fi
pass "second concurrent run exits 75 while the first holds the flock"

# 4. Retention: owned names only, keep_count=3 and keep_days, newest always kept.
touch "$backup_dir/operator-notes.txt" "$backup_dir/cp-backup-manual.age"
cp "$backup_dir/$first" "$backup_dir/cp-backup-20200101T000000Z.pgcustom.age"
for _ in 1 2 3; do sleep 1; run_backup 2>>"$work/retention.log" || { cat "$work/retention.log"; fail "retention run"; }; done
newest=$(artifacts | tail -n1)
mapfile -t kept < <(artifacts)
[[ ${#kept[@]} == 3 ]] || fail "retention kept ${#kept[@]} artifacts, expected 3"
[[ ! -e $backup_dir/cp-backup-20200101T000000Z.pgcustom.age ]] || fail "expired artifact kept"
[[ -e $backup_dir/operator-notes.txt && -e $backup_dir/cp-backup-manual.age ]] || fail "retention removed foreign files"
grep -q "wrote $backup_dir/$newest" "$work/retention.log" || fail "newest artifact is not the last written"
pass "retention keeps 3 newest artifacts incl. $newest, drops expired, ignores foreign files"
rm -f "$backup_dir/operator-notes.txt" "$backup_dir/cp-backup-manual.age"

# 5. The newest artifact survives every failure regardless of age.
mv "$backup_dir/$newest" "$backup_dir/cp-backup-20200102T000000Z.pgcustom.age"
before=$(snapshot)
expect_failure() {
  local label=$1
  shift
  sleep 1
  if run_backup "$@" 2>"$work/fail.log"; then fail "$label: run succeeded"; fi
  [[ $(snapshot) == "$before" ]] || fail "$label: artifacts changed"
  ! find "$backup_dir" -name '*.partial' | grep -q . || fail "$label: partial file left"
  pass "$label exits non-zero; previous artifacts unchanged, no partial file ($(tail -n1 "$work/fail.log"))"
}
expect_failure "injected pg_dump failure" CP_BACKUP_DB_NAME=missing_db
age-keygen -o "$work/wrong-identity.txt" 2>/dev/null
expect_failure "injected identity failure" "CP_BACKUP_VERIFY_IDENTITY_FILE=$work/wrong-identity.txt"
expect_failure "missing verify identity" "CP_BACKUP_VERIFY_IDENTITY_FILE=$work/absent.txt"
: >"$work/empty-recipients.txt"
expect_failure "empty recipients file" "CP_BACKUP_RECIPIENTS_FILE=$work/empty-recipients.txt"
expect_failure "identity in recipients file" "CP_BACKUP_RECIPIENTS_FILE=$work/operator/identity.txt"
docker stop "$src" >/dev/null
expect_failure "stopped source container" CP_BACKUP_DB_NAME=panel
docker start "$src" >/dev/null
wait_pg "$src"

# 6. Restore drill: drop the source database, restore into a new database.
restore_artifact=$backup_dir/$(artifacts | tail -n1)
psql_src -c 'ALTER DATABASE panel RENAME TO panel_gone' >/dev/null
restore() {
  (cd "$ansible_dir" && "$playbook" -i "$work/hosts" playbooks/restore.yml \
    -e cp_restore_hosts=localhost -e cp_backup_age_install=false \
    -e "cp_restore_artifact_src=$restore_artifact" \
    -e "cp_restore_identity_file=$work/operator/identity.txt" \
    -e cp_restore_live_project=$project -e cp_restore_db_name=panel_restore \
    -e cp_restore_sentinel_table=public.cp_backup_sentinel \
    -e cp_restore_sentinel_rows=$sentinel_rows "$@") >"$work/restore.log" 2>&1
}
restore -e cp_restore_confirm=false && fail "restore without confirmation ran"
grep -q 'cp_restore_confirm=true' "$work/restore.log" || fail "unexpected refusal reason"
pass "restore.yml refuses without cp_restore_confirm=true"
restore -e cp_restore_confirm=true -e cp_restore_container=$src && fail "restore into live container ran"
grep -q 'belongs to live project' "$work/restore.log" || { cat "$work/restore.log"; fail "unexpected live refusal"; }
pass "restore.yml refuses the live panel container"
restore -e cp_restore_confirm=true -e cp_restore_container=$dst || { cat "$work/restore.log"; fail "restore"; }
restored_digest=$(psql_dst -d panel_restore -c "SELECT md5(string_agg(id || ':' || label, ',' ORDER BY id)) FROM public.cp_backup_sentinel")
gone_digest=$(psql_src -d panel_gone -c "SELECT md5(string_agg(id || ':' || label, ',' ORDER BY id)) FROM public.cp_backup_sentinel")
[[ $restored_digest == "$fixture_digest" && $gone_digest == "$fixture_digest" ]] || fail "sentinel rows differ"
pass "restored panel_restore: $sentinel_rows sentinel rows, digest matches the fixture"
restore -e cp_restore_confirm=true -e cp_restore_container=$dst && fail "restore over existing database ran"
grep -q 'already exists' "$work/restore.log" || { cat "$work/restore.log"; fail "unexpected exists refusal"; }
pass "restore.yml refuses an existing database"
restore -e cp_restore_confirm=true -e cp_restore_container=$dst -e cp_restore_replace=true \
  || { cat "$work/restore.log"; fail "replace restore"; }
pass "restore.yml replaces an existing database only with cp_restore_replace=true"
! find /tmp -maxdepth 1 -name 'cp-restore.*' | grep -q . || fail "restore left its working directory"
pass "restore removed the copied identity and artifact"

printf '\ndrill summary:\n'
printf '  %s\n' "${results[@]}"
