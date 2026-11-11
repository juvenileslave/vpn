#!/usr/bin/env bash
# Encrypted pg_dump of the panel PostgreSQL container (docs/BACKUP.md).
# Settings come from the environment (systemd EnvironmentFile). The script reads
# no secrets and logs only paths, sizes, counts and checksums.
set -Eeuo pipefail
umask 077

log() { printf 'cp-backup: %s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

readonly ARTIFACT_RE='^cp-backup-[0-9]{8}T[0-9]{6}Z\.pgcustom\.age$'
readonly NAME_RE='^[A-Za-z0-9_][A-Za-z0-9_.-]*$'

backup_dir=${CP_BACKUP_DIR:?CP_BACKUP_DIR is required}
recipients=${CP_BACKUP_RECIPIENTS_FILE:?CP_BACKUP_RECIPIENTS_FILE is required}
db_name=${CP_BACKUP_DB_NAME:-postgres}
db_user=${CP_BACKUP_DB_USER:-postgres}
project=${CP_BACKUP_COMPOSE_PROJECT:-remnawave}
service=${CP_BACKUP_COMPOSE_SERVICE:-postgres}
container=${CP_BACKUP_CONTAINER:-}
keep_days=${CP_BACKUP_KEEP_DAYS:-14}
keep_count=${CP_BACKUP_KEEP_COUNT:-30}
lock_file=${CP_BACKUP_LOCK_FILE:-/run/lock/cp-backup.lock}
verify_identity=${CP_BACKUP_VERIFY_IDENTITY_FILE:-}
unsafe_skip_verify=${CP_BACKUP_UNSAFE_SKIP_VERIFY:-false}

for value in "$db_name" "$db_user" "$project" "$service"; do
  [[ $value =~ $NAME_RE ]] || die "invalid database, user, project or service name"
done
[[ -z $container || $container =~ $NAME_RE ]] || die "invalid container name"
[[ $keep_days =~ ^[1-9][0-9]*$ && $keep_count =~ ^[1-9][0-9]*$ ]] \
  || die "CP_BACKUP_KEEP_DAYS and CP_BACKUP_KEEP_COUNT must be positive integers"
[[ $unsafe_skip_verify == true || $unsafe_skip_verify == false ]] \
  || die "CP_BACKUP_UNSAFE_SKIP_VERIFY must be true or false"

exec 9>>"$lock_file" || die "cannot open lock $lock_file"
if ! flock --nonblock 9; then
  log "another run holds $lock_file; refusing to overlap"
  exit 75
fi

[[ -d $backup_dir && ! -L $backup_dir ]] || die "backup directory $backup_dir is missing"
[[ -f $recipients && -r $recipients ]] || die "recipients file $recipients is missing"
if grep -q 'AGE-SECRET-KEY-' "$recipients"; then
  die "recipients file contains an age identity; refusing to run"
fi
recipient_count=$(grep -cEv '^[[:space:]]*(#|$)' "$recipients" || true)
((recipient_count >= 1)) || die "recipients file $recipients lists no recipients"

tmp=""
work=""
cleanup() {
  local rc=$?
  [[ -n $tmp ]] && rm -f -- "$tmp"
  [[ -n $work ]] && rm -rf -- "$work"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Leftovers of a crashed run; safe to remove while holding the lock.
find "$backup_dir" -maxdepth 1 -type f -name '.cp-backup-*.partial' -delete

if [[ -z $container ]]; then
  mapfile -t ids < <(docker ps --quiet \
    --filter "label=com.docker.compose.project=$project" \
    --filter "label=com.docker.compose.service=$service")
  ((${#ids[@]} == 1)) || die "expected one running $project/$service container, found ${#ids[@]}"
  container=${ids[0]}
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
final="$backup_dir/cp-backup-$stamp.pgcustom.age"
[[ ! -e $final ]] || die "artifact $final already exists"

work=$(mktemp -d "${RUNTIME_DIRECTORY:-/run}/cp-backup.XXXXXXXX")
extra_recipients=()
identity=""
if [[ $unsafe_skip_verify == true ]]; then
  log "WARNING: ciphertext verification disabled by CP_BACKUP_UNSAFE_SKIP_VERIFY"
elif [[ -n $verify_identity ]]; then
  [[ -f $verify_identity && -r $verify_identity ]] || die "verify identity $verify_identity is missing"
  identity=$verify_identity
else
  # Per-run verification key: the artifact gets one extra recipient whose
  # identity lives only in this runtime directory and is deleted on exit.
  age-keygen -o "$work/verify.key" 2>/dev/null
  extra_recipients=(-r "$(age-keygen -y "$work/verify.key")")
  identity="$work/verify.key"
fi

tmp=$(mktemp --suffix=.partial "$backup_dir/.cp-backup-XXXXXXXX")
docker exec "$container" pg_dump --format=custom --no-password \
  --username="$db_user" --dbname="$db_name" \
  | age --encrypt --recipients-file "$recipients" "${extra_recipients[@]}" >"$tmp"
[[ -s $tmp ]] || die "encrypted dump is empty"
sync -- "$tmp"

if [[ -n $identity ]]; then
  age --decrypt --identity "$identity" "$tmp" \
    | docker exec -i "$container" pg_restore --list >"$work/toc"
  toc_entries=$(grep -cv '^;' "$work/toc" || true)
  ((toc_entries > 0)) || die "pg_restore --list returned an empty table of contents"
  log "verified: age --decrypt | pg_restore --list ok, $toc_entries TOC entries"
fi

mv -T -- "$tmp" "$final"
tmp=""
sync -- "$backup_dir"
size=$(stat -c %s -- "$final")
sum=$(sha256sum -- "$final")
log "wrote $final size=$size sha256=${sum%% *} recipients=$recipient_count"

# Retention runs only after a verified write and touches only owned names.
# The newest artifact is always kept regardless of age.
now=$(date -u +%s)
mapfile -t artifacts < <(find "$backup_dir" -maxdepth 1 -type f -printf '%f\n' \
  | grep -E "$ARTIFACT_RE" | LC_ALL=C sort -r || true)
for ((i = 1; i < ${#artifacts[@]}; i++)); do
  name=${artifacts[i]}
  [[ "$backup_dir/$name" != "$final" ]] || continue
  ts=${name#cp-backup-}
  ts=${ts%%.*}
  epoch=$(date -u -d "${ts:0:4}-${ts:4:2}-${ts:6:2}T${ts:9:2}:${ts:11:2}:${ts:13:2}Z" +%s)
  if ((i >= keep_count || now - epoch > keep_days * 86400)); then
    rm -f -- "$backup_dir/$name"
    log "retention removed $backup_dir/$name"
  fi
done
kept=$(find "$backup_dir" -maxdepth 1 -type f -printf '%f\n' | grep -cE "$ARTIFACT_RE" || true)
log "retention kept $kept artifacts (keep_count=$keep_count keep_days=$keep_days)"
