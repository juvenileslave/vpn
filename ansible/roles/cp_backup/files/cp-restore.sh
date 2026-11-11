#!/usr/bin/env bash
# Restore one cp-backup artifact into a new database of a disposable PostgreSQL
# container (docs/BACKUP.md). Invoked by the cp_backup role (tasks_from: restore).
set -Eeuo pipefail
umask 077

log() { printf 'cp-restore: %s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

readonly ARTIFACT_RE='^cp-backup-[0-9]{8}T[0-9]{6}Z\.pgcustom\.age$'
readonly IDENT_RE='^[a-z_][a-z0-9_]{0,62}$'
readonly NAME_RE='^[A-Za-z0-9_][A-Za-z0-9_.-]*$'

artifact=${CP_RESTORE_ARTIFACT:?CP_RESTORE_ARTIFACT is required}
identity=${CP_RESTORE_IDENTITY_FILE:?CP_RESTORE_IDENTITY_FILE is required}
container=${CP_RESTORE_CONTAINER:?CP_RESTORE_CONTAINER is required}
db_name=${CP_RESTORE_DB_NAME:?CP_RESTORE_DB_NAME is required}
db_user=${CP_RESTORE_DB_USER:-postgres}
live_project=${CP_RESTORE_LIVE_PROJECT:-remnawave}
replace=${CP_RESTORE_REPLACE:-false}
sentinel_table=${CP_RESTORE_SENTINEL_TABLE:-}
sentinel_rows=${CP_RESTORE_SENTINEL_ROWS:-}

[[ ${CP_RESTORE_CONFIRM:-false} == true ]] || die "CP_RESTORE_CONFIRM=true is required"
[[ $replace == true || $replace == false ]] || die "CP_RESTORE_REPLACE must be true or false"
[[ $(basename -- "$artifact") =~ $ARTIFACT_RE && -f $artifact ]] \
  || die "artifact $artifact is missing or not a cp-backup artifact"
[[ -f $identity && -r $identity ]] || die "identity file is missing"
[[ $db_name =~ $IDENT_RE ]] || die "database name must match $IDENT_RE"
[[ $db_user =~ $NAME_RE && $container =~ $NAME_RE ]] || die "invalid user or container name"
if [[ -n $sentinel_table ]]; then
  [[ $sentinel_table =~ ^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$ ]] || die "invalid sentinel table name"
  [[ $sentinel_rows =~ ^[0-9]+$ ]] || die "CP_RESTORE_SENTINEL_ROWS must be an integer"
fi

psql_in() {
  docker exec "$container" psql --no-password --username="$db_user" --dbname="$1" \
    --set=ON_ERROR_STOP=1 --no-align --tuples-only --command="$2"
}

[[ $(docker inspect --format '{{.State.Running}}' "$container") == true ]] \
  || die "container $container is not running"
project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container")
if [[ $project == "$live_project" ]]; then
  [[ $replace == true ]] || die "container $container belongs to live project $live_project; set cp_restore_replace to override"
  log "WARNING: restoring into live project $live_project because replace=true"
fi

exists=$(psql_in postgres "SELECT 1 FROM pg_database WHERE datname = '$db_name'")
if [[ $exists == 1 ]]; then
  [[ $replace == true ]] || die "database $db_name already exists; set cp_restore_replace to override"
  log "dropping existing database $db_name because replace=true"
  docker exec "$container" dropdb --no-password --username="$db_user" --force -- "$db_name"
fi

docker exec "$container" createdb --no-password --username="$db_user" -- "$db_name"
created=true
on_exit() {
  local rc=$?
  if ((rc != 0)) && [[ ${created:-false} == true ]]; then
    docker exec "$container" dropdb --no-password --username="$db_user" --force -- "$db_name" || true
    log "removed incomplete database $db_name"
  fi
  exit "$rc"
}
trap on_exit EXIT

age --decrypt --identity "$identity" "$artifact" \
  | docker exec -i "$container" pg_restore --no-password --username="$db_user" \
    --dbname="$db_name" --exit-on-error --single-transaction --no-owner --no-acl

tables=$(psql_in "$db_name" "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')")
((tables > 0)) || die "restored database $db_name has no tables"
if [[ -n $sentinel_table ]]; then
  rows=$(psql_in "$db_name" "SELECT count(*) FROM $sentinel_table")
  [[ $rows == "$sentinel_rows" ]] || die "sentinel $sentinel_table has $rows rows, expected $sentinel_rows"
  log "sentinel $sentinel_table rows=$rows"
fi
created=false
log "restored $(basename -- "$artifact") into $db_name tables=$tables"
