#!/usr/bin/env bash
set -euo pipefail

# Target from the environment or a local file outside the repository, e.g.
#   ~/.config/vigilance/deploy.env:  PROXMOX_HOST=192.0.2.49  CONTAINER_ID=123
DEPLOY_ENV="${VIGILANCE_DEPLOY_ENV:-$HOME/.config/vigilance/deploy.env}"
# shellcheck disable=SC1090
[ -f "$DEPLOY_ENV" ] && . "$DEPLOY_ENV"
PROXMOX_HOST="${PROXMOX_HOST:?PROXMOX_HOST fehlt: in $DEPLOY_ENV oder als Umgebungsvariable setzen}"
PROXMOX_USER="${PROXMOX_USER:-root}"
CONTAINER_ID="${CONTAINER_ID:-123}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/vigilance}"
REMOTE="${PROXMOX_USER}@${PROXMOX_HOST}"
COMMIT="$(git rev-parse --short HEAD)"
ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/vigilance-deploy.XXXXXX")"
REMOTE_ARCHIVE="/tmp/vigilance-deploy-${COMMIT}.tar"

trap 'rm -f "$ARCHIVE"' EXIT

echo "=== Vigilance ${COMMIT} -> CT ${CONTAINER_ID} auf ${PROXMOX_HOST} ==="
git archive --format=tar --output="$ARCHIVE" HEAD
scp -o BatchMode=yes "$ARCHIVE" "${REMOTE}:${REMOTE_ARCHIVE}"

ssh -o BatchMode=yes "$REMOTE" "pct status ${CONTAINER_ID} | grep -q 'status: running' && pct push ${CONTAINER_ID} ${REMOTE_ARCHIVE} ${REMOTE_ARCHIVE}"
ssh -o BatchMode=yes "$REMOTE" "pct exec ${CONTAINER_ID} -- bash -s -- ${COMMIT} ${REMOTE_ARCHIVE} ${DEPLOY_DIR}" <<'REMOTE_SCRIPT'
set -euo pipefail

commit=$1
archive=$2
deploy_dir=$3
stage="/tmp/vigilance-release-${commit}"

test -f "$deploy_dir/.env"
test -f "$deploy_dir/docker/docker-compose.override.yml"
rm -rf "$stage"
mkdir -p "$stage"
tar -xf "$archive" -C "$stage"
test -f "$stage/docker/docker-compose.yml"
test -f "$stage/vigilance/database/crud.py"
cp "$deploy_dir/docker/docker-compose.override.yml" "$stage/docker/docker-compose.override.yml"

# Backup database (PostgreSQL)
echo "Backing up database..."
docker exec vigilance-postgres pg_dump -U vigilance vigilance > "/tmp/vigilance-db-before-${commit}.sql" 2>/dev/null || echo "pg_dump failed (database may not exist yet)"
# Also backup config volume
tar -cf "/tmp/vigilance-config-before-${commit}.tar" -C "$deploy_dir" data 2>/dev/null || true

# Backup source code
tar -cf "/tmp/vigilance-source-before-${commit}.tar" -C "$deploy_dir" vigilance docker

# Deploy new code
rm -rf "$deploy_dir/vigilance" "$deploy_dir/docker"
mv "$stage/vigilance" "$deploy_dir/vigilance"
mv "$stage/docker" "$deploy_dir/docker"
tar -xf "$archive" -C "$deploy_dir"

compose=(docker compose -p vigilance --project-directory "$deploy_dir/docker" -f "$deploy_dir/docker/docker-compose.yml" -f "$deploy_dir/docker/docker-compose.override.yml")
"${compose[@]}" config --quiet

# Clear BuildKit cache to avoid stale build plan (pip install before COPY vigilance/)
docker builder prune -af

# Force fresh build plan with cache-bust arg
"${compose[@]}" build --no-cache --build-arg CACHEBUST=$(date +%s)
"${compose[@]}" up -d

# Wait longer for PostgreSQL to be ready and migrations to run
for attempt in $(seq 1 60); do
    if curl -fsS http://127.0.0.1:8000/api/health >/dev/null; then
        break
    fi
    if [ "$attempt" -eq 60 ]; then
        echo "Health check failed after deployment." >&2
        docker compose -p vigilance --project-directory "$deploy_dir/docker" logs --tail 50
        exit 1
    fi
    sleep 3
done

curl -fsS http://127.0.0.1:8000/api/health
printf '\nDashboard severity counts: '
curl -fsS http://127.0.0.1:8000/api/dashboard/stats | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("findings_by_severity", {}), sort_keys=True))'
printf 'Container severity counts: '
curl -fsS http://127.0.0.1:8000/api/inventory-findings | python3 -c 'import json,sys; hosts=json.load(sys.stdin); levels=("CRITICAL","HIGH","MEDIUM","LOW","NONE"); print(json.dumps({k:sum(h.get("counts",{}).get(k,0) for h in hosts) for k in levels}, sort_keys=True))'
printf 'Overview: '
curl -fsS http://127.0.0.1:8000/api/overview | python3 -c 'import json,sys; k=json.load(sys.stdin)["kpis"]; print(json.dumps(k, sort_keys=True))'

rm -rf "$stage" "$archive"
REMOTE_SCRIPT

ssh -o BatchMode=yes "$REMOTE" "rm -f ${REMOTE_ARCHIVE}"