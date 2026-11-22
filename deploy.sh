#!/usr/bin/env bash
set -euo pipefail

PROXMOX_HOST="192.0.2.49"
PROXMOX_USER="root"
CONTAINER_ID="123"
DEPLOY_DIR="/opt/vigilance"
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

# Keep environment, container-specific config, and the existing Docker volume.
docker exec vigilance python -c "import sqlite3; src=sqlite3.connect('file:/app/data/vigilance.db?mode=ro', uri=True); dst=sqlite3.connect('/app/data/vigilance.db.before-${commit}'); src.backup(dst); print('database_backup=' + dst.execute('PRAGMA quick_check').fetchone()[0]); dst.close(); src.close()"
tar -cf "/tmp/vigilance-source-before-${commit}.tar" -C "$deploy_dir" vigilance docker
rm -rf "$deploy_dir/vigilance" "$deploy_dir/docker"
mv "$stage/vigilance" "$deploy_dir/vigilance"
mv "$stage/docker" "$deploy_dir/docker"
tar -xf "$archive" -C "$deploy_dir"

compose=(docker compose -p vigilance --project-directory "$deploy_dir/docker" -f "$deploy_dir/docker/docker-compose.yml" -f "$deploy_dir/docker/docker-compose.override.yml")
"${compose[@]}" config --quiet
"${compose[@]}" up -d --build

for attempt in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8000/api/health >/dev/null; then
        break
    fi
    if [ "$attempt" -eq 30 ]; then
        echo "Health check failed after deployment." >&2
        exit 1
    fi
    sleep 2
done

curl -fsS http://127.0.0.1:8000/api/health
printf '\nDashboard severity counts: '
curl -fsS http://127.0.0.1:8000/api/dashboard/stats | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("findings_by_severity", {}), sort_keys=True))'
printf 'Container severity counts: '
curl -fsS http://127.0.0.1:8000/api/inventory-findings | python3 -c 'import json,sys; hosts=json.load(sys.stdin); levels=("CRITICAL","HIGH","MEDIUM","LOW","NONE"); print(json.dumps({k:sum(h.get("counts",{}).get(k,0) for h in hosts) for k in levels}, sort_keys=True))'

rm -rf "$stage" "$archive"
REMOTE_SCRIPT

ssh -o BatchMode=yes "$REMOTE" "rm -f ${REMOTE_ARCHIVE}"
