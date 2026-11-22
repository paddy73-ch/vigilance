#!/usr/bin/env bash
set -euo pipefail

PROXMOX_HOST="192.0.2.49"
PROXMOX_USER="root"
REPO_URL="https://github.com/paddy73-ch/vigilance.git"
DEPLOY_BRANCH="main"
DEPLOY_DIR="/opt/vigilance"
REMOTE="${PROXMOX_USER}@${PROXMOX_HOST}"

echo "=== Vigilance Deployment auf ${PROXMOX_HOST} ==="

ssh "$REMOTE" bash -s -- "$DEPLOY_DIR" "$REPO_URL" "$DEPLOY_BRANCH" <<'REMOTE_SCRIPT'
set -euo pipefail

deploy_dir=$1
repo_url=$2
branch=$3

mkdir -p "$deploy_dir"
if [ -d "$deploy_dir/.git" ]; then
    git -C "$deploy_dir" fetch origin "$branch"
    git -C "$deploy_dir" checkout "$branch"
    git -C "$deploy_dir" merge --ff-only "origin/$branch"
else
    if [ -n "$(find "$deploy_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo "Fehler: $deploy_dir ist nicht leer und kein Git-Checkout." >&2
        exit 1
    fi
    git clone --branch "$branch" "$repo_url" "$deploy_dir"
fi

if [ ! -f "$deploy_dir/.env" ]; then
    cp "$deploy_dir/.env.example" "$deploy_dir/.env"
    chmod 600 "$deploy_dir/.env"
    echo "Vorlage erstellt: $deploy_dir/.env"
    echo "Bitte Secrets eintragen und deploy.sh danach erneut starten." >&2
    exit 1
fi

if grep -Eq 'example\.com|your-token-secret|your-app-token|your-write-api-token|change-me-in-production' "$deploy_dir/.env"; then
    echo "Fehler: Bitte die Platzhalter-Secrets in $deploy_dir/.env ersetzen." >&2
    exit 1
fi

compose=(docker compose --project-directory "$deploy_dir/docker" -f "$deploy_dir/docker/docker-compose.yml")

# The application uses a named Docker volume, so prepare SSH material there.
"${compose[@]}" build vigilance
"${compose[@]}" run --rm --no-deps --user 0:0 --entrypoint /bin/sh vigilance -ec '
    mkdir -p /app/data/ssh
    if [ ! -f /app/data/ssh/id_rsa ]; then
        ssh-keygen -q -t ed25519 -f /app/data/ssh/id_rsa -N ""
    fi
    touch /app/data/ssh/known_hosts
    chmod 700 /app/data/ssh
    chmod 600 /app/data/ssh/id_rsa
    chmod 644 /app/data/ssh/id_rsa.pub /app/data/ssh/known_hosts
    chown -R 1000:1000 /app/data/ssh
'

"${compose[@]}" up -d --build

echo "=== SSH Public Key (auf Zielsysteme deployen) ==="
"${compose[@]}" exec -T vigilance cat /app/data/ssh/id_rsa.pub
echo
echo "=== Deployment abgeschlossen ==="
echo "Known hosts bei Bedarf ergänzen: docker compose -f $DEPLOY_DIR/docker/docker-compose.yml exec vigilance sh"
echo "Health: curl http://${PROXMOX_HOST}:8000/api/health"
REMOTE_SCRIPT
