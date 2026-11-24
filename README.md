# Vigilance

Self-hosted Proxmox security and patch monitoring dashboard with inventory, CVE tracking, and optional SSH-based discovery.

Vigilance automatically discovers webapps, services, Docker images, and tools on your Proxmox hosts, LXC containers, and VMs, matches them against CVE and security advisory databases, and sends notifications via Gotify or generic webhooks.

## Features

- **Proxmox Discovery**: Automatic inventory of nodes, VMs, and LXC containers via Proxmox VE API
- **SSH-based Discovery**: Deep scanning of Docker containers, system packages (dpkg/apk/rpm), systemd services, and custom checks
- **CVE Matching**: Integration with OSV.dev, GitHub Security Advisories (GHSA), NVD, Debian & Ubuntu Security Trackers
- **Smart Version Matching**: SemVer, Debian version, and Docker tag/digest comparison
- **Patch view**: per host what an `apt` update fixes, and which old packages left over from a previous Debian release should be removed
- **Exceptions**: Accept specific advisories (per host or everywhere) with a reason and optional expiry
- **Gotify Notifications**: Rich Markdown notifications with severity-based priority and digest mode
- **Web UI** (German): Jinja2 + Alpine.js, own CSS, no external resources (strict Content-Security-Policy), light/dark, phone-friendly
- **Docker Deployment**: Docker Compose with PostgreSQL database

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Proxmox VE    │────▶│   Vigilance      │────▶│   CVE Sources   │
│   (API + SSH)   │     │   (FastAPI)      │     │  (OSV, GHSA,    │
└─────────────────┘     └────────┬─────────┘     │   NVD, Debian,  │
                                 │               │   Ubuntu)       │
                                 ▼               └─────────────────┘
                        ┌──────────────────┐
                        │   PostgreSQL     │
                        │   + SQLAlchemy   │
                        └────────┬─────────┘
                                 │
                                 ▼
                        ┌──────────────────┐
                        │   Gotify /       │
                        │   Webhooks       │
                        └──────────────────┘
```

## Quick Start

### 1. Clone and Configure

```bash
git clone <repository> vigilance
cd vigilance
cp .env.example .env
# Edit .env with your settings
```

### 2. SSH Key Setup

Vigilance uses a hardcoded SSH key pair for consistency across container restarts. The key is automatically generated and distributed to all running VMs/LXCs on first scan.

For manual setup (optional):
```bash
mkdir -p data/ssh
ssh-keygen -t ed25519 -f data/ssh/id_rsa -N ""
```

### 3. Deploy SSH Key to Proxmox Nodes

```bash
# For each Proxmox node and target VM/LXC:
ssh-copy-id -i data/ssh/id_rsa.pub root@proxmox-node1
ssh-copy-id -i data/ssh/id_rsa.pub root@lxc-container-1
ssh-copy-id -i data/ssh/id_rsa.pub root@vm-1

# Initialize known_hosts
ssh-keyscan proxmox-node1 lxc-container-1 vm-1 > data/ssh/known_hosts
```

### 4. Create Proxmox API Token

On your Proxmox host (as root):

```bash
# Create role with minimal permissions
pveum role add VigilanceRole -privs "Datastore.Audit Sys.Audit VM.Audit"

# Create user
pveum user add vigilance@pam

# Assign role
pveum acl modify / -user vigilance@pam -role VigilanceRole

# Create token
pveum user token add vigilance@pam vigilance-token --privsep 0
# Note the token ID (vigilance@pam!vigilance-token) and secret
```

Add the token to `.env`:
```bash
VIGILANCE_PROXMOX_TOKEN_ID=vigilance@pam!vigilance-token
VIGILANCE_PROXMOX_TOKEN_SECRET=your-token-secret
```

### 5. Configure Gotify (Optional)

In Gotify Web UI: Apps → Create Application → Name: "Vigilance"
Copy the token to `.env`:
```bash
VIGILANCE_GOTIFY_URL=https://gotify.example.com
VIGILANCE_GOTIFY_TOKEN=your-app-token
```

### 6. Start with Docker Compose

```bash
cd docker
docker compose up -d --build

# Check logs
docker compose logs -f vigilance

# Verify health
curl http://localhost:8000/api/health
```

The docker-compose setup includes:
- `vigilance`: The main application container
- `vigilance-postgres`: PostgreSQL 16 database container

### 7. Access Dashboard

Open http://localhost:8000/ in your browser.

For production, put behind a reverse proxy (nginx, Traefik, Caddy) with authentication (Authelia, Authentik, etc.).

## Configuration

### Environment Variables (`.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `VIGILANCE_DATABASE_URL` | PostgreSQL connection URL | `postgresql+asyncpg://vigilance:vigilance@postgres:5432/vigilance` |
| `VIGILANCE_CONFIG_PATH` | Config YAML path | `/app/data/config.yaml` |
| `VIGILANCE_PROXMOX_URL` | Proxmox API URL | - |
| `VIGILANCE_PROXMOX_TOKEN_ID` | Proxmox API token ID | - |
| `VIGILANCE_PROXMOX_TOKEN_SECRET` | Proxmox API token secret | - |
| `VIGILANCE_PROXMOX_VERIFY_TLS` | Verify TLS certificates | `true` |
| `VIGILANCE_GOTIFY_URL` | Gotify server URL | - |
| `VIGILANCE_GOTIFY_TOKEN` | Gotify application token | - |
| `VIGILANCE_GOTIFY_MIN_SEVERITY` | Minimum severity for notifications | `HIGH` |
| `VIGILANCE_GOTIFY_DIGEST_MODE` | Bundle notifications | `false` |
| `VIGILANCE_AUTH_MODE` | `proxy`, `builtin`, or `both` | `proxy` |
| `VIGILANCE_API_TOKEN` | API token for write access | - |
| `VIGILANCE_REMOTE_USER_HEADER` | Header for reverse proxy auth | `Remote-User` |
| `VIGILANCE_CVE_SYNC_INTERVAL_HOURS` | CVE sync interval | `6` |
| `VIGILANCE_NVD_API_KEY` | NVD API key (optional) | - |
| `VIGILANCE_SCAN_INTERVAL_HOURS` | Discovery scan interval | `24` |
| `VIGILANCE_SSH_TIMEOUT` | SSH command timeout | `30` |
| `VIGILANCE_SSH_PARALLEL_JOBS` | Parallel SSH connections | `10` |
| `VIGILANCE_LOG_LEVEL` | Log level | `INFO` |
| `VIGILANCE_SECRET_KEY` | Secret key for sessions | `change-me` |

### Config YAML (`config.yaml`)

See `config/config.yaml.example` for full configuration including:
- Proxmox nodes with SSH settings
- Discovery settings (Docker, packages, services, custom checks)
- CVE sync sources and intervals
- Notification settings (Gotify, webhooks)
- Scan settings
- Default suppressions

## CLI Commands

```bash
# Test Gotify connection
docker compose exec vigilance python -m vigilance test-gotify

# Trigger manual scan
docker compose exec vigilance python -m vigilance scan-now [--full]

# Sync CVE database
docker compose exec vigilance python -m vigilance sync-cves [--source osv]

# Run database migrations
docker compose exec vigilance python -m vigilance db-upgrade

# Validate configuration
docker compose exec vigilance python -m vigilance config-check

# List configured nodes
docker compose exec vigilance python -m vigilance list-nodes

# API token for write access (shown once)
docker compose exec vigilance vigilance token-rotate

# Show / replace Vigilance's SSH key
docker compose exec vigilance vigilance ssh-key-show
docker compose exec -u vigilance vigilance vigilance ssh-key-rotate
```

## Web UI

- **Übersicht** (`/`): status of scan and CVE sync, what can be fixed now (update vs. remove old packages), host board, top packages, 30-day trend
- **Hosts** (`/hosts`, `/hosts/{id}`): per container the packages to fix with copyable `apt-get` commands, open findings without fix, exceptions, fixed in the last 30 days, scan problems (stopped, no IP, unreachable)
- **Schwachstellen** (`/vulnerabilities`): grouped by package or by CVE, filters (status, fix, severity, host, Debian "unimportant"), search incl. CVE IDs, detail panel with the solution, links and "Ausnahme anlegen"
- **Verwaltung** (`/admin/...`): CVE sources, exceptions, schedule, API token, Gotify, Proxmox/SSH info

Reading needs no login; every change needs the API token ("Bearbeiten" in the header).

### Solutions and removal check

Every finding with a fix shows a solution: an update command, or - for an older version that stayed
installed next to a newer one (e.g. `libapt-pkg6.0` next to `libapt-pkg7.0` after a release upgrade) -
the command to remove it. Such packages are shown by their installed name, with the source package below.

Before suggesting a removal, each scan runs a read-only check on the host
(`vigilance/discovery/removal_check.sh`, nothing is changed):

- `apt-get -s purge <package>`: what apt would remove in addition (dependent packages)
- running processes (same mount namespace, so not Docker containers) that still map a library of the package
- ELF files under `/usr/local` and `/opt` that reference one of its sonames (not managed by dpkg, apt cannot see them)
- `apt-cache policy`: whether the version is still in a package source, i.e. whether the removal can be undone

### Running the fixes (Aktionen)

Vigilance can run the apt commands itself, per container (host detail) or for all containers
(Hosts page). Every run needs the API token and shows a preview first: the commands, what is
skipped and why, and what `apt-get -s` says would change.

- **Vorschläge umsetzen**: targeted `apt-get install --only-upgrade` for packages whose fix is in the
  container's package sources, and `apt-get purge` for obsolete packages whose removal check is "ok".
  Everything else is skipped and listed with the reason.
- **Vollständiges Upgrade**: `apt-get update && apt-get full-upgrade`, non-interactive, existing
  configuration files are kept (`--force-confdef --force-confold`).

Only LXC containers are changed. The Proxmox host and VMs are refused in the code, also when their
ID is sent to the API. One batch runs at a time; output and exit code of every run are kept
(Verwaltung, Aktionen), and a scan starts afterwards. Each scan also records which newer versions the
package sources offer (`apt list --upgradable`, without `apt update`), so a fix that apt cannot
install is shown as such instead of a command that does nothing.

### Packages from vendor repositories

Debian has no advisories for software installed from a vendor's own apt repository (the Debian
tracker marks it NOT-FOR-US). Each scan records where every installed package comes from
(`apt-cache policy`), and the host detail lists packages from non-Debian sources. Some of them are
checked against the Go vulnerability data on OSV instead, by their Go module:

| deb package | Go module |
|---|---|
| `tailscale` | `tailscale.com` |
| `crowdsec` | `github.com/crowdsecurity/crowdsec` |
| `containerd.io` | `github.com/containerd/containerd` (`/v2` for 2.x) |

**Tailscale security bulletins.** Recent Tailscale issues are not in the Go data. If a `tailscale`
package is installed, Vigilance reads https://tailscale.com/security-bulletins/index.xml as its own
source. Versions and platforms are only in the text, so each bulletin is classified: client issue
with a recognised fixed version (becomes an advisory for the `tailscale` package), other product or
no action needed (Kubernetes operator, libtailscale, coordination server, DERP, ...), other platform
only (structured "Affected platforms" line without Linux), or no fixed version recognised. Only the
first kind produces findings; the sources page shows the counts and lists the unrecognised ones.
Platform hints from the text ("on macOS and iOS") appear as "laut Meldung nur macOS".

`docker-ce` is deliberately not mapped: the advisories on `github.com/docker/docker` carry no fixed
version (every release would match), and Docker 29 releases do not map onto the
`github.com/moby/moby/v2` module versions. Operating-system restrictions: reviewed
entries of the Go vulnerability database list the affected systems (`goos`). If that list does
not include linux, the finding gets the status "Anderes OS" (filter on the Schwachstellen page,
fold in the host detail) instead of "open"; a GHSA record inherits this from the GO record of the
same CVE. Many entries lack the field (e.g. unreviewed ones such as GO-2023-1671 for
CVE-2023-28436, FreeBSD only). If only the title or description names another system, Vigilance
shows "laut Meldung nur FreeBSD" with a button to record an exception; it does not hide those
findings by itself.

### Scanning the Proxmox host

The containers are scanned as root. The Proxmox host itself is optional and uses its own
unprivileged user, so Vigilance gets no root access to the host:

```bash
# on the Proxmox host
useradd --system --create-home --home-dir /var/lib/vigilance-scan --shell /bin/sh vigilance-scan
passwd -l vigilance-scan
install -d -m 700 -o vigilance-scan -g vigilance-scan /var/lib/vigilance-scan/.ssh
PUB=$(pct exec <Vigilance-CT> -- docker exec vigilance cat /app/data/ssh/id_rsa.pub)
echo "from=\"<Vigilance-IP>\",restrict $PUB" > /var/lib/vigilance-scan/.ssh/authorized_keys
chown vigilance-scan: /var/lib/vigilance-scan/.ssh/authorized_keys; chmod 600 /var/lib/vigilance-scan/.ssh/authorized_keys
```

and in `config.yaml` under the node's `ssh:` set `scan_host: true` (`host_user` defaults to `vigilance-scan`).
The host appears as "Proxmox-Host". Without root, the removal check cannot see processes of other
users; the UI says so. Packages built by Proxmox (pve-*, proxmox-*) are not in the Debian advisory
data, so findings cover the Debian packages on the host.

Advisories for the same CVE (e.g. `DEBIAN-CVE-2026-1234` and `DSA-6000-1`) are shown and counted as one
vulnerability. An exception for one of them covers all advisories of that CVE.

## Authentication

### Reverse Proxy Auth (Default)

Vigilance reads the `Remote-User` header (configurable) set by your reverse proxy/SSO.
- Read access: Any authenticated user
- Write access: Authenticated users (in proxy mode) or `Authorization: Bearer <API_TOKEN>` header (API token mode)

### Built-in Auth (Optional)

Set `VIGILANCE_AUTH_MODE=builtin` or `both` to enable built-in authentication (planned for future release).

## Development

### Install Dependencies

```bash
pip install -e ".[dev]"
```

### Run Locally

```bash
# Set environment variables
export VIGILANCE_DATABASE_URL=postgresql+asyncpg://vigilance:vigilance@localhost:5432/vigilance
export VIGILANCE_CONFIG_PATH=./config/config.yaml.example
# ... other vars

# Run migrations
alembic upgrade head

# Start server
uvicorn vigilance.main:app --reload --host 0.0.0.0 --port 8000
```

Note: Requires PostgreSQL to be running locally or via Docker.

### Run Tests

```bash
pytest tests/
```

### Code Quality

```bash
ruff check .
ruff format .
mypy vigilance/
```

## Project Structure

```
vigilance/
├── ansible/                # Ansible playbooks for SSH key distribution
├── config/                 # Configuration files
├── docker/                 # Docker files (Dockerfile, docker-compose.yml)
├── vigilance/              # Python package
│   ├── api/                # FastAPI routes
│   ├── cli/                # CLI commands
│   ├── core/               # Core services (auth, scheduler, notifications)
│   ├── database/           # SQLAlchemy models, migrations, CRUD
│   ├── discovery/          # Proxmox, SSH, Docker, package, service discovery
│   ├── cve/                # CVE sync, matching, sources (OSV, GHSA, NVD, Debian, Ubuntu)
│   └── web/                # Jinja2 templates, static assets
├── tests/                  # Unit and integration tests
├── .env.example            # Example environment variables
├── config.yaml.example     # Example config YAML
├── docker-compose.yml      # Docker Compose (symlink to docker/docker-compose.yml)
├── pyproject.toml          # Python project config
└── README.md               # This file
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## Support

For issues and feature requests, please use the GitHub issue tracker.
