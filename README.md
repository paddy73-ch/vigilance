# Vigilance

Self-hosted security and patch monitoring for a Proxmox VE homelab.

Vigilance takes the inventory of a Proxmox node over its API, reads the installed packages of every
running LXC container (through the Proxmox host with `pct exec`, or by SSH), of the VMs you switch on and,
optionally, of the Proxmox host itself. It matches them against security advisories and shows per host
what to update, remove or tidy up. It can run the fixes itself, with a simulated preview and a snapshot
first, and notify you of new findings via Gotify.

The web UI is in German; this README and the code are in English.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/overview-dark.png">
  <img src="docs/images/overview-light.png" alt="Übersicht: 149 offene Befunde lassen sich jetzt beheben, davon 93 kritisch oder hoch; Hosts mit Ampelfarben" width="100%">
</picture>

<sub>Screenshots from a demo copy of a homelab: names and addresses changed, findings real.</sub>

## Features

- **Inventory** of nodes, LXC containers and VMs via the Proxmox VE API, including stopped ones. Guests
  deleted in Proxmox disappear on the next scan. Windows and Home Assistant OS VMs are recognised and
  marked as not scannable.
- **Package scan** through the Proxmox host (`pct exec`, no key or IP needed in the containers) or by SSH,
  several hosts at a time: dpkg, apk and rpm packages; optionally Docker images, systemd services and
  custom checks (`config.yaml`, `discovery:`).
- **Advisory sources**: OSV.dev (Debian, Ubuntu, Alpine, Go modules), GitHub Security Advisories, the
  Tailscale security bulletins; optionally NVD, the Debian and the Ubuntu security trackers. Each source
  can be switched on and off in the UI.
- **Version comparison** by the rules of each ecosystem (dpkg, SemVer, Docker tags).
- **Per host what to do**: update commands for fixes that are in the host's package sources, removal of
  old packages left over from a release upgrade (with a read-only removal check), kernel packages in
  containers, headers of kernels that are gone, compilers you no longer need (Vigilance asks), packages
  from vendor repositories. Kernel CVEs on hosts that only have kernel headers count as not affected.
- **Actions**: run the suggested commands or a full upgrade from the UI, on one host or on all
  containers and VMs, with an `apt-get -s` preview, a snapshot of each container or VM first, parallel
  runs and a log.
- **Exceptions** per host or everywhere, with a reason and an optional expiry. Advisories for the same
  CVE (e.g. `DEBIAN-CVE-…` and `DSA-…`) count as one vulnerability.
- **Schedule**: scan and advisory sync every N hours or at fixed times of day (set on an analogue clock),
  the sync optionally right after each scan.
- **Gotify notifications** for new findings, single or as a digest.
- **Web UI**: Jinja2 + Alpine.js, own CSS, no external resources (strict Content-Security-Policy),
  light/dark, usable on a phone.
- **Docker Compose** deployment with PostgreSQL 16.

## Architecture

```
┌──────────────────┐ API, SSH ┌──────────────────┐  HTTPS  ┌──────────────────┐
│ Proxmox VE node  │◀─────────│    Vigilance     │────────▶│ Advisory sources │
│ (vigilance-scan) │          │    (FastAPI)     │         │ OSV, GHSA,       │
└────────┬─────────┘          └───┬─────────┬────┘         │ Tailscale, (NVD, │
         │ pct exec               │ SSH     │              │ Debian, Ubuntu)  │
┌────────▼─────────┐   ┌──────────▼───────┐ │              └──────────────────┘
│ LXC containers   │   │ VMs (and         │ ▼
│                  │   │ containers, ssh) │ ┌──────────────────┐ ┌──────────────┐
└──────────────────┘   └──────────────────┘ │   PostgreSQL     │ │    Gotify    │
                                            └──────────────────┘ └──────────────┘
```

## Quick start

### 1. Clone and configure

```bash
git clone https://github.com/paddy73-ch/vigilance.git
cd vigilance
cp .env.example .env
# edit .env: at least VIGILANCE_PROXMOX_URL, _TOKEN_ID, _TOKEN_SECRET
```

### 2. Proxmox API token

On the Proxmox host as root:

```bash
pveum role add VigilanceRole -privs "VM.Audit,VM.GuestAgent.Audit,VM.Snapshot"
pveum user add vigilance@pam
pveum acl modify / -role VigilanceRole -user vigilance@pam
pveum user token add vigilance@pam vigilance --privsep 1
pveum acl modify / -role VigilanceRole -token 'vigilance@pam!vigilance'
```

Put the token ID (`vigilance@pam!vigilance`) and the secret into `.env`. What the rights are for:

- `VM.Audit`: list containers and VMs with their configuration (required).
- `VM.GuestAgent.Audit` (Proxmox VE 9): read-only calls to the QEMU guest agent, for the IPs of VMs and to
  recognise Home Assistant OS. Optional.
- `VM.Snapshot`: a snapshot right before "Vorschläge umsetzen" and the other actions change a container
  or VM (switch "Vorher Snapshot anlegen" in the dialog, on by default). Vigilance keeps one snapshot
  `vigilance-JJJJMMTT-HHMMSS` per guest, deletes its older ones and never touches others; it cannot roll
  back. Without the right the snapshot fails and the host is left unchanged, unless the switch is off.
  Containers with mount points on storage without snapshot support cannot be snapshotted.

### 3. Start

```bash
cd docker
docker compose up -d --build
docker compose logs -f vigilance
curl http://localhost:8000/api/health
```

On the first start the container creates `/app/data/config.yaml` from
`config/config.yaml.example` and an ed25519 SSH key pair for this installation in `/app/data/ssh/`
(a Docker volume). Nothing secret is stored in the image or the repository.

### 4. Let Vigilance into the containers

There are two ways, set per node in Verwaltung › Einstellungen › Proxmox und SSH ("Zugang zu den
Containern") or with `container_access: pct | ssh` on the node in `config.yaml`; the UI wins.

**Through the Proxmox host (`pct`, default).** Vigilance logs in to the host as the unprivileged user
`vigilance-scan` and runs `sudo pct exec <id> -- …`. The containers need no key, no sshd and no known
IP. Up to `discovery.ssh.parallel_jobs` hosts (UI: "Parallele SSH-Verbindungen", default 10) are read at
the same time, at most 8 containers per node over one SSH connection (sshd allows 10 sessions per
connection by default). Each `pct exec` takes about half a
second to start. On the Proxmox host:

```bash
useradd --system --create-home --home-dir /var/lib/vigilance-scan --shell /bin/sh vigilance-scan
passwd -l vigilance-scan
install -d -m 700 -o vigilance-scan -g vigilance-scan /var/lib/vigilance-scan/.ssh
PUB='ssh-ed25519 AAAA… vigilance@…'        # from: vigilance ssh-key-show
echo "from=\"<Vigilance-IP>\",restrict $PUB" > /var/lib/vigilance-scan/.ssh/authorized_keys
chown vigilance-scan: /var/lib/vigilance-scan/.ssh/authorized_keys
chmod 600 /var/lib/vigilance-scan/.ssh/authorized_keys
echo 'vigilance-scan ALL=(root) NOPASSWD: /usr/sbin/pct exec [0-9]* -- *' > /tmp/vp
visudo -cf /tmp/vp && install -o root -g root -m 0440 /tmp/vp /etc/sudoers.d/vigilance-pct && rm /tmp/vp
```

The rule allows `pct exec` and nothing else of `pct` (no `stop`, `destroy`, `set`, …). It makes Vigilance
root in every container of the node, which is what the key in each container gives it with SSH too. In an
unprivileged container, root is an unprivileged user on the host; in a privileged one it is much closer
to root on the host. Without the rule each container shows "sudo-Regel für pct exec fehlt".

**Directly by SSH (`ssh`).** Vigilance connects to every container's IP as root with its own key.
Installations from before 0.18.0 keep this way until it is switched. Show the public key and put it into
`/root/.ssh/authorized_keys` of each running container, for example with the script in this repository
(run it on the Proxmox host):

```bash
docker compose exec -u vigilance vigilance vigilance ssh-key-show
sh scripts/distribute-ssh-key.sh 'ssh-ed25519 AAAA… vigilance@…'
```

Host keys are checked against `/app/data/ssh/known_hosts`, and unknown hosts are refused
(`discovery.ssh.strict_host_key_checking: true` in `config.yaml`). Add the containers' host keys once:

```bash
docker compose exec -u vigilance vigilance \
  sh -c 'ssh-keyscan -t ed25519 192.0.2.101 192.0.2.102 >> /app/data/ssh/known_hosts'
```

Setting the option to `false` accepts and stores unknown host keys on first contact instead, which is
simpler but does not detect a changed host.

### 5. Enable changes

Reading needs no login. Every change (exceptions, settings, actions) needs an API token:

```bash
docker compose exec -u vigilance vigilance vigilance token-rotate
```

The token is shown once; enter it in the UI with "Bearbeiten" in the header.

### 6. Put it behind HTTPS

Open http://localhost:8000/ to try it. For regular use put Vigilance behind a reverse proxy with TLS
and allow access to port 8000 only from that proxy: anyone who reaches the UI can read all hosts,
packages and vulnerabilities, and the API token must not travel in clear text. If the proxy
authenticates users and sets `Remote-User`, list its address in `VIGILANCE_TRUSTED_PROXIES`; that
header is ignored from any other address.

### 7. Gotify (optional)

In Gotify create an application for Vigilance. Enter the server address and the app token in the UI
under Verwaltung › Einstellungen › Benachrichtigungen (stored in the database, takes precedence over
`.env`; the token is never shown again), or set `VIGILANCE_GOTIFY_URL` and `VIGILANCE_GOTIFY_TOKEN`
in `.env`. Set `VIGILANCE_PUBLIC_URL` to get a link to the host in each message.

## Configuration

### Environment variables (`.env`)

| Variable | Description | Default |
|---|---|---|
| `VIGILANCE_DATABASE_URL` | Database URL | set in `.env.example` for the compose setup |
| `VIGILANCE_CONFIG_PATH` | Path of `config.yaml` | `/app/data/config.yaml` |
| `VIGILANCE_PROXMOX_URL` | Proxmox API URL, e.g. `https://192.0.2.49:8006` | – |
| `VIGILANCE_PROXMOX_TOKEN_ID` | Proxmox API token ID | – |
| `VIGILANCE_PROXMOX_TOKEN_SECRET` | Proxmox API token secret | – |
| `VIGILANCE_PROXMOX_VERIFY_TLS` | Verify the Proxmox TLS certificate | `true` |
| `VIGILANCE_API_TOKEN` | Write token until one is created with `token-rotate` | – |
| `VIGILANCE_TRUSTED_PROXIES` | IPs/CIDRs whose `Remote-User` header is trusted | – |
| `VIGILANCE_REMOTE_USER_HEADER` | Name of that header | `Remote-User` |
| `VIGILANCE_AUTH_MODE` | `proxy` (header + token); `builtin` is not implemented | `proxy` |
| `VIGILANCE_PUBLIC_URL` | Address of the UI as a browser sees it, for links in notifications | – |
| `VIGILANCE_GOTIFY_URL` | Gotify server URL | – |
| `VIGILANCE_GOTIFY_TOKEN` | Gotify application token | – |
| `VIGILANCE_GOTIFY_MIN_SEVERITY` | Lowest severity that is notified | `HIGH` |
| `VIGILANCE_GOTIFY_DIGEST_MODE` | One digest instead of single messages | `false` |
| `VIGILANCE_CVE_SYNC_INTERVAL_HOURS` | Advisory sync interval | `6` |
| `VIGILANCE_SCAN_INTERVAL_HOURS` | Scan interval | `24` |
| `VIGILANCE_NVD_API_KEY` | NVD API key (only if NVD is switched on) | – |
| `VIGILANCE_GITHUB_TOKEN` | GitHub token for GHSA (higher rate limit) | – |
| `VIGILANCE_SSH_TIMEOUT` | SSH timeout in seconds | `30` |
| `VIGILANCE_SSH_PARALLEL_JOBS` | Hosts scanned at the same time (via `pct`: at most 8 per node) | `10` |
| `VIGILANCE_LOG_LEVEL` | Log level | `INFO` |

Gotify settings and source switches saved in the UI take precedence over these values. The clock next
to "Scan alle … Stunden" and "CVE-Abgleich alle … Stunden" (Verwaltung › Einstellungen) sets fixed times
of day instead, optionally only on some weekdays, in the browser's time zone; those take precedence over
the intervals. For the CVE sync the clock also offers "Nach Scan": the sync then has no runs of its own
and only runs right after each scan (scheduled or started by hand), as part of the scan pipeline.

### `config.yaml`

`config/config.yaml.example` documents all options: Proxmox nodes with their SSH settings, VMs to scan,
scanning the Proxmox host, discovery (packages, Docker, services, custom checks), advisory sources,
notifications and scan schedule. The file lives in the data volume; edit it there, e.g.

```bash
docker compose cp vigilance:/app/data/config.yaml .
# edit, then
docker compose cp config.yaml vigilance:/app/data/config.yaml && docker compose restart vigilance
```

## CLI

Run inside the container as the `vigilance` user:

```bash
docker compose exec -u vigilance vigilance vigilance <command>
```

| Command | Purpose |
|---|---|
| `scan-now [--full]` | Scan now and match the result; exits with 1 if the scan fails |
| `sync-cves [--source osv]` | Sync advisories now |
| `test-gotify` | Send a test notification |
| `config-check` | Validate the configuration |
| `list-nodes` | Show the configured Proxmox nodes |
| `db-upgrade` | Run database migrations (also done on start) |
| `token-rotate` | Create a new API token for write access (shown once) |
| `ssh-key-show` | Show Vigilance's public SSH key |
| `ssh-key-rotate` | Create a new SSH key; the old one is kept as `id_rsa.old-<time>` |
| `version` | Show the version |

## Web UI

- **Übersicht** (`/`): status of scan and sync, what can be fixed now, a card per host, containers with
  superfluous kernel packages, packages to look at first, 30-day trend. The bar on a host card shows the
  fixable findings by severity, or green if there is nothing to fix; a violet fifth at its end means
  something to tidy up (old kernel headers, kernel packages in a container, compilers whose question is
  open or answered with "no"), named in the line below.
- **Hosts** (`/hosts`, `/hosts/{id}`): the list is sortable by its columns and groups running hosts,
  "Läuft, nicht gescannt" and "Gestoppt"; a right click (or ⋯) on a VM switches its scan on or off. Per
  container, VM or Proxmox host: the packages to fix with the commands, findings without a fix,
  findings that do not apply ("Nicht betroffen"), packages from other sources, compilers and old kernel
  headers, exceptions, scan problems; buttons for the actions.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/host-dark.png">
  <img src="docs/images/host-light.png" alt="Host docker-all: Befehle für Updates und zum Entfernen alter Pakete, Prüfung „unbedenklich“, Pakete mit Schwere und Anzahl Lücken" width="100%">
</picture>

- **Schwachstellen** (`/vulnerabilities`): by package or by vulnerability, filters (status, fix,
  severity, host), search incl. CVE IDs, detail panel with the solution and "Ausnahme anlegen".

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/cves-dark.png">
  <img src="docs/images/cves-light.png" alt="Schwachstellen nach CVE: offene Lücken mit Fix, sortiert nach Schwere und CVSS, mit Paket, Anzahl Hosts und Fix-Version" width="100%">
</picture>

- **Verwaltung** (`/admin/…`): Quellen (sources on/off), Ausnahmen, Aktionen (log), Einstellungen
  (schedule with the clock, API token, Gotify, access to the containers, SSH key) and Grenzen
  (limitations). „Behoben in 7 Tagen“ on the overview opens a log of all fixes.

## How it works

### Solutions and removal check

Every finding with a fix shows a solution: an update command, or – for an older version that stayed
installed next to a newer one (e.g. `libapt-pkg6.0` next to `libapt-pkg7.0` after a release upgrade) –
the command to remove it. An update is only suggested if the host's package sources offer a version at
or above the fix (`apt list --upgradable`, without `apt update`); the age of the package lists is shown.

Before suggesting a removal, each scan runs a read-only check on the host
(`vigilance/discovery/removal_check.sh`, nothing is changed):

- `apt-get -s purge <package>`: what apt would remove in addition
- running processes that still map a library of the package (same mount namespace, so not Docker
  containers)
- ELF files under `/usr/local` and `/opt` that reference one of its sonames
- `apt-cache policy`: whether the version is still in a package source, i.e. whether the removal can be
  undone

### Actions

Every run needs the API token and shows a preview first: the commands, what is skipped and why, and
what `apt-get -s` says would change.

- **Vorschläge umsetzen**: `apt-get install --only-upgrade` for packages whose fix is in the host's
  package sources, `apt-get purge` for old packages whose removal check is "ok", the kernel cleanup if
  nothing else would be removed, headers of kernels that are gone, and compilers answered with "no".
- **Vollständiges Upgrade**: `apt-get update && apt-get full-upgrade` (`dist-upgrade` on the Proxmox
  host), non-interactive, existing configuration files are kept.
- **Kernel aufräumen** (containers only): a container always runs the host's kernel, so kernel
  packages in it are never loaded. They come in e.g. with the `wireguard` meta package.

Containers (through `pct exec` or by SSH) and VMs switched on for scanning are changed as root. "All" on
the Hosts page means all running containers and those VMs, never the Proxmox host. With "Vorher Snapshot
anlegen" (on by default) each container or VM gets a snapshot right before its commands run; if that
fails, the host is left unchanged (see the token rights in step 2). Up to 4 hosts run in parallel; a host
with `apt-cacher-ng` runs first and alone, because the others may download through it. Output, exit code
and snapshot name of every run are kept, and a scan starts afterwards. Vigilance never reboots anything
and never rolls back a snapshot; that is done in Proxmox.

### VMs

Every VM appears in the host list. Running VMs that are not scanned are grouped as "Läuft, nicht
gescannt". Switch scanning on with a right click on the row (or its ⋯ button) › "Für den Scan
aktivieren …", optionally with an IP; a scan starts right away. That choice is stored in the database
and takes precedence over `config.yaml`, where VMs can also be listed under the node. Scanned VMs are
handled like containers, but always by SSH as root with Vigilance's key (there is no `pct exec` for VMs),
apt only. Windows and Home Assistant OS are
not supported and cannot be switched on; they get an (i) with the reason. Windows is recognised by the
VM's OS type. Home Assistant OS has the generic type "l26", so Vigilance asks the QEMU guest agent of a
running VM (token right `VM.GuestAgent.Audit`) and otherwise looks for "haos" or "Home Assistant OS" in
the name or description:

```yaml
proxmox:
  nodes:
    - name: pve
      vms:
        - 201                           # IP from the QEMU guest agent
        - {vmid: 202, ip: 192.0.2.202}  # fixed IP
```

Put Vigilance's public key into `/root/.ssh/authorized_keys` of the VM. For the guest agent the token
needs `VM.GuestAgent.Audit` (see Quick start).

### The Proxmox host

Scanning the host is optional and uses the unprivileged user `vigilance-scan` (created as in step 4, the
`useradd` … `chmod 600` lines), so the scan itself gets no root access.

Then set `scan_host: true` under the node's `ssh:` in `config.yaml` (`host_user` defaults to
`vigilance-scan`). The host appears as "Proxmox-Host". Without root, the removal check cannot see
processes of other users; the UI says so. Packages built by Proxmox (`pve-*`, `proxmox-*`) are not in
the Debian advisory data, so findings cover the Debian packages on the host.

To let Vigilance run apt on the host too (host detail › "Vorschläge umsetzen" / "dist-upgrade", always
alone and with an explicit confirmation), add a sudo rule. sudo for apt-get is effectively root:
apt-get options can run arbitrary commands.

```bash
visudo -f /etc/sudoers.d/vigilance-scan
# content:
Defaults:vigilance-scan env_keep += "DEBIAN_FRONTEND NEEDRESTART_MODE NEEDRESTART_SUSPEND APT_LISTCHANGES_FRONTEND LC_ALL"
vigilance-scan ALL=(root) NOPASSWD: /usr/bin/apt-get
```

Without it the preview says that the rule is missing and nothing runs. On the host, apt runs detached
(nohup) and Vigilance polls for the result, so a dropped SSH connection does not interrupt it.

### Let Vigilance put its key into new containers

Only for nodes whose containers are reached directly by SSH. With the switch "Schlüssel in neue
Container selbst eintragen" (Verwaltung › Einstellungen › Proxmox und SSH; off by default), a running
container that rejects Vigilance's key gets it from the Proxmox host
during the scan, and the scan goes on. The host runs only `scripts/vigilance-install-key`, which has the
public key built in, through its own sudo rule for `vigilance-scan`. VMs are left out. On pve:

```bash
PUB='ssh-ed25519 AAAA… vigilance@…'   # from: vigilance ssh-key-show
sed "s|__VIGILANCE_PUBLIC_KEY__|$PUB|" scripts/vigilance-install-key > /tmp/vik
install -o root -g root -m 0755 /tmp/vik /usr/local/sbin/vigilance-install-key && rm /tmp/vik
echo 'vigilance-scan ALL=(root) NOPASSWD: /usr/local/sbin/vigilance-install-key' > /tmp/vk
visudo -cf /tmp/vk && install -o root -g root -m 0440 /tmp/vk /etc/sudoers.d/vigilance-keys && rm /tmp/vk
```

If Vigilance gets a new key pair, install the script again with the new key.

### Compilers and old kernel headers

The scan also looks for compilers and build tools (`build-essential`, `gcc`, `g++`, `clang`, `dkms`).
They are no standard part of Proxmox or of a container template, but Vigilance cannot tell whether
something is compiled on the host or whether DKMS modules must be rebuilt after a kernel update. The host
page therefore asks "Werden diese Werkzeuge noch gebraucht?" and shows the DKMS modules. Only after "Nein"
do they go into "Vorschläge umsetzen", with `purge --autoremove`. Unrelated packages that autoremove would
take along only because they are marked as automatically installed are kept with apt's `name+` syntax,
which also marks them as manually installed (on pve that was `sudo`). It is one apt-get command, so the
preview simulates it and the sudo rule for apt-get covers it on the Proxmox host. If something depends on
the tools, nothing is suggested and the host page says why. Header packages of kernels that are no longer
installed (`proxmox-headers-6.2…` after the move to 7.0) are always suggested. The answer is stored per
host and can be reset.

### Packages from vendor repositories

Debian has no advisories for software installed from a vendor's own apt repository. Each scan records
where every installed package comes from (`apt-cache policy`), and the host detail lists packages from
other sources as "Geprüft" (checked another way), "Nur Debian-Daten" or "Keine Sicherheitsdaten". Some
are checked against the Go vulnerability data on OSV by their Go module:

| deb package | Go module |
|---|---|
| `tailscale` | `tailscale.com` |
| `crowdsec` | `github.com/crowdsecurity/crowdsec` |
| `containerd.io` | `github.com/containerd/containerd` (`/v2` for 2.x) |

`docker-ce` is deliberately not mapped: the advisories on `github.com/docker/docker` carry no fixed
version, and Docker 29 releases do not map onto the `github.com/moby/moby/v2` module versions.

**Tailscale security bulletins.** Recent Tailscale issues are not in the Go data. If `tailscale` is
installed, Vigilance reads https://tailscale.com/security-bulletins/index.xml. Versions and platforms
are only in the text, so each bulletin is classified; only client issues with a recognised fixed
version become findings. The sources page shows the counts and lists the unrecognised ones.

**Operating systems.** Reviewed entries of the Go vulnerability database list the affected systems
(`goos`). If that list does not include Linux, the finding gets the status "Nicht betroffen" instead of
"open". The same happens to kernel CVEs on hosts where the only packages built from Debian's kernel
source `linux` are header or build files (`linux-libc-dev`, `linux-headers-*`, `linux-kbuild-*`): they
contain no kernel. If only the text names another system, Vigilance shows a hint ("laut Meldung nur
FreeBSD") but does not hide the finding by itself.

### Limitations

What Vigilance does not see, or only judges roughly, is described in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) (German). The same text is shown in the UI under
Verwaltung › Grenzen; findings from less precise sources carry an (i) with the specific limitation.

## Development

```bash
pip install -e ".[dev]"

export VIGILANCE_DATABASE_URL=postgresql+asyncpg://vigilance:vigilance@localhost:5432/vigilance
export VIGILANCE_CONFIG_PATH=./config/config.yaml.example
alembic upgrade head
uvicorn vigilance.main:app --reload --port 8000
```

### Tests

```bash
python -m pytest tests/unit                       # SQLite
VIGILANCE_TEST_PG_URL=postgresql+asyncpg://vigilance:vigilance@localhost/vigilance_test \
  python -m pytest tests/unit                     # SQLite and PostgreSQL
VIGILANCE_E2E=1 VIGILANCE_E2E_CHROME=/usr/bin/google-chrome \
  python -m pytest tests/e2e                      # browser tests (needs playwright and Chrome)
```

Use `python -m pytest` (not `pytest`), so the project directory is on the import path. GitHub Actions
runs all three on every pull request and on pushes to `main`.

`ruff` and `mypy` are configured in `pyproject.toml`, but the code base is not lint-clean yet and CI
does not run them.

### Deploy with deploy.sh

`deploy.sh` copies the current commit to a Proxmox host and rebuilds the container there. The target
comes from `~/.config/vigilance/deploy.env` (or the environment), not from the repository:

```bash
PROXMOX_HOST=192.0.2.49   # Proxmox host, reachable as root via SSH
CONTAINER_ID=123          # LXC running Vigilance
```

## Project structure

```
vigilance/
├── .github/workflows/      # CI: tests
├── config/                 # config.yaml.example, logging
├── docker/                 # Dockerfile, docker-compose.yml, entrypoint
├── docs/                   # LIMITATIONS.md (shown in the UI), images/ (README screenshots)
├── scripts/                # distribute-ssh-key.sh, vigilance-install-key
├── tests/                  # unit and browser tests
├── vigilance/              # Python package
│   ├── actions/            # running fixes (preview, batches, log, snapshots)
│   ├── api/                # FastAPI routes
│   ├── cli/                # command line
│   ├── core/               # auth, scheduler and schedule, notifications, settings from the UI
│   ├── cve/                # advisory sources, matching, version comparison
│   ├── database/           # SQLAlchemy models, migrations, CRUD
│   ├── discovery/          # Proxmox API, SSH and pct access, packages, removal and build-tool checks
│   └── web/                # templates, CSS, JavaScript
├── CHANGELOG.md
├── deploy.sh
└── pyproject.toml
```

## License

No license has been chosen yet. Until there is one, the usual copyright applies: you may read the code
and fork it on GitHub, but not use, modify or redistribute it.

## Contributing and support

Questions, bugs and ideas: please open an issue. Pull requests are welcome once a license is in place;
please run the tests before opening one.
