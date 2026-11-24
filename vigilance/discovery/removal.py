"""Read-only check of what removing obsolete packages would affect.

After a Debian release upgrade, libraries of the old release often stay installed next to
their successors (libapt-pkg6.0 next to libapt-pkg7.0). Vigilance suggests removing them.
Before the user does that, the scan collects per package on the host:

* what `apt-get -s purge <package>` would remove (simulation only),
* running processes that still have a library of the package mapped,
* ELF files under /usr/local and /opt (not managed by dpkg) that reference one of its sonames,
* whether the installed version is still in a package source (otherwise it cannot be reinstalled).

The shell part lives in removal_check.sh; nothing is changed on the host.
"""

import json
import logging
import re
import shlex
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from vigilance.cve.matcher import compare_debian_versions
from vigilance.discovery.packages import PackageInfo
from vigilance.discovery.ssh import get_ssh_pool

logger = logging.getLogger(__name__)

SCRIPT = (Path(__file__).parent / "removal_check.sh").read_text()
_PKG_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]+(:[a-z0-9]+)?$")
CHECK_TIMEOUT = 120


def _newest(versions: Iterable[str]) -> Optional[str]:
    best = None
    for v in versions:
        try:
            if best is None or compare_debian_versions(v, best) > 0:
                best = v
        except ValueError:
            best = best or v
    return best


def obsolete_binaries(packages: List[PackageInfo]) -> List[str]:
    """Binary packages whose source package is also installed in a newer version.

    Same rule as the UI (views.obsolete_keys): per source package, every version but
    the newest is obsolete.
    """
    by_source: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    for p in packages:
        if p.manager != "dpkg" or not p.source_version:
            continue
        by_source[p.source_name][p.source_version].append(p.name)
    result = []
    for versions in by_source.values():
        if len(versions) < 2:
            continue
        newest = _newest(versions)
        for ver, names in versions.items():
            if ver != newest:
                result.extend(names)
    return sorted(set(n for n in result if _PKG_NAME_RE.match(n)))


def parse_header(output: str) -> dict:
    """Host-wide facts printed before the first package: run as root? running kernel."""
    header = {"root": True, "kernel": None}
    for line in output.splitlines():
        if line.startswith("##PKG "):
            break
        if line.strip() == "##NOROOT":
            header["root"] = False
        elif line.startswith("##KERNEL "):
            header["kernel"] = line[9:].strip() or None
    return header


def parse_check_output(output: str, packages: List[str]) -> Dict[str, dict]:
    """Parse removal_check.sh output into {package: {would_remove, in_use, external, error}}."""
    def empty():
        return {"would_remove": [], "in_use": [], "external": [], "error": None, "reinstallable": None, "libraries": None}
    result = {p: empty() for p in packages}
    current = None
    for line in output.splitlines():
        if line.startswith("##PKG "):
            current = result.setdefault(line[6:].strip(), empty())
        elif current is None:
            continue
        elif line.startswith("##SIM "):
            parts = line.split()
            if len(parts) >= 3 and parts[2] not in current["would_remove"]:
                current["would_remove"].append(parts[2])
        elif line.startswith("##SIMERR"):
            current["error"] = line[8:].strip() or "Simulation fehlgeschlagen"
        elif line.startswith("##USE "):
            pid, _, cmd = line[6:].strip().partition(" ")
            if pid.isdigit():
                current["in_use"].append({"pid": int(pid), "command": cmd.strip()})
        elif line.startswith("##EXT "):
            current["external"].append(line[6:].strip())
        elif line.startswith("##LIBS "):
            n = line[7:].strip()
            current["libraries"] = int(n) if n.isdigit() else None
        elif line.startswith("##AVAIL "):
            current["reinstallable"] = line[8:].strip() == "yes"
    return result


async def check_removal(host: str, port: int, user: str, key_path: str, known_hosts: str,
                        packages: List[str]) -> dict:
    """Run the check on one host. Returns the JSON-serialisable result stored on the inventory."""
    checked_at = datetime.utcnow().isoformat() + "Z"
    if not packages:
        return {"checked_at": checked_at, "packages": {}}
    pool = get_ssh_pool()
    client = pool.get_client(host, port, user, key_path, known_hosts, CHECK_TIMEOUT)
    # The script is passed inline as a heredoc, so nothing is written to the host
    command = f"sh -s -- {' '.join(shlex.quote(p) for p in packages)} <<'VIGILANCE_EOF'\n{SCRIPT}\nVIGILANCE_EOF"
    res = client.run_command(command, timeout=CHECK_TIMEOUT)
    if not res.stdout and not res.success:
        logger.warning("Removal check on %s failed: %s", host, res.stderr)
        return {"checked_at": checked_at, "packages": {}, "error": (res.stderr or "Prüfung fehlgeschlagen")[:300]}
    return {"checked_at": checked_at, **parse_header(res.stdout), "packages": parse_check_output(res.stdout, packages)}


def dumps(result: dict) -> str:
    return json.dumps(result, separators=(",", ":"))


# ---------------------------------------------------------------- upgrade availability
#
# Which newer versions the host's configured package sources offer. Uses the package lists
# as they are (no `apt update`, nothing is changed); their age is reported with the result.
UPGRADE_SCRIPT = r"""LC_ALL=C; export LC_ALL
# Age of the package lists: apt rebuilds pkgcache.bin after `apt update`. (The *Release files
# keep the server's timestamp and say nothing about when the lists were fetched.)
for f in /var/cache/apt/pkgcache.bin /var/lib/apt/lists; do
  [ -e "$f" ] && { echo "##LISTS $(stat -c %Y "$f")"; break; }
done
apt list --upgradable 2>/dev/null | awk '/upgradable from/ { split($1, a, "/"); print "##UPG " a[1] " " $2 }'
# Where each installed version comes from (package sources listed under *** in apt-cache policy),
# and whether Debian/Ubuntu also offer the package (any version from a debian.org/ubuntu.com source)
apt-cache policy $(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 ~ /^[ih]i/ {print $2}') 2>/dev/null | awk '
  /^[^ ].*:$/ { pkg = substr($0, 1, length($0) - 1); inst = 0; distro = 0; next }
  /^        -?[0-9]+ / && $2 ~ /(debian\.org|ubuntu\.com)/ && !distro { print "##DISTRO " pkg; distro = 1 }
  /^ \*\*\* / { inst = 1; next }
  inst && /^        -?[0-9]+ / { if ($2 != "/var/lib/dpkg/status") print "##ORIGIN " pkg " " $2; next }
  inst && /^     [^ ]/ { inst = 0 }'
"""


def parse_upgrade_output(output: str) -> dict:
    lists_at = None
    candidates = {}
    origins: dict = {}
    distro = set()
    for line in output.splitlines():
        if line.startswith("##LISTS "):
            ts = line[8:].strip()
            if ts.isdigit():
                lists_at = datetime.utcfromtimestamp(int(ts)).isoformat() + "Z"
        elif line.startswith("##UPG "):
            parts = line.split()
            if len(parts) >= 3:
                candidates[parts[1]] = parts[2]
        elif line.startswith("##DISTRO "):
            distro.add(line[9:].strip())
        elif line.startswith("##ORIGIN "):
            parts = line.split()
            if len(parts) >= 3 and parts[2] not in origins.setdefault(parts[1], []):
                origins[parts[1]].append(parts[2])
    # Only kept for packages installed from somewhere else (e.g. Proxmox builds of Debian packages)
    return {"lists_at": lists_at, "candidates": candidates, "origins": origins,
            "distro_also": sorted(p for p in distro if p in origins
                                  and not any(re.search(r"(debian\.org|ubuntu\.com)", u) for u in origins[p]))}


async def check_upgrades(host: str, port: int, user: str, key_path: str, known_hosts: str) -> Optional[dict]:
    pool = get_ssh_pool()
    client = pool.get_client(host, port, user, key_path, known_hosts, CHECK_TIMEOUT)
    res = client.run_command(f"sh -s <<'VIGILANCE_EOF'\n{UPGRADE_SCRIPT}\nVIGILANCE_EOF", timeout=CHECK_TIMEOUT)
    if not res.stdout and not res.success:
        logger.warning("Upgrade check on %s failed: %s", host, res.stderr)
        return None
    return {"checked_at": datetime.utcnow().isoformat() + "Z", **parse_upgrade_output(res.stdout)}


# ---------------------------------------------------------------- kernel packages in containers
#
# An LXC container always runs the host's kernel; kernel images installed inside are never
# loaded (they usually arrive as a dependency, e.g. the "wireguard" package pulls in a kernel
# that provides wireguard-modules). The check lists them (installed and "rc" remnants) and
# simulates removing them together with what then becomes unused (purge --autoremove).
KERNEL_SCRIPT = r"""LC_ALL=C; export LC_ALL
pk=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image*' 'linux-headers*' 'linux-modules*' 2>/dev/null | awk '$1 ~ /^(ii|hi|rc|iU|iF|hU|hF)/ {print $1 " " $2}')
[ -n "$pk" ] || exit 0
echo "##KERNEL $(uname -r)"
printf '%s\n' "$pk" | while read -r s n; do echo "##KPKG $s $n"; done
names=$(printf '%s\n' "$pk" | awk '{print $2}' | tr '\n' ' ')
apt-get -s -o Debug::NoLocking=1 -o Dir::Log::Planner=/dev/null --autoremove purge $names 2>&1 \
  | awk '/^(Purg|Remv) / {print "##KSIM " $2} /^E:/ {print "##KERR " $0}'
"""
# What removing kernels may take along without that being a surprise
KERNEL_RELATED = re.compile(
    r"^(linux-(image|headers|modules|kbuild|compiler|support|base)|firmware-|initramfs-tools|klibc-utils|libklibc"
    r"|dracut|amd64-microcode|intel-microcode|busybox$)"  # busybox: pulled in by initramfs-tools
)


def parse_kernel_output(output: str) -> Optional[dict]:
    packages, would_remove, error, running = [], [], None, None
    for line in output.splitlines():
        if line.startswith("##KPKG "):
            parts = line.split()
            if len(parts) >= 3:
                packages.append({"status": parts[1], "name": parts[2]})
        elif line.startswith("##KSIM "):
            name = line[7:].strip()
            if name and name not in would_remove:
                would_remove.append(name)
        elif line.startswith("##KERR"):
            error = line[6:].strip()
        elif line.startswith("##KERNEL "):
            running = line[9:].strip()
    if not packages:
        return None
    return {"packages": packages, "would_remove": would_remove, "running_kernel": running, "error": error,
            "extra": [p for p in would_remove if not KERNEL_RELATED.match(p)]}


async def check_kernels(host: str, port: int, user: str, key_path: str, known_hosts: str) -> Optional[dict]:
    pool = get_ssh_pool()
    client = pool.get_client(host, port, user, key_path, known_hosts, CHECK_TIMEOUT)
    res = client.run_command(f"sh -s <<'VIGILANCE_EOF'\n{KERNEL_SCRIPT}\nVIGILANCE_EOF", timeout=CHECK_TIMEOUT)
    return parse_kernel_output(res.stdout or "")
