import json
import logging
import re
from dataclasses import dataclass
from typing import List, Optional

from vigilance.discovery.ssh import get_ssh_pool, CommandResult
from vigilance.config import settings

logger = logging.getLogger(__name__)


@dataclass
class PackageInfo:
    name: str
    version: str
    architecture: str = ""
    description: str = ""
    manager: str = "dpkg"
    # Source package (Debian) / origin (Alpine). CVE trackers key on these,
    # not on binary package names (e.g. libssl3t64 -> openssl).
    source_name: str = ""
    source_version: str = ""

    def __post_init__(self):
        if not self.source_name:
            self.source_name = self.name
        if not self.source_version:
            self.source_version = self.version


DPKG_QUERY_FORMAT = "${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\t${source:Version}\\t${binary:Summary}\\n"


def parse_dpkg_output(output: str) -> List[PackageInfo]:
    """Parse dpkg-query output.

    Expected columns: Package, Version, Architecture, source:Package,
    source:Version, binary:Summary (see DPKG_QUERY_FORMAT). Older four-column
    output (without source fields) is still accepted.
    """
    packages = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t", 5)
        if len(parts) < 2:
            continue
        if len(parts) >= 5:
            packages.append(PackageInfo(
                name=parts[0],
                version=parts[1],
                architecture=parts[2],
                source_name=parts[3],
                source_version=parts[4],
                description=parts[5] if len(parts) > 5 else "",
                manager="dpkg",
            ))
        else:
            packages.append(PackageInfo(
                name=parts[0],
                version=parts[1],
                architecture=parts[2] if len(parts) > 2 else "",
                description=parts[3] if len(parts) > 3 else "",
                manager="dpkg",
            ))
    return packages


_APK_LIST_RE = re.compile(r"^(?P<nv>\S+)\s+\S+\s+\{(?P<origin>[^}]+)\}")
_APK_NAME_VERSION_RE = re.compile(r"^(?P<name>.+)-(?P<version>\d[^-]*-r\d+)$")


def parse_apk_output(output: str) -> List[PackageInfo]:
    """Parse `apk list --installed` output (falls back to `apk info -v` lines).

    `apk list --installed` line: ``busybox-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only) [installed]``
    """
    packages = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("WARNING"):
            continue
        origin = ""
        nv = line
        m = _APK_LIST_RE.match(line)
        if m:
            nv, origin = m.group("nv"), m.group("origin")
        else:
            nv = line.split()[0]
        m = _APK_NAME_VERSION_RE.match(nv)
        if not m:
            continue
        packages.append(PackageInfo(
            name=m.group("name"),
            version=m.group("version"),
            source_name=origin,
            manager="apk",
        ))
    return packages


def parse_rpm_output(output: str) -> List[PackageInfo]:
    """Parse `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\n'` output."""
    packages = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t", 3)
        if len(parts) >= 2:
            packages.append(PackageInfo(
                name=parts[0],
                version=parts[1],
                architecture=parts[2] if len(parts) > 2 else "",
                description=parts[3] if len(parts) > 3 else "",
                manager="rpm",
            ))
    return packages


async def discover_packages_on_host(
    host: str,
    port: int,
    user: str,
    key_path: str,
    known_hosts: str,
    managers: List[str],
) -> List[PackageInfo]:
    """Discover packages on a single host via SSH."""
    pool = get_ssh_pool()
    targets = [{"host": host, "port": port, "user": user, "key_path": key_path, "known_hosts": known_hosts}]
    all_packages = []

    for manager in managers:
        if manager == "dpkg":
            cmd = f"dpkg-query -W -f='{DPKG_QUERY_FORMAT}' 2>/dev/null"
            result = pool.run_parallel(targets, cmd)
            if result[host].success:
                all_packages.extend(parse_dpkg_output(result[host].stdout))
        elif manager == "apk":
            cmd = "apk list --installed 2>/dev/null || apk info -v 2>/dev/null"
            result = pool.run_parallel(targets, cmd)
            if result[host].success:
                all_packages.extend(parse_apk_output(result[host].stdout))
        elif manager == "rpm":
            cmd = "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SUMMARY}\\n' 2>/dev/null"
            result = pool.run_parallel(targets, cmd)
            if result[host].success:
                all_packages.extend(parse_rpm_output(result[host].stdout))

    return all_packages


async def discover_packages_all() -> dict:
    """Discover packages on all configured hosts."""
    results = {}

    for node_config in settings.proxmox_nodes:
        if not node_config.ssh_host:
            continue

        managers = settings.discovery.packages_managers if settings.discovery else ["dpkg", "apk", "rpm"]
        packages = await discover_packages_on_host(
            node_config.ssh_host,
            node_config.ssh_port,
            node_config.ssh_user,
            node_config.ssh_key_path,
            node_config.ssh_known_hosts,
            managers,
        )
        results[f"{node_config.name} (host)"] = packages

    return results