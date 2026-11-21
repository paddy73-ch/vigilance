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


def parse_dpkg_output(output: str) -> List[PackageInfo]:
    """Parse `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Description}\n'` output."""
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
                manager="dpkg",
            ))
    return packages


def parse_apk_output(output: str) -> List[PackageInfo]:
    """Parse `apk info -v` output."""
    packages = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        # apk info -v outputs: package-name-version
        match = re.match(r"^(.+)-([\d.]+(?:-[\w.]+)?)?$", line.strip())
        if match:
            packages.append(PackageInfo(
                name=match.group(1),
                version=match.group(2) or "",
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
            cmd = "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${Description}\\n' 2>/dev/null"
            result = pool.run_parallel(targets, cmd)
            if result[host].success:
                all_packages.extend(parse_dpkg_output(result[host].stdout))
        elif manager == "apk":
            cmd = "apk info -v 2>/dev/null"
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