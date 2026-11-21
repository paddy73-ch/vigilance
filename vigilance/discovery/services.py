import logging
import re
from dataclasses import dataclass
from typing import List

from vigilance.discovery.ssh import get_ssh_pool
from vigilance.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    name: str
    status: str  # active, inactive, failed, etc.
    version: str = ""
    description: str = ""


def parse_systemctl_output(output: str) -> List[ServiceInfo]:
    """Parse `systemctl list-units --type=service --all --no-legend --plain` output."""
    services = []
    # Format: UNIT LOAD ACTIVE SUB DESCRIPTION
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split(None, 4)
        if len(parts) >= 4:
            name = parts[0]
            load = parts[1]
            active = parts[2]
            sub = parts[3]
            description = parts[4] if len(parts) > 4 else ""
            if load == "loaded":
                services.append(ServiceInfo(
                    name=name.replace(".service", ""),
                    status=active,
                    description=description,
                ))
    return services


def get_service_version(service_name: str, host: str, port: int, user: str, key_path: str, known_hosts: str) -> str:
    """Try to get version for a specific service."""
    pool = get_ssh_pool()
    targets = [{"host": host, "port": port, "user": user, "key_path": key_path, "known_hosts": known_hosts}]

    version_commands = {
        "nginx": "nginx -v 2>&1 | head -1",
        "apache2": "apache2 -v 2>&1 | head -1",
        "httpd": "httpd -v 2>&1 | head -1",
        "postgresql": "postgres --version 2>&1 | head -1",
        "mysql": "mysql --version 2>&1 | head -1",
        "mariadb": "mysql --version 2>&1 | head -1",
        "redis": "redis-server --version 2>&1 | head -1",
        "docker": "docker --version 2>&1",
        "containerd": "containerd --version 2>&1",
        "kubelet": "kubelet --version 2>&1",
    }

    cmd = version_commands.get(service_name)
    if not cmd:
        return ""

    result = pool.run_parallel(targets, cmd)
    if result[host].success:
        return result[host].stdout.strip()
    return ""


async def discover_services_on_host(
    host: str,
    port: int,
    user: str,
    key_path: str,
    known_hosts: str,
    include_patterns: List[str],
) -> List[ServiceInfo]:
    """Discover systemd services on a single host via SSH."""
    pool = get_ssh_pool()
    targets = [{"host": host, "port": port, "user": user, "key_path": key_path, "known_hosts": known_hosts}]

    # Get all services
    cmd = "systemctl list-units --type=service --all --no-legend --plain 2>/dev/null"
    result = pool.run_parallel(targets, cmd)

    if not result[host].success:
        return []

    all_services = parse_systemctl_output(result[host].stdout)

    # Filter by include patterns
    filtered = []
    for svc in all_services:
        for pattern in include_patterns:
            if pattern.lower() in svc.name.lower():
                # Try to get version
                svc.version = get_service_version(svc.name, host, port, user, key_path, known_hosts)
                filtered.append(svc)
                break

    return filtered


async def discover_services_all() -> dict:
    """Discover services on all configured hosts."""
    results = {}
    include_patterns = settings.discovery.services_include_patterns if settings.discovery else []

    for node_config in settings.proxmox_nodes:
        if not node_config.ssh_host:
            continue

        services = await discover_services_on_host(
            node_config.ssh_host,
            node_config.ssh_port,
            node_config.ssh_user,
            node_config.ssh_key_path,
            node_config.ssh_known_hosts,
            include_patterns,
        )
        results[f"{node_config.name} (host)"] = services

    return results