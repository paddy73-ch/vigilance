"""Detect the operating system release of a scan target via /etc/os-release."""

import logging
import shlex
from dataclasses import dataclass
from typing import Optional, Tuple

from vigilance.discovery.ssh import get_ssh_pool

logger = logging.getLogger(__name__)


@dataclass
class OSInfo:
    id: str = ""  # debian, ubuntu, alpine, ...
    version_id: str = ""  # 13, 24.04, 3.20.3
    codename: str = ""  # trixie, noble
    pretty_name: str = ""


def parse_os_release(text: str) -> OSInfo:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        try:
            parts = shlex.split(raw)
            value = parts[0] if parts else ""
        except ValueError:
            value = raw.strip().strip('"').strip("'")
        values[key.strip()] = value
    return OSInfo(
        id=values.get("ID", "").lower(),
        version_id=values.get("VERSION_ID", ""),
        codename=values.get("VERSION_CODENAME", ""),
        pretty_name=values.get("PRETTY_NAME", ""),
    )


async def probe_os(
    host: str, port: int, user: str, key_path: str, known_hosts: str
) -> Tuple[Optional[OSInfo], Optional[str]]:
    """Read os-release over SSH. Returns (info, error message). Doubles as reachability check."""
    pool = get_ssh_pool()
    target = {"host": host, "port": port, "user": user, "key_path": key_path, "known_hosts": known_hosts}
    result = pool.run_parallel([target], "cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null")
    res = result.get(host)
    if not res or not res.success or not res.stdout:
        error = (getattr(res, "error", None) or getattr(res, "stderr", None) or "").strip() if res else ""
        logger.warning("Could not read os-release on %s: %s", host, error or "no output")
        return None, error or "SSH-Verbindung fehlgeschlagen"
    return parse_os_release(res.stdout), None


async def discover_os_on_host(
    host: str, port: int, user: str, key_path: str, known_hosts: str
) -> Optional[OSInfo]:
    info, _ = await probe_os(host, port, user, key_path, known_hosts)
    return info
