"""Detect the operating system release of a scan target via /etc/os-release."""

import logging
import shlex
from dataclasses import dataclass
from typing import Optional

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


async def discover_os_on_host(
    host: str, port: int, user: str, key_path: str, known_hosts: str
) -> Optional[OSInfo]:
    pool = get_ssh_pool()
    target = {"host": host, "port": port, "user": user, "key_path": key_path, "known_hosts": known_hosts}
    result = pool.run_parallel([target], "cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null")
    res = result.get(host)
    if not res or not res.success or not res.stdout:
        logger.warning("Could not read os-release on %s", host)
        return None
    return parse_os_release(res.stdout)
