import logging
import re
from dataclasses import dataclass
from typing import List, Optional

from vigilance.discovery.ssh import get_ssh_pool
from vigilance.config import settings

logger = logging.getLogger(__name__)


@dataclass
class CustomCheckResult:
    check_name: str
    command: str
    version: str = ""
    raw_output: str = ""
    success: bool = False


async def run_custom_check(
    check_name: str,
    command: str,
    version_regex: str,
    host: str,
    port: int,
    user: str,
    key_path: str,
    known_hosts: str,
) -> CustomCheckResult:
    """Run a custom check command on a host via SSH."""
    pool = get_ssh_pool()
    targets = [{"host": host, "port": port, "user": user, "key_path": key_path, "known_hosts": known_hosts}]

    result = pool.run_parallel(targets, command)

    if not result[host].success:
        return CustomCheckResult(
            check_name=check_name,
            command=command,
            raw_output=result[host].stderr,
            success=False,
        )

    output = result[host].stdout
    version = ""

    if version_regex:
        match = re.search(version_regex, output)
        if match:
            version = match.group(1) if match.groups() else match.group(0)

    return CustomCheckResult(
        check_name=check_name,
        command=command,
        version=version,
        raw_output=output,
        success=True,
    )


async def run_all_custom_checks(
    host: str,
    port: int,
    user: str,
    key_path: str,
    known_hosts: str,
) -> List[CustomCheckResult]:
    """Run all configured custom checks on a host."""
    results = []
    custom_checks = settings.discovery.custom_checks if settings.discovery else []

    for check in custom_checks:
        result = await run_custom_check(
            check_name=check["name"],
            command=check["command"],
            version_regex=check.get("version_regex", ""),
            host=host,
            port=port,
            user=user,
            key_path=key_path,
            known_hosts=known_hosts,
        )
        results.append(result)

    return results