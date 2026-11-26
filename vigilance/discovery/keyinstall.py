"""Put Vigilance's SSH key into a container that rejects it (switch "Schlüssel selbst eintragen").

Runs on the Proxmox host as the unprivileged host user (``vigilance-scan``) and calls only
``sudo -n /usr/local/sbin/vigilance-install-key <vmid>``. That helper has the public key built in, so
Vigilance cannot put any other key anywhere; see docs/LIMITATIONS.md for the setup on the host.
"""
import asyncio
import logging
from typing import Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.database import crud
from vigilance.discovery.ssh import get_ssh_pool

logger = logging.getLogger(__name__)

SETTING_KEY = "ssh_key_autoinstall"
HELPER = "/usr/local/sbin/vigilance-install-key"


async def autoinstall_enabled(db: AsyncSession) -> bool:
    return (await crud.get_setting(db, SETTING_KEY)) == "1"


async def set_autoinstall(db: AsyncSession, enabled: bool) -> None:
    await crud.set_setting(db, SETTING_KEY, "1" if enabled else "0",
                           "Put Vigilance's SSH key into containers that reject it")


def install_command(vmid: int) -> str:
    return f"sudo -n {HELPER} {int(vmid)}"


async def install_key(node_config, vmid: int, key_path: str, known_hosts: str) -> Tuple[bool, Optional[str]]:
    """Ask the Proxmox host to put the key into container ``vmid``. Returns (ok, error)."""
    if not node_config or not node_config.ssh_host:
        return False, "kein SSH-Zugang zum Proxmox-Host konfiguriert"
    target = {"host": node_config.ssh_host, "port": node_config.ssh_port or 22, "user": node_config.host_user,
              "key_path": key_path, "known_hosts": known_hosts}
    pool = get_ssh_pool()
    results = await asyncio.to_thread(pool.run_parallel, [target], install_command(vmid))
    res = results.get(node_config.ssh_host)
    if res and res.success:
        logger.info("SSH key put into CT %s via %s", vmid, node_config.ssh_host)
        return True, None
    detail = ((res.stderr or res.stdout) if res else "") or "keine Antwort"
    if "a password is required" in detail or "not allowed" in detail or "may not run sudo" in detail:
        detail = f"sudo-Regel für {HELPER} fehlt auf dem Proxmox-Host"
    logger.warning("Could not put SSH key into CT %s: %s", vmid, detail)
    return False, detail.strip().splitlines()[-1][:200]
