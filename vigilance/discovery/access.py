"""How Vigilance reaches the containers of a Proxmox node.

- "pct" (default): over SSH to the Proxmox host as the host user (vigilance-scan), then
  `sudo pct exec <vmid> -- …`. No key, sshd or IP needed in the containers.
- "ssh": directly to each container's IP as root with Vigilance's key.

Set per node in Verwaltung › Einstellungen (stored as app_settings "container_access.<node>"), or in
config.yaml with `container_access:` on the node; the UI wins. Installations that existed before this
option keep "ssh" (migration 007), so an update does not break their scans. VMs always use SSH.
"""
from typing import Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.config import settings
from vigilance.database import crud

PREFIX = "container_access."
MODES = ("pct", "ssh")
DEFAULT = "pct"

# node name -> mode, as switched in the UI
OVERRIDES: Dict[str, str] = {}


def mode_for(node_name: Optional[str]) -> str:
    if node_name in OVERRIDES:
        return OVERRIDES[node_name]
    cfg = next((c for c in settings.proxmox_nodes if c.name == node_name), None)
    configured = getattr(cfg, "container_access", None) if cfg else None
    return configured if configured in MODES else DEFAULT


def origin_for(node_name: str) -> str:
    if node_name in OVERRIDES:
        return "ui"
    cfg = next((c for c in settings.proxmox_nodes if c.name == node_name), None)
    return "config" if cfg and getattr(cfg, "container_access", None) in MODES else "default"


async def load(db: AsyncSession) -> None:
    from vigilance.database.models import AppSetting
    rows = (await db.execute(select(AppSetting).where(AppSetting.key.like(PREFIX + "%")))).scalars().all()
    OVERRIDES.clear()
    for row in rows:
        if row.value in MODES:
            OVERRIDES[row.key[len(PREFIX):]] = row.value


async def set_mode(db: AsyncSession, node_name: str, mode: str) -> None:
    if mode not in MODES:
        raise ValueError(mode)
    await crud.set_setting(db, PREFIX + node_name, mode, "How Vigilance reaches the containers (pct or ssh)")
    OVERRIDES[node_name] = mode
