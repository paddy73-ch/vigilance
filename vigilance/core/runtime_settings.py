"""Settings changed in the UI (stored in app_settings), applied on top of .env / config.yaml.

- Gotify: once saved in the UI, the stored values win over VIGILANCE_GOTIFY_* and config.yaml.
  The token is stored in the database and never returned by the API.
- CVE sources: on/off per source; the stored value wins over config.yaml.
"""

import logging
from typing import Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.config import NotificationsConfig, settings
from vigilance.database import crud

logger = logging.getLogger(__name__)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
GOTIFY_PREFIX = "gotify."
SOURCE_PREFIX = "source_enabled."

# source -> enabled, as switched in the UI (read by cve.sync._source_enabled)
SOURCE_OVERRIDES: Dict[str, bool] = {}
VM_PREFIX = "vm_scan."
# vmid -> {"enabled": bool, "ip": str|None}, as switched in the UI (read by config.vm_scan_entries)
VM_SCAN_OVERRIDES: Dict[int, dict] = {}
# where the Gotify settings come from: "ui" once saved there, else "config"
gotify_origin = "config"


def gotify_config():
    if settings.notifications is None:
        settings.notifications = NotificationsConfig({})
    return settings.notifications.gotify


async def load(db: AsyncSession) -> None:
    """Apply everything stored in the database (at startup and before a CVE sync in the CLI)."""
    await load_gotify(db)
    await load_source_overrides(db)
    await load_vm_overrides(db)


async def load_gotify(db: AsyncSession) -> None:
    global gotify_origin
    stored = {k: await crud.get_setting(db, GOTIFY_PREFIX + k)
              for k in ("enabled", "url", "token", "min_severity", "digest_mode", "digest_interval_minutes")}
    if stored["url"] is None:  # never saved in the UI
        return
    g = gotify_config()
    g.enabled = stored["enabled"] == "true"
    g.url = stored["url"] or ""
    if stored["token"] is not None:
        g.token = stored["token"]
    if stored["min_severity"] in SEVERITIES:
        g.min_severity = stored["min_severity"]
    g.digest_mode = stored["digest_mode"] == "true"
    try:
        g.digest_interval_minutes = int(stored["digest_interval_minutes"] or g.digest_interval_minutes)
    except ValueError:
        pass
    gotify_origin = "ui"


async def save_gotify(db: AsyncSession, enabled: bool, url: str, token: Optional[str], min_severity: str,
                      digest_mode: bool, digest_interval_minutes: int) -> None:
    """token None = keep the current token."""
    global gotify_origin
    g = gotify_config()
    values = {"enabled": "true" if enabled else "false", "url": url, "min_severity": min_severity,
              "digest_mode": "true" if digest_mode else "false", "digest_interval_minutes": str(digest_interval_minutes)}
    if token is not None:
        values["token"] = token
    elif g.token and await crud.get_setting(db, GOTIFY_PREFIX + "token") is None:
        values["token"] = g.token  # keep the token from .env when the UI takes over
    for k, v in values.items():
        await crud.set_setting(db, GOTIFY_PREFIX + k, v, "Gotify (set in the UI)")
    await db.commit()
    g.enabled, g.url, g.min_severity = enabled, url, min_severity
    g.digest_mode, g.digest_interval_minutes = digest_mode, digest_interval_minutes
    if token is not None:
        g.token = token
    gotify_origin = "ui"


def gotify_ready() -> bool:
    g = settings.notifications.gotify if settings.notifications else None
    return bool(g and g.enabled and g.url and g.token)


async def load_source_overrides(db: AsyncSession) -> None:
    from vigilance.cve.sync import ALL_SOURCES
    for s in ALL_SOURCES:
        v = await crud.get_setting(db, SOURCE_PREFIX + s)
        if v is not None:
            SOURCE_OVERRIDES[s] = v == "true"


async def set_source_enabled(db: AsyncSession, source: str, enabled: bool) -> None:
    await crud.set_setting(db, SOURCE_PREFIX + source, "true" if enabled else "false", "CVE source on/off (UI)")
    SOURCE_OVERRIDES[source] = enabled


async def load_vm_overrides(db: AsyncSession) -> None:
    import json
    from sqlalchemy import select
    from vigilance.database.models import AppSetting
    rows = (await db.execute(select(AppSetting).where(AppSetting.key.like(VM_PREFIX + "%")))).scalars().all()
    VM_SCAN_OVERRIDES.clear()
    for row in rows:
        try:
            VM_SCAN_OVERRIDES[int(row.key[len(VM_PREFIX):])] = json.loads(row.value)
        except (ValueError, TypeError):
            continue


async def set_vm_scan(db: AsyncSession, vmid: int, enabled: bool, ip: Optional[str]) -> None:
    import json
    value = {"enabled": enabled, "ip": ip or None}
    await crud.set_setting(db, VM_PREFIX + str(vmid), json.dumps(value), "VM scan on/off (UI)")
    VM_SCAN_OVERRIDES[vmid] = value
