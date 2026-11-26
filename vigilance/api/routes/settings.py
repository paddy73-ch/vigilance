from typing import List, Literal, Optional
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.discovery import keyinstall
from vigilance.core import schedule
from vigilance.core.scheduler import next_runs, reschedule_jobs
from vigilance.api.deps import get_db, get_current_user_optional, require_write_access
from vigilance.api.schemas import GotifyTestRequest, GotifyTestResponse
from vigilance.database import crud
from vigilance.database.models import AppSetting
from vigilance.core.notifications import send_test_gotify
from vigilance.core.security import User
from vigilance.config import settings

router = APIRouter()


def _get_int_setting(db_settings: dict, key: str, default: int) -> int:
    val = db_settings.get(key)
    if val is not None:
        try:
            return int(val)
        except (ValueError, TypeError):
            pass
    return default


async def _load_db_settings(db: AsyncSession) -> dict:
    """Load editable settings from database, falling back to config defaults."""
    keys = ["scan_interval_hours", "cve_sync_interval_hours", "ssh_timeout", "ssh_parallel_jobs"]
    result = {}
    for key in keys:
        val = await crud.get_setting(db, key)
        if val is not None:
            result[key] = val
    return result


def _gotify_info() -> dict:
    """Gotify settings for the UI. The token itself is never returned."""
    from vigilance.core import runtime_settings as rs
    g = settings.notifications.gotify if settings.notifications else None
    return {
        "enabled": bool(g and g.enabled),
        "ready": rs.gotify_ready(),
        "url": (g.url if g else "") or "",
        "token_set": bool(g and g.token),
        "min_severity": (g.min_severity if g else "HIGH") or "HIGH",
        "digest_mode": bool(g and g.digest_mode),
        "digest_interval_minutes": (g.digest_interval_minutes if g else 60) or 60,
        "origin": rs.gotify_origin,
    }


class GotifyUpdate(BaseModel):
    enabled: bool = True
    url: str = Field("", max_length=500)
    token: Optional[str] = Field(None, max_length=200)  # None or "" = keep the current token
    min_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "HIGH"
    digest_mode: bool = False
    digest_interval_minutes: int = Field(60, ge=5, le=1440)


@router.put("/settings/gotify")
async def update_gotify(update: GotifyUpdate, db: AsyncSession = Depends(get_db),
                        current_user: User = Depends(require_write_access)):
    """Gotify settings from the UI; they take precedence over .env and config.yaml."""
    from vigilance.core import runtime_settings as rs
    url = update.url.strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Die Adresse muss mit http:// oder https:// beginnen.")
    if update.enabled and not url:
        raise HTTPException(status_code=400, detail="Für aktive Meldungen braucht es die Adresse des Gotify-Servers.")
    token = (update.token or "").strip() or None
    if update.enabled and not token and not (settings.notifications and settings.notifications.gotify.token):
        raise HTTPException(status_code=400, detail="Für aktive Meldungen braucht es den App-Token aus Gotify.")
    await rs.save_gotify(db, update.enabled, url, token, update.min_severity, update.digest_mode,
                         update.digest_interval_minutes)
    from vigilance.core.scheduler import apply_digest_job
    apply_digest_job()
    return _gotify_info()


def _source_on(source: str) -> bool:
    from vigilance.cve.sync import _source_enabled
    return _source_enabled(source)


@router.get("/settings/ssh-key")
async def get_ssh_public_key(current_user: User = Depends(get_current_user_optional)):
    """Public SSH key Vigilance uses for the LXCs (to put into authorized_keys)."""
    from vigilance.discovery.sshkey import SSH_PUBLIC_KEY
    try:
        return {"public_key": SSH_PUBLIC_KEY.read_text().strip()}
    except OSError:
        return {"public_key": None}


@router.get("/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get current configuration (non-sensitive)."""
    db_settings = await _load_db_settings(db)
    return {
        "auth_mode": settings.auth_mode,
        "scan_interval_hours": _get_int_setting(db_settings, "scan_interval_hours", settings.scan_interval_hours),
        "cve_sync_interval_hours": _get_int_setting(db_settings, "cve_sync_interval_hours", settings.cve_sync_interval_hours),
        "ssh_timeout": _get_int_setting(db_settings, "ssh_timeout", settings.ssh_timeout),
        "ssh_parallel_jobs": _get_int_setting(db_settings, "ssh_parallel_jobs", settings.ssh_parallel_jobs),
        "ssh_key_autoinstall": await keyinstall.autoinstall_enabled(db),
        "schedules": {kind: schedule.describe(kind) for kind in schedule.KINDS},
        "next_runs": next_runs(),
        "ssh_key_helper": keyinstall.HELPER,
        "gotify_configured": bool(settings.notifications and settings.notifications.gotify and settings.notifications.gotify.url),
        "gotify": _gotify_info(),
        "sources_disabled": [s for s in ("nvd", "debian", "ubuntu", "ghsa", "osv", "tailscale") if not _source_on(s)],
        "proxmox_nodes_configured": len(settings.proxmox_nodes),
        "proxmox_nodes": [
            {
                "name": node.name,
                "url": node.url,
                "token_id": node.token_id,
                "verify_tls": node.verify_tls,
                "ssh_host": node.ssh_host,
            }
            for node in settings.proxmox_nodes
        ],
    }


class SettingsUpdate(BaseModel):
    scan_interval_hours: Optional[int] = Field(None, ge=1, le=168)
    cve_sync_interval_hours: Optional[int] = Field(None, ge=1, le=168)
    ssh_timeout: Optional[int] = Field(None, ge=5, le=300)
    ssh_parallel_jobs: Optional[int] = Field(None, ge=1, le=50)
    ssh_key_autoinstall: Optional[bool] = None


@router.post("/settings")
async def update_settings(
    update: SettingsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Update editable settings. Values are persisted in the database."""
    if update.scan_interval_hours is not None:
        await crud.set_setting(db, "scan_interval_hours", str(update.scan_interval_hours), "Scan interval in hours")
        settings.scan_interval_hours = update.scan_interval_hours
    if update.cve_sync_interval_hours is not None:
        await crud.set_setting(db, "cve_sync_interval_hours", str(update.cve_sync_interval_hours), "CVE sync interval in hours")
        settings.cve_sync_interval_hours = update.cve_sync_interval_hours
    if update.ssh_timeout is not None:
        await crud.set_setting(db, "ssh_timeout", str(update.ssh_timeout), "SSH timeout in seconds")
        settings.ssh_timeout = update.ssh_timeout
    if update.ssh_parallel_jobs is not None:
        await crud.set_setting(db, "ssh_parallel_jobs", str(update.ssh_parallel_jobs), "SSH parallel jobs")
        settings.ssh_parallel_jobs = update.ssh_parallel_jobs
    if update.ssh_key_autoinstall is not None:
        await keyinstall.set_autoinstall(db, update.ssh_key_autoinstall)
    await db.commit()
    if update.scan_interval_hours is not None or update.cve_sync_interval_hours is not None:
        from vigilance.core.scheduler import reschedule_jobs
        reschedule_jobs()
    return {"message": "Settings saved successfully"}


class ScheduleUpdate(BaseModel):
    mode: Literal["interval", "times"] = "interval"
    hours: Optional[int] = Field(None, ge=1, le=168)
    times: List[str] = Field(default_factory=list, max_length=schedule.MAX_TIMES)
    days: List[int] = Field(default_factory=list, max_length=7)
    timezone: Optional[str] = Field(None, max_length=64)


@router.put("/settings/schedule/{kind}")
async def update_schedule(
    kind: str,
    update: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Scan or CVE sync: every N hours, or at fixed times of day (set with the clock)."""
    if kind not in schedule.KINDS:
        raise HTTPException(status_code=404, detail="Unbekannter Auftrag")
    try:
        await schedule.save(db, kind, update.model_dump())
    except schedule.ScheduleError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await db.commit()
    reschedule_jobs()
    return {"schedule": schedule.describe(kind), "next_runs": next_runs()}


@router.post("/settings/gotify/test", response_model=GotifyTestResponse)
async def test_gotify(
    request: GotifyTestRequest,
    current_user: User = Depends(require_write_access),
):
    """Test Gotify connectivity with provided or configured credentials."""
    success, error = await send_test_gotify(url=request.url, token=request.token)
    if success:
        return GotifyTestResponse(
            success=True,
            message="Testnachricht gesendet.",
        )
    return GotifyTestResponse(
        success=False,
        message=f"Testnachricht nicht gesendet: {error}",
    )


@router.get("/settings/api-token")
async def get_api_token_info(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Whether a write token is configured (never returns the token or parts of it)."""
    from vigilance.core import auth_token
    return await auth_token.get_token_info(db)
