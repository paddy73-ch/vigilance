from typing import Optional
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

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
        "gotify_configured": bool(settings.notifications and settings.notifications.gotify and settings.notifications.gotify.url),
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
    scan_interval_hours: Optional[int] = None
    cve_sync_interval_hours: Optional[int] = None
    ssh_timeout: Optional[int] = None
    ssh_parallel_jobs: Optional[int] = None


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
    await db.commit()
    if update.scan_interval_hours is not None or update.cve_sync_interval_hours is not None:
        from vigilance.core.scheduler import reschedule_jobs
        reschedule_jobs()
    return {"message": "Settings saved successfully"}


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
            message="Test notification sent successfully",
        )
    return GotifyTestResponse(
        success=False,
        message=f"Failed to send test notification: {error}",
    )


@router.get("/settings/api-token")
async def get_api_token_info(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Whether a write token is configured (never returns the token or parts of it)."""
    from vigilance.core import auth_token
    return await auth_token.get_token_info(db)
