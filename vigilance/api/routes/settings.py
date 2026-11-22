from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_db, get_current_user_optional, require_write_access
from vigilance.api.schemas import GotifyTestRequest, GotifyTestResponse
from vigilance.database import crud
from vigilance.database.models import AppSetting
from vigilance.core.notifications import send_test_gotify
from vigilance.core.security import User
from vigilance.config import settings

router = APIRouter()


@router.get("/settings")
async def get_settings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get current configuration (non-sensitive)."""
    return {
        "auth_mode": settings.auth_mode,
        "scan_interval_hours": settings.scan_interval_hours,
        "cve_sync_interval_hours": settings.cve_sync_interval_hours,
        "ssh_timeout": settings.ssh_timeout,
        "ssh_parallel_jobs": settings.ssh_parallel_jobs,
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


@router.post("/settings/gotify/test", response_model=GotifyTestResponse)
async def test_gotify(
    request: GotifyTestRequest,
    current_user: User = Depends(require_write_access),
):
    """Test Gotify connectivity with provided or configured credentials."""
    success = await send_test_gotify(url=request.url, token=request.token)
    return GotifyTestResponse(
        success=success,
        message="Test notification sent successfully" if success else "Failed to send test notification. Check URL and token.",
    )


@router.get("/settings/api-token")
async def get_api_token_info(
    current_user: User = Depends(require_write_access),
):
    """Get API token info (masked)."""
    token = settings.api_token
    return {
        "configured": bool(token),
        "preview": token[:8] + "..." + token[-4:] if token and len(token) > 12 else "",
    }
