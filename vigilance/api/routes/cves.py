import asyncio
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_db, get_current_user_optional, require_write_access
from vigilance.api.schemas import CVEEntryResponse, CVESyncStatusResponse, CVESyncTriggerResponse
from vigilance.database import crud
from vigilance.cve.sync import sync_cve_source
from vigilance.core.security import User

router = APIRouter()


@router.get("/cves", response_model=List[CVEEntryResponse])
async def list_cves(
    source: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """List CVE entries from local cache."""
    return await crud.get_cve_entries(db, source=source, severity=severity, limit=limit, offset=offset)


@router.get("/cves/{cve_id}", response_model=CVEEntryResponse)
async def get_cve(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get a specific CVE entry."""
    cve = await crud.get_cve_entry(db, cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


@router.get("/cves/sync/status", response_model=List[CVESyncStatusResponse])
async def get_sync_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get CVE sync status for all sources."""
    return await crud.get_all_sync_status(db)


@router.post("/cves/sync", response_model=CVESyncTriggerResponse)
async def trigger_cve_sync(
    source: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Trigger CVE sync for all or specific source."""
    async def run() -> None:
        if source:
            await sync_cve_source(source)
        else:
            from vigilance.cve.sync import CVESyncOrchestrator
            from vigilance.database.base import async_session_maker
            async with async_session_maker() as sync_db:
                await CVESyncOrchestrator(sync_db).sync_all()

    asyncio.create_task(run(), name=f"cve-sync-{source or 'all'}")
    return CVESyncTriggerResponse(results={}, message="CVE sync started")
