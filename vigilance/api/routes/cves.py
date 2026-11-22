import asyncio
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_db, get_current_user_optional, require_write_access
from vigilance.api.schemas import CVEEntryResponse, CVESyncStatusResponse, CVESyncTriggerResponse, CVESyncStatusWithEntriesResponse
from vigilance.database import crud
from vigilance.cve.sync import sync_cve_source
from vigilance.core.security import User

logger = logging.getLogger(__name__)

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


@router.get("/cves/sync/status/{source}/entries", response_model=CVESyncStatusWithEntriesResponse)
async def get_sync_status_entries(
    source: str,
    limit: int = Query(100, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get CVE sync status with entries for a specific source."""
    status = await crud.get_sync_status(db, source)
    if not status:
        raise HTTPException(status_code=404, detail="Sync status not found for source")
    
    entries = await crud.get_cve_entries_by_source(db, source, limit=limit)
    
    return CVESyncStatusWithEntriesResponse(
        source=status.source,
        status=status.status,
        last_sync_at=status.last_sync_at,
        last_success_at=status.last_success_at,
        entries_count=status.entries_count,
        error_message=status.error_message,
        next_sync_at=status.next_sync_at,
        entries=entries,
    )


@router.post("/cves/sync", response_model=CVESyncTriggerResponse)
async def trigger_cve_sync(
    source: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Trigger CVE sync for all or specific source."""
    async def run() -> None:
        try:
            if source:
                await sync_cve_source(source)
            else:
                from vigilance.cve.sync import CVESyncOrchestrator
                from vigilance.database.base import async_session_maker
                async with async_session_maker() as sync_db:
                    await CVESyncOrchestrator(sync_db).sync_all()
        except Exception as e:
            logger.error(f"CVE sync failed for {source or 'all'}: {e}")
            # Update sync status to error
            from vigilance.database.base import async_session_maker
            from vigilance.database import crud
            async with async_session_maker() as sync_db:
                src = source or "all"
                await crud.update_sync_status(sync_db, src, status="error", error_message=str(e))
                await sync_db.commit()

    task = asyncio.create_task(run(), name=f"cve-sync-{source or 'all'}")
    task.add_done_callback(lambda t: t.exception() if t.exception() else None)
    return CVESyncTriggerResponse(results={}, message="CVE sync started in background")
