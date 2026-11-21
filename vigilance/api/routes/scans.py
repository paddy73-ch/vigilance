from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_db, get_current_user_optional, require_write_access
from vigilance.api.schemas import ScanRunResponse, ScanTriggerRequest, ScanTriggerResponse
from vigilance.database import crud
from vigilance.core.scheduler import trigger_scan_now
from vigilance.core.security import User

router = APIRouter()


@router.get("/scans", response_model=List[ScanRunResponse])
async def list_scans(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """List recent scan runs."""
    return await crud.get_recent_scan_runs(db, limit=limit)


@router.post("/scans/trigger", response_model=ScanTriggerResponse)
async def trigger_scan(
    request: ScanTriggerRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Trigger a new scan."""
    scan_run_id = await trigger_scan_now(full=request.full)
    return ScanTriggerResponse(
        scan_run_id=scan_run_id,
        message=f"{'Full' if request.full else 'Incremental'} scan started",
    )


@router.get("/scans/{scan_id}", response_model=ScanRunResponse)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get a specific scan run."""
    scan = await db.get(crud.ScanRun, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan