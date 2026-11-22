from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_db, get_current_user_optional, require_write_access
from vigilance.api.schemas import (
    VulnerabilityFindingResponse,
    FindingDetailResponse,
    SuppressionResponse,
    SuppressionCreate,
)
from vigilance.database import crud
from vigilance.database.models import VulnerabilityFinding, CVEEntry, DiscoveredTool, Inventory
from vigilance.core.security import User

router = APIRouter()


@router.get("/findings", response_model=List[VulnerabilityFindingResponse])
async def list_findings(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    inventory_id: Optional[int] = Query(None),
    tool_name: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """List vulnerability findings with filters."""
    findings = await crud.get_findings(
        db,
        status=status,
        severity=severity,
        inventory_id=inventory_id,
        tool_name=tool_name,
        limit=limit,
        offset=offset,
    )
    return findings


@router.get("/findings/count")
async def count_filtered_findings(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    inventory_id: Optional[int] = Query(None),
    tool_name: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    return {"total": await crud.count_filtered_findings(
        db, status=status, severity=severity, inventory_id=inventory_id, tool_name=tool_name
    )}


@router.get("/findings/stats")
async def get_findings_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get findings statistics."""
    return await crud.get_finding_stats(db)


@router.get("/findings/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get detailed finding with tool, CVE, and inventory info."""
    finding = await crud.get_findings(db, limit=1, offset=0)
    # This is simplified - in reality you'd fetch by ID with joins
    # For now, return a placeholder
    raise HTTPException(status_code=501, detail="Not fully implemented")


@router.patch("/findings/{finding_id}/suppress")
async def suppress_finding(
    finding_id: int,
    reason: str,
    expires_at: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Suppress a finding."""
    finding = await db.get(VulnerabilityFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    tool = await db.get(DiscoveredTool, finding.discovered_tool_id)
    inventory = await db.get(Inventory, tool.inventory_id) if tool else None

    from datetime import datetime
    expires = datetime.fromisoformat(expires_at) if expires_at else None

    await crud.create_suppression(
        db,
        cve_id=finding.cve.cve_id if finding.cve else "",
        tool_name_pattern=tool.tool_name if tool else None,
        inventory_id=inventory.id if inventory else None,
        reason=reason,
        expires_at=expires,
        created_by=current_user.username,
    )

    finding.status = "suppressed"
    finding.resolved_at = datetime.utcnow()
    await db.commit()

    return {"message": "Finding suppressed"}


@router.patch("/findings/{finding_id}/unsuppress")
async def unsuppress_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Remove suppression from a finding."""
    finding = await db.get(VulnerabilityFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Delete matching suppressions
    from sqlalchemy import delete
    from vigilance.database.models import Suppression
    await db.execute(
        delete(Suppression).where(
            Suppression.cve_id == finding.cve.cve_id,
            Suppression.tool_name_pattern == finding.tool.tool_name,
        )
    )

    finding.status = "open"
    finding.resolved_at = None
    await db.commit()

    return {"message": "Suppression removed"}


# Suppressions
@router.get("/suppressions", response_model=List[SuppressionResponse])
async def list_suppressions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """List all suppressions."""
    return await crud.get_suppressions(db)


@router.post("/suppressions", response_model=SuppressionResponse)
async def create_suppression(
    suppression: SuppressionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Create a new suppression."""
    return await crud.create_suppression(db, **suppression.model_dump(), created_by=current_user.username)


@router.delete("/suppressions/{suppression_id}")
async def delete_suppression(
    suppression_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Delete a suppression."""
    success = await crud.delete_suppression(db, suppression_id)
    if not success:
        raise HTTPException(status_code=404, detail="Suppression not found")
    return {"message": "Suppression deleted"}
