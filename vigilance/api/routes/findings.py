from typing import List, Optional
from sqlalchemy import func, select
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
from vigilance.database.models import VulnerabilityFinding, CVEEntry, DiscoveredTool, Inventory, ProxmoxNode
from vigilance.core.security import User

router = APIRouter()


@router.get("/inventory-findings")
async def inventory_findings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    inventories = (await db.execute(
        select(Inventory, ProxmoxNode.name)
        .outerjoin(ProxmoxNode, Inventory.proxmox_node_id == ProxmoxNode.id)
        .where(Inventory.status == "running")
        .order_by(Inventory.name)
    )).all()
    rows = {
        inventory.id: {
            "id": inventory.id, "name": inventory.name, "vmid": inventory.vmid,
            "type": inventory.type, "status": inventory.status, "hostname": inventory.hostname,
            "node": node_name or "Unknown",
            "counts": {level: 0 for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]},
            "total": 0, "tools": {},
        }
        for inventory, node_name in inventories
    }
    finding_rows = (await db.execute(
        select(VulnerabilityFinding, DiscoveredTool, CVEEntry)
        .join(DiscoveredTool, VulnerabilityFinding.discovered_tool_id == DiscoveredTool.id)
        .join(CVEEntry, VulnerabilityFinding.cve_entry_id == CVEEntry.id)
        .where(VulnerabilityFinding.status == "open")
        .order_by(CVEEntry.severity, DiscoveredTool.tool_name, CVEEntry.cve_id)
    )).all()
    for finding, tool, cve in finding_rows:
        host = rows.get(tool.inventory_id)
        if not host:
            continue
        level = (cve.severity or "NONE").upper()
        host["counts"][level if level in host["counts"] else "NONE"] += 1
        host["total"] += 1
        item = host["tools"].setdefault(tool.id, {
            "name": tool.tool_name, "version": tool.detected_version, "findings": []
        })
        item["findings"].append({
            "cve_id": cve.cve_id, "severity": level,
            "title": cve.title, "fixed_version": finding.fixed_version,
        })
    result = list(rows.values())
    for host in result:
        host["tools"] = list(host["tools"].values())
    return sorted(result, key=lambda row: row["total"], reverse=True)


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


@router.get("/findings/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get detailed finding with tool, CVE, and inventory info."""
    finding = await crud.get_findings(db, limit=1, offset=0)
    raise HTTPException(status_code=501, detail="Not fully implemented")


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
