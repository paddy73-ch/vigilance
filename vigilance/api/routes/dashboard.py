from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select

from vigilance.api.deps import get_db, get_current_user_optional
from vigilance.api.schemas import DashboardStats, ScanRunResponse, CVESyncStatusResponse
from vigilance.database import crud
from vigilance.database.models import (
    ProxmoxNode,
    Inventory,
    DiscoveredTool,
    VulnerabilityFinding,
    CVEEntry,
    ScanRun,
    CVESyncStatus,
)
from vigilance.core.security import User

router = APIRouter()


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get dashboard statistics."""
    # Count nodes
    total_nodes = await db.scalar(select(func.count(ProxmoxNode.id)))

    # Count VMs and LXCs (only running)
    total_vms = await db.scalar(select(func.count(Inventory.id)).where(Inventory.type == "qemu", Inventory.status == "running"))
    total_lxcs = await db.scalar(select(func.count(Inventory.id)).where(Inventory.type == "lxc", Inventory.status == "running"))

    # Count tools
    total_tools = await db.scalar(select(func.count(DiscoveredTool.id)))

    # Get finding stats
    finding_stats = await crud.get_finding_stats(db)

    # Recent scans
    recent_scans = await crud.get_recent_scan_runs(db, limit=5)

    # CVE sync status
    from vigilance.cve.sync import annotate_enabled
    cve_sync_status = annotate_enabled(await crud.get_all_sync_status(db))

    return DashboardStats(
        total_nodes=total_nodes or 0,
        total_vms=total_vms or 0,
        total_lxcs=total_lxcs or 0,
        total_tools=total_tools or 0,
        open_findings=finding_stats["by_status"].get("open", 0),
        findings_by_severity=finding_stats["by_severity"],
        findings_by_status=finding_stats["by_status"],
        open_with_fix=finding_stats["open_with_fix"],
        open_unimportant=finding_stats["open_unimportant"],
        open_with_fix_by_severity=finding_stats["open_with_fix_by_severity"],
        recent_scans=recent_scans,
        cve_sync_status=cve_sync_status,
    )