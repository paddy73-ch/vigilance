from datetime import datetime
from typing import List, Optional, Sequence
from sqlalchemy import select, func, delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from vigilance.database.models import (
    ProxmoxNode,
    Inventory,
    DiscoveredTool,
    ScanRun,
    CVEEntry,
    VulnerabilityFinding,
    Suppression,
    ToolOverride,
    CVESyncStatus,
    AppSetting,
)


# Proxmox Nodes
async def get_proxmox_nodes(db: AsyncSession) -> Sequence[ProxmoxNode]:
    result = await db.execute(select(ProxmoxNode).order_by(ProxmoxNode.name))
    return result.scalars().all()


async def get_proxmox_node(db: AsyncSession, node_id: int) -> Optional[ProxmoxNode]:
    result = await db.execute(select(ProxmoxNode).where(ProxmoxNode.id == node_id))
    return result.scalar_one_or_none()


async def get_proxmox_node_by_name(db: AsyncSession, name: str) -> Optional[ProxmoxNode]:
    result = await db.execute(select(ProxmoxNode).where(ProxmoxNode.name == name))
    return result.scalar_one_or_none()


async def create_proxmox_node(db: AsyncSession, **kwargs) -> ProxmoxNode:
    node = ProxmoxNode(**kwargs)
    db.add(node)
    await db.flush()
    return node


async def update_proxmox_node(db: AsyncSession, node_id: int, **kwargs) -> Optional[ProxmoxNode]:
    node = await get_proxmox_node(db, node_id)
    if node:
        for k, v in kwargs.items():
            setattr(node, k, v)
        node.updated_at = datetime.utcnow()
        await db.flush()
    return node


async def delete_proxmox_node(db: AsyncSession, node_id: int) -> bool:
    node = await get_proxmox_node(db, node_id)
    if node:
        await db.delete(node)
        return True
    return False


# Inventories
async def get_inventories(db: AsyncSession, node_id: Optional[int] = None) -> Sequence[Inventory]:
    stmt = select(Inventory).options(selectinload(Inventory.discovered_tools))
    if node_id:
        stmt = stmt.where(Inventory.proxmox_node_id == node_id)
    stmt = stmt.order_by(Inventory.name)
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_inventory(db: AsyncSession, inventory_id: int) -> Optional[Inventory]:
    result = await db.execute(
        select(Inventory).options(selectinload(Inventory.discovered_tools)).where(Inventory.id == inventory_id)
    )
    return result.scalar_one_or_none()


async def upsert_inventory(db: AsyncSession, **kwargs) -> Inventory:
    vmid = kwargs.get("vmid")
    node_id = kwargs.get("proxmox_node_id")
    result = await db.execute(
        select(Inventory).where(Inventory.proxmox_node_id == node_id, Inventory.vmid == vmid)
    )
    inv = result.scalar_one_or_none()
    if inv:
        for k, v in kwargs.items():
            setattr(inv, k, v)
        inv.updated_at = datetime.utcnow()
    else:
        inv = Inventory(**kwargs)
        db.add(inv)
    await db.flush()
    return inv


# Discovered Tools
async def get_discovered_tools(
    db: AsyncSession,
    inventory_id: Optional[int] = None,
    tool_name: Optional[str] = None,
    source_type: Optional[str] = None,
) -> Sequence[DiscoveredTool]:
    stmt = select(DiscoveredTool).options(selectinload(DiscoveredTool.findings))
    if inventory_id:
        stmt = stmt.where(DiscoveredTool.inventory_id == inventory_id)
    if tool_name:
        stmt = stmt.where(DiscoveredTool.tool_name == tool_name)
    if source_type:
        stmt = stmt.where(DiscoveredTool.source_type == source_type)
    stmt = stmt.order_by(DiscoveredTool.tool_name)
    result = await db.execute(stmt)
    return result.scalars().all()


async def upsert_discovered_tool(db: AsyncSession, **kwargs) -> DiscoveredTool:
    inventory_id = kwargs.get("inventory_id")
    tool_name = kwargs.get("tool_name")
    source_type = kwargs.get("source_type")
    result = await db.execute(
        select(DiscoveredTool).where(
            DiscoveredTool.inventory_id == inventory_id,
            DiscoveredTool.tool_name == tool_name,
            DiscoveredTool.source_type == source_type,
        )
    )
    tool = result.scalar_one_or_none()
    if tool:
        for k, v in kwargs.items():
            setattr(tool, k, v)
    else:
        tool = DiscoveredTool(**kwargs)
        db.add(tool)
    await db.flush()
    return tool


# Scan Runs
async def create_scan_run(db: AsyncSession, scan_type: str) -> ScanRun:
    run = ScanRun(scan_type=scan_type, status="running")
    db.add(run)
    await db.flush()
    return run


async def complete_scan_run(db: AsyncSession, run_id: int, status: str, **kwargs) -> Optional[ScanRun]:
    run = await db.get(ScanRun, run_id)
    if run:
        run.status = status
        run.completed_at = datetime.utcnow()
        for k, v in kwargs.items():
            setattr(run, k, v)
        await db.flush()
    return run


async def get_recent_scan_runs(db: AsyncSession, limit: int = 10) -> Sequence[ScanRun]:
    result = await db.execute(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit))
    return result.scalars().all()


# CVE Entries
async def upsert_cve_entry(db: AsyncSession, **kwargs) -> CVEEntry:
    cve_id = kwargs.get("cve_id")
    result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if cve:
        for k, v in kwargs.items():
            setattr(cve, k, v)
    else:
        cve = CVEEntry(**kwargs)
        db.add(cve)
    await db.flush()
    return cve


async def get_cve_entry(db: AsyncSession, cve_id: str) -> Optional[CVEEntry]:
    result = await db.execute(select(CVEEntry).where(CVEEntry.cve_id == cve_id))
    return result.scalar_one_or_none()


async def get_cve_entries(
    db: AsyncSession,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Sequence[CVEEntry]:
    stmt = select(CVEEntry).order_by(CVEEntry.fetched_at.desc()).limit(limit).offset(offset)
    if source:
        stmt = stmt.where(CVEEntry.source == source)
    if severity:
        stmt = stmt.where(CVEEntry.severity == severity)
    result = await db.execute(stmt)
    return result.scalars().all()


async def count_cve_entries(db: AsyncSession, source: Optional[str] = None) -> int:
    stmt = select(func.count(CVEEntry.id))
    if source:
        stmt = stmt.where(CVEEntry.source == source)
    result = await db.execute(stmt)
    return result.scalar_one()


# Vulnerability Findings
async def upsert_finding(db: AsyncSession, **kwargs) -> VulnerabilityFinding:
    tool_id = kwargs.get("discovered_tool_id")
    cve_id = kwargs.get("cve_entry_id")
    result = await db.execute(
        select(VulnerabilityFinding).where(
            VulnerabilityFinding.discovered_tool_id == tool_id,
            VulnerabilityFinding.cve_entry_id == cve_id,
        )
    )
    finding = result.scalar_one_or_none()
    if finding:
        for k, v in kwargs.items():
            setattr(finding, k, v)
        finding.last_seen_at = datetime.utcnow()
    else:
        finding = VulnerabilityFinding(**kwargs)
        db.add(finding)
    await db.flush()
    return finding


async def get_findings(
    db: AsyncSession,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    inventory_id: Optional[int] = None,
    tool_name: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Sequence[VulnerabilityFinding]:
    stmt = (
        select(VulnerabilityFinding)
        .options(selectinload(VulnerabilityFinding.tool).selectinload(DiscoveredTool.inventory))
        .options(selectinload(VulnerabilityFinding.cve))
        .order_by(VulnerabilityFinding.first_seen_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if status:
        stmt = stmt.where(VulnerabilityFinding.status == status)
    if inventory_id:
        stmt = stmt.where(DiscoveredTool.inventory_id == inventory_id)
    if tool_name:
        stmt = stmt.where(DiscoveredTool.tool_name == tool_name)
    if severity:
        stmt = stmt.join(CVEEntry).where(CVEEntry.severity == severity)
    result = await db.execute(stmt)
    return result.scalars().all()


async def count_findings(db: AsyncSession, status: Optional[str] = None) -> int:
    stmt = select(func.count(VulnerabilityFinding.id))
    if status:
        stmt = stmt.where(VulnerabilityFinding.status == status)
    result = await db.execute(stmt)
    return result.scalar_one()


async def count_filtered_findings(
    db: AsyncSession,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    inventory_id: Optional[int] = None,
    tool_name: Optional[str] = None,
) -> int:
    stmt = select(func.count(VulnerabilityFinding.id))
    if status:
        stmt = stmt.where(VulnerabilityFinding.status == status)
    if severity:
        stmt = stmt.join(CVEEntry).where(CVEEntry.severity == severity)
    if inventory_id or tool_name:
        stmt = stmt.join(DiscoveredTool)
        if inventory_id:
            stmt = stmt.where(DiscoveredTool.inventory_id == inventory_id)
        if tool_name:
            stmt = stmt.where(DiscoveredTool.tool_name == tool_name)
    result = await db.execute(stmt)
    return result.scalar_one()


async def get_finding_stats(db: AsyncSession) -> dict:
    # Count by status
    status_counts = {}
    for status in ["open", "fixed", "suppressed", "unknown_version"]:
        count = await count_findings(db, status)
        status_counts[status] = count

    # Count by severity
    severity_counts = {}
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        stmt = select(func.count(VulnerabilityFinding.id)).join(CVEEntry).where(
            CVEEntry.severity == severity, VulnerabilityFinding.status == "open"
        )
        result = await db.execute(stmt)
        severity_counts[severity] = result.scalar_one()

    return {"by_status": status_counts, "by_severity": severity_counts}


# Suppressions
async def get_suppressions(db: AsyncSession) -> Sequence[Suppression]:
    result = await db.execute(select(Suppression).order_by(Suppression.created_at.desc()))
    return result.scalars().all()


async def create_suppression(db: AsyncSession, **kwargs) -> Suppression:
    supp = Suppression(**kwargs)
    db.add(supp)
    await db.flush()
    return supp


async def delete_suppression(db: AsyncSession, supp_id: int) -> bool:
    supp = await db.get(Suppression, supp_id)
    if supp:
        await db.delete(supp)
        return True
    return False


async def is_suppressed(db: AsyncSession, cve_id: str, tool_name: str, inventory_id: Optional[int]) -> bool:
    stmt = select(Suppression).where(Suppression.cve_id == cve_id)
    result = await db.execute(stmt)
    suppressions = result.scalars().all()

    for s in suppressions:
        if s.expires_at and s.expires_at < datetime.utcnow():
            continue
        if s.tool_name_pattern:
            import fnmatch
            if not fnmatch.fnmatch(tool_name, s.tool_name_pattern):
                continue
        if s.inventory_id and s.inventory_id != inventory_id:
            continue
        return True
    return False


# Tool Overrides
async def get_tool_overrides(db: AsyncSession) -> Sequence[ToolOverride]:
    result = await db.execute(select(ToolOverride).order_by(ToolOverride.tool_name))
    return result.scalars().all()


async def get_tool_override(db: AsyncSession, tool_name: str) -> Optional[ToolOverride]:
    result = await db.execute(select(ToolOverride).where(ToolOverride.tool_name == tool_name))
    return result.scalar_one_or_none()


async def upsert_tool_override(db: AsyncSession, **kwargs) -> ToolOverride:
    tool_name = kwargs.get("tool_name")
    result = await db.execute(select(ToolOverride).where(ToolOverride.tool_name == tool_name))
    override = result.scalar_one_or_none()
    if override:
        for k, v in kwargs.items():
            setattr(override, k, v)
        override.updated_at = datetime.utcnow()
    else:
        override = ToolOverride(**kwargs)
        db.add(override)
    await db.flush()
    return override


async def delete_tool_override(db: AsyncSession, tool_name: str) -> bool:
    override = await get_tool_override(db, tool_name)
    if override:
        await db.delete(override)
        return True
    return False


# CVE Sync Status
async def get_sync_status(db: AsyncSession, source: str) -> Optional[CVESyncStatus]:
    result = await db.execute(select(CVESyncStatus).where(CVESyncStatus.source == source))
    return result.scalar_one_or_none()


async def update_sync_status(db: AsyncSession, source: str, **kwargs) -> CVESyncStatus:
    status = await get_sync_status(db, source)
    if not status:
        status = CVESyncStatus(source=source)
        db.add(status)
    for k, v in kwargs.items():
        setattr(status, k, v)
    await db.flush()
    return status


async def get_all_sync_status(db: AsyncSession) -> Sequence[CVESyncStatus]:
    result = await db.execute(select(CVESyncStatus))
    return result.scalars().all()


# App Settings
async def get_setting(db: AsyncSession, key: str) -> Optional[str]:
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    setting = result.scalar_one_or_none()
    return setting.value if setting else None


async def set_setting(db: AsyncSession, key: str, value: str, description: str = "") -> AppSetting:
    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    setting = result.scalar_one_or_none()
    if setting:
        setting.value = value
    else:
        setting = AppSetting(key=key, value=value, description=description)
        db.add(setting)
    await db.flush()
    return setting
