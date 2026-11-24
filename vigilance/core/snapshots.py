"""Daily totals for the trend chart."""

import json
from datetime import date, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.database.models import CVEEntry, FindingSnapshot, VulnerabilityFinding


async def write_daily_snapshot(db: AsyncSession, day: date = None) -> FindingSnapshot:
    """Store today's totals (overwrites an earlier snapshot of the same day). Does not commit."""
    day = day or datetime.utcnow().date()
    open_ = VulnerabilityFinding.status == "open"
    patchable = await db.scalar(
        select(func.count()).select_from(VulnerabilityFinding).where(open_, VulnerabilityFinding.fix_available.is_(True))
    )
    open_total = await db.scalar(select(func.count()).select_from(VulnerabilityFinding).where(open_))
    fixed_total = await db.scalar(
        select(func.count()).select_from(VulnerabilityFinding).where(VulnerabilityFinding.status == "fixed")
    )
    rows = await db.execute(
        select(CVEEntry.severity, func.count())
        .select_from(VulnerabilityFinding)
        .join(CVEEntry, CVEEntry.id == VulnerabilityFinding.cve_entry_id)
        .where(open_, VulnerabilityFinding.fix_available.is_(True))
        .group_by(CVEEntry.severity)
    )
    by_sev: dict = {}
    for sev, n in rows.all():
        key = (sev or "NONE").upper()
        by_sev[key] = by_sev.get(key, 0) + n

    snap = await db.get(FindingSnapshot, day)
    if snap is None:
        snap = FindingSnapshot(day=day)
        db.add(snap)
    snap.patchable = patchable or 0
    snap.without_fix = (open_total or 0) - (patchable or 0)
    snap.fixed_total = fixed_total or 0
    snap.patchable_by_severity = json.dumps(by_sev)
    snap.created_at = datetime.utcnow()
    await db.flush()
    return snap
