"""Aggregated read APIs for the UI (overview, hosts, packages, vulnerabilities) and exceptions.

All aggregation happens in SQL. GROUP BY only uses plain columns or COALESCE of
columns (no bound literals), so the queries behave the same on PostgreSQL and SQLite.
"""

import fnmatch
import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, case, distinct, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_current_user_optional, get_db, require_write_access
from vigilance.core.security import User
from vigilance.cve.matcher import compare_debian_versions
from vigilance.database.models import (
    CVEEntry,
    CVESyncStatus,
    DiscoveredTool,
    FindingSnapshot,
    Inventory,
    ScanRun,
    Suppression,
    VulnerabilityFinding,
)

router = APIRouter()

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
RANK_TO_SEV = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "NONE"}

F = VulnerabilityFinding
T = DiscoveredTool
C = CVEEntry
I = Inventory

SEV_RANK = case(
    (func.upper(C.severity) == "CRITICAL", 4),
    (func.upper(C.severity) == "HIGH", 3),
    (func.upper(C.severity) == "MEDIUM", 2),
    (func.upper(C.severity) == "LOW", 1),
    else_=0,
)
PKG_NAME = func.coalesce(T.source_name, T.tool_name)
PKG_VERSION = func.coalesce(T.source_version, T.detected_version)
IS_OPEN = F.status == "open"
IS_FIX = F.fix_available.is_(True)
PATCHABLE = and_(IS_OPEN, IS_FIX)


def _count_if(cond):
    return func.coalesce(func.sum(case((cond, 1), else_=0)), 0)


def _sev(rank) -> str:
    return RANK_TO_SEV.get(int(rank or 0), "NONE")


def _max_debian(versions) -> Optional[str]:
    best = None
    for v in versions:
        if not v:
            continue
        try:
            if best is None or compare_debian_versions(v, best) > 0:
                best = v
        except ValueError:
            best = best or v
    return best


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() + "Z" if dt else None


def _upstream(cve: C) -> List[str]:
    return [u for u in (cve.upstream_ids or "").split(",") if u]


def _links(cve: C) -> List[dict]:
    links = []
    cve_ids = [u for u in _upstream(cve) if u.startswith("CVE-")]
    if cve.cve_id.startswith("CVE-"):
        cve_ids.insert(0, cve.cve_id)
    if cve_ids:
        links.append({"label": "Debian Security Tracker", "url": f"https://security-tracker.debian.org/tracker/{cve_ids[0]}"})
        links.append({"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_ids[0]}"})
    if cve.source == "osv":
        links.append({"label": "OSV", "url": f"https://osv.dev/vulnerability/{cve.cve_id}"})
    if cve.source == "ghsa":
        links.append({"label": "GitHub Advisory", "url": f"https://github.com/advisories/{cve.cve_id}"})
    try:
        for ref in json.loads(cve.references or "[]")[:12]:
            url = ref.get("url") or ""
            if url.startswith(("https://", "http://")) and all(url != l["url"] for l in links):
                links.append({"label": ref.get("type") or "Link", "url": url})
    except (TypeError, ValueError):
        pass
    return links


# ---------------------------------------------------------------- obsolete packages
#
# After a release upgrade (bookworm -> trixie) old library packages often stay installed,
# e.g. libglib2.0-0 2.74 next to libglib2.0-0t64 2.84. They get no updates any more:
# the fix is to remove them, not to upgrade. A (host, source package, version) is
# considered obsolete when the same host has the same source package in a higher version.


async def obsolete_keys(db: AsyncSession, inventory_id: Optional[int] = None) -> set:
    stmt = (select(T.inventory_id, T.source_name, T.source_version)
            .where(T.source_name.is_not(None), T.removed_at.is_(None)).distinct())
    if inventory_id is not None:
        stmt = stmt.where(T.inventory_id == inventory_id)
    versions: Dict[tuple, set] = defaultdict(set)
    for inv, pkg, ver in (await db.execute(stmt)).all():
        if ver:
            versions[(inv, pkg)].add(ver)
    result = set()
    for (inv, pkg), vers in versions.items():
        if len(vers) < 2:
            continue
        newest = _max_debian(vers)
        result.update((inv, pkg, v) for v in vers if v != newest)
    return result


async def patchable_split(db: AsyncSession, inventory_id: Optional[int] = None) -> Dict[int, dict]:
    """Per host: patchable findings/packages split into 'upgrade' and 'remove' (obsolete)."""
    obsolete = await obsolete_keys(db, inventory_id)
    stmt = (
        select(T.inventory_id, PKG_NAME, PKG_VERSION, func.count(F.id))
        .select_from(F).join(T, T.id == F.discovered_tool_id)
        .where(PATCHABLE).group_by(T.inventory_id, PKG_NAME, PKG_VERSION)
    )
    if inventory_id is not None:
        stmt = stmt.where(T.inventory_id == inventory_id)
    out: Dict[int, dict] = defaultdict(lambda: {"upgrade_findings": 0, "remove_findings": 0,
                                                 "upgrade_packages": 0, "remove_packages": 0})
    for inv, pkg, ver, n in (await db.execute(stmt)).all():
        kind = "remove" if (inv, pkg, ver) in obsolete else "upgrade"
        out[inv][f"{kind}_findings"] += n
        out[inv][f"{kind}_packages"] += 1
    return out


# ---------------------------------------------------------------- hosts


def _host_level(row) -> str:
    if row["status"] != "running":
        return "stopped"
    if row["last_scan_status"] in ("unreachable", "no_ip") or (row["tools"] == 0 and row["last_scan_status"] != "ok"):
        return "unknown"
    if row["patchable_critical"] or row["patchable_high"]:
        return "critical"
    if row["patchable"]:
        return "warning"
    return "ok"


LEVEL_ORDER = {"critical": 0, "warning": 1, "unknown": 2, "ok": 3, "stopped": 4}


async def host_summaries(db: AsyncSession, inventory_id: Optional[int] = None) -> List[dict]:
    stmt = (
        select(
            I.id, I.vmid, I.name, I.type, I.status, I.ip_address, I.os_id, I.os_version_id, I.os_codename,
            I.last_scan_at, I.last_scan_status, I.last_scan_error, I.last_seen,
            func.count(distinct(case((T.removed_at.is_(None), T.id)))).label("tools"),
            _count_if(PATCHABLE).label("patchable"),
            func.count(distinct(case((PATCHABLE, PKG_NAME)))).label("patchable_packages"),
            _count_if(and_(PATCHABLE, SEV_RANK == 4)).label("patchable_critical"),
            _count_if(and_(PATCHABLE, SEV_RANK == 3)).label("patchable_high"),
            _count_if(and_(PATCHABLE, SEV_RANK == 2)).label("patchable_medium"),
            _count_if(and_(PATCHABLE, SEV_RANK <= 1)).label("patchable_low"),
            _count_if(and_(IS_OPEN, not_(IS_FIX))).label("without_fix"),
            _count_if(F.status == "suppressed").label("suppressed"),
        )
        .select_from(I)
        .outerjoin(T, T.inventory_id == I.id)
        .outerjoin(F, F.discovered_tool_id == T.id)
        .outerjoin(C, C.id == F.cve_entry_id)
        .where(I.type == "lxc")
        .group_by(I.id)
    )
    if inventory_id is not None:
        stmt = stmt.where(I.id == inventory_id)
    rows = [dict(r._mapping) for r in (await db.execute(stmt)).all()]
    split = await patchable_split(db, inventory_id)
    hosts = []
    for r in rows:
        r.update(split.get(r["id"], {"upgrade_findings": 0, "remove_findings": 0,
                                     "upgrade_packages": 0, "remove_packages": 0}))
        r["level"] = _host_level(r)
        os_name = {"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine"}.get(r["os_id"] or "", r["os_id"] or "")
        r["os"] = " ".join(x for x in [os_name, r["os_version_id"] or ""] if x) or None
        if r["os"] and r["os_codename"]:
            r["os"] += f" ({r['os_codename']})"
        for k in ("last_scan_at", "last_seen"):
            r[k] = _iso(r[k])
        hosts.append(r)
    hosts.sort(key=lambda h: (LEVEL_ORDER[h["level"]], -h["patchable_critical"], -h["patchable_high"], -h["patchable"], h["vmid"]))
    return hosts


@router.get("/hosts")
async def list_hosts(db: AsyncSession = Depends(get_db), _: Optional[User] = Depends(get_current_user_optional)):
    return await host_summaries(db)


def _finding_row(f: F, t: T, c: C) -> dict:
    details = {}
    try:
        details = json.loads(f.match_details or "{}")
    except ValueError:
        pass
    return {
        "finding_id": f.id,
        "cve_entry_id": c.id,
        "id": c.cve_id,
        "upstream": _upstream(c),
        "title": c.title,
        "severity": (c.severity or "NONE").upper(),
        "cvss": c.cvss_score,
        "status": f.status,
        "fix_available": bool(f.fix_available),
        "fixed_version": f.fixed_version,
        "urgency": f.urgency,
        "first_seen": _iso(f.first_seen_at),
        "resolved_at": _iso(f.resolved_at),
        "binaries": details.get("binaries") or [t.tool_name],
    }


@router.get("/hosts/{inventory_id}")
async def get_host(inventory_id: int, db: AsyncSession = Depends(get_db),
                   _: Optional[User] = Depends(get_current_user_optional)):
    hosts = await host_summaries(db, inventory_id)
    if not hosts:
        raise HTTPException(status_code=404, detail="Host nicht gefunden")
    host = hosts[0]
    since = datetime.utcnow() - timedelta(days=30)
    rows = (await db.execute(
        select(F, T, C)
        .join(T, T.id == F.discovered_tool_id)
        .join(C, C.id == F.cve_entry_id)
        .where(T.inventory_id == inventory_id)
        .where(or_(F.status.in_(["open", "suppressed"]), and_(F.status == "fixed", F.resolved_at >= since)))
    )).all()

    # Installed binary packages per source package + version on this host
    binaries: Dict[tuple, List[str]] = defaultdict(list)
    for name, src, ver in (await db.execute(
        select(T.tool_name, PKG_NAME, PKG_VERSION).where(T.inventory_id == inventory_id, T.removed_at.is_(None))
    )).all():
        binaries[(src, ver)].append(name)
    obsolete = await obsolete_keys(db, inventory_id)

    groups: Dict[str, Dict[tuple, dict]] = {"patchable": {}, "without_fix": {}, "suppressed": {}, "fixed": {}}
    for f, t, c in rows:
        if f.status == "open":
            bucket = "patchable" if f.fix_available else "without_fix"
        else:
            bucket = f.status
        pkg = t.source_name or t.tool_name
        key = (pkg, t.source_version or t.detected_version)
        g = groups[bucket].setdefault(key, {
            "package": pkg, "installed_version": key[1], "binaries": sorted(binaries.get(key, [t.tool_name])),
            "obsolete": (inventory_id, pkg, key[1]) in obsolete,
            "advisories": [], "max_rank": 0,
        })
        row = _finding_row(f, t, c)
        g["advisories"].append(row)
        g["max_rank"] = max(g["max_rank"], SEVERITIES[::-1].index(row["severity"]))

    def finish(bucket: str) -> List[dict]:
        out = []
        for g in groups[bucket].values():
            g["advisories"].sort(key=lambda a: (-SEVERITIES[::-1].index(a["severity"]), -(a["cvss"] or 0)))
            g["severity"] = _sev(g.pop("max_rank"))
            g["fixed_version"] = _max_debian(a["fixed_version"] for a in g["advisories"])
            g["count"] = len(g["advisories"])
            out.append(g)
        out.sort(key=lambda g: (-SEVERITIES[::-1].index(g["severity"]), -g["count"], g["package"]))
        return out

    patchable = finish("patchable")
    upgrade = sorted({b for g in patchable if not g["obsolete"] for b in g["binaries"]})
    remove = sorted({b for g in patchable if g["obsolete"] for b in g["binaries"]})
    return {
        **host,
        "patchable_list": patchable,
        "without_fix_list": finish("without_fix"),
        "suppressed_list": finish("suppressed"),
        "fixed_list": finish("fixed"),
        "upgrade_command": f"apt-get update && apt-get install --only-upgrade {' '.join(upgrade)}" if upgrade else None,
        # Simulation first (-s): shows what else would be removed before anything happens
        "remove_command": f"apt-get -s purge {' '.join(remove)}" if remove else None,
    }


# ---------------------------------------------------------------- overview


@router.get("/overview")
async def overview(db: AsyncSession = Depends(get_db), _: Optional[User] = Depends(get_current_user_optional)):
    from vigilance.cve.sync import annotate_enabled

    now = datetime.utcnow()
    kpi = (await db.execute(
        select(
            _count_if(PATCHABLE).label("patchable"),
            _count_if(and_(PATCHABLE, SEV_RANK >= 3)).label("patchable_crit_high"),
            _count_if(and_(IS_OPEN, not_(IS_FIX))).label("without_fix"),
            _count_if(and_(IS_OPEN, not_(IS_FIX), F.urgency == "unimportant")).label("without_fix_unimportant"),
            _count_if(and_(F.status == "fixed", F.resolved_at >= now - timedelta(days=7))).label("fixed_7d"),
            _count_if(F.status == "suppressed").label("suppressed"),
        ).select_from(F).join(C, C.id == F.cve_entry_id)
    )).one()._mapping

    top = (await db.execute(
        select(
            PKG_NAME.label("package"),
            PKG_VERSION.label("version"),
            func.max(SEV_RANK).label("rank"),
            func.count(distinct(F.cve_entry_id)).label("advisories"),
            func.count(distinct(T.inventory_id)).label("hosts"),
        )
        .select_from(F).join(T, T.id == F.discovered_tool_id).join(C, C.id == F.cve_entry_id)
        .where(PATCHABLE)
        .group_by(PKG_NAME, PKG_VERSION)
        .order_by(func.max(SEV_RANK).desc(), func.count(distinct(T.inventory_id)).desc(),
                  func.count(distinct(F.cve_entry_id)).desc(), PKG_NAME)
        .limit(8)
    )).all()
    obsolete_all = await obsolete_keys(db)
    obsolete_pkgs = {(p, v) for _, p, v in obsolete_all}

    last_scan = (await db.execute(
        select(ScanRun).where(ScanRun.scan_type != "cve_sync").order_by(ScanRun.started_at.desc()).limit(1)
    )).scalar_one_or_none()
    sources = [s for s in annotate_enabled((await db.execute(select(CVESyncStatus))).scalars().all()) if s.enabled]
    snaps = (await db.execute(
        select(FindingSnapshot).where(FindingSnapshot.day >= (now - timedelta(days=30)).date()).order_by(FindingSnapshot.day)
    )).scalars().all()
    hosts = await host_summaries(db)

    kpis = dict(kpi)
    kpis["patchable_upgrade"] = sum(h["upgrade_findings"] for h in hosts)
    kpis["patchable_remove"] = sum(h["remove_findings"] for h in hosts)
    return {
        "kpis": kpis,
        "hosts": hosts,
        "hosts_needing_attention": sum(1 for h in hosts if h["level"] in ("critical", "warning")),
        "hosts_unknown": sum(1 for h in hosts if h["level"] == "unknown"),
        "top_packages": [
            {"package": r.package, "version": r.version, "severity": _sev(r.rank), "advisories": r.advisories,
             "hosts": r.hosts, "action": "remove" if (r.package, r.version) in obsolete_pkgs else "upgrade"}
            for r in top
        ],
        "last_scan": None if not last_scan else {
            "id": last_scan.id, "status": last_scan.status, "started_at": _iso(last_scan.started_at),
            "completed_at": _iso(last_scan.completed_at), "error": last_scan.error_message,
            "hosts": last_scan.nodes_scanned, "packages": last_scan.tools_found,
        },
        "sources": [
            {"source": s.source, "status": s.status, "last_success_at": _iso(s.last_success_at),
             "last_sync_at": _iso(s.last_sync_at), "message": s.error_message, "entries": s.entries_count}
            for s in sources
        ],
        "trend": [
            {"day": s.day.isoformat(), "patchable": s.patchable, "without_fix": s.without_fix, "fixed_total": s.fixed_total}
            for s in snaps
        ],
        "generated_at": _iso(now),
    }


# ---------------------------------------------------------------- packages / vulnerabilities


def _filters(stmt, status: str, fix: Optional[bool], hide_unimportant: bool, severity: Optional[str],
             host_id: Optional[int], q: Optional[str]):
    if status and status != "all":
        stmt = stmt.where(F.status == status)
    if fix is True:
        stmt = stmt.where(IS_FIX)
    elif fix is False:
        stmt = stmt.where(not_(IS_FIX))
    if hide_unimportant:
        stmt = stmt.where(or_(F.urgency.is_(None), F.urgency != "unimportant"))
    if severity:
        wanted = [s.strip().upper() for s in severity.split(",") if s.strip().upper() in SEVERITIES]
        if wanted:
            conds = [func.upper(C.severity).in_([w for w in wanted if w != "NONE"])]
            if "NONE" in wanted:
                conds.append(or_(C.severity.is_(None), func.upper(C.severity) == "NONE"))
            stmt = stmt.where(or_(*conds))
    if host_id:
        stmt = stmt.where(T.inventory_id == host_id)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            T.tool_name.ilike(like), T.source_name.ilike(like), C.cve_id.ilike(like),
            C.upstream_ids.ilike(like), C.title.ilike(like),
        ))
    return stmt


def _base():
    return (select().select_from(F).join(T, T.id == F.discovered_tool_id)
            .join(C, C.id == F.cve_entry_id).join(I, I.id == T.inventory_id))


@router.get("/packages")
async def list_packages(
    status: str = Query("open"),
    fix: Optional[bool] = Query(None),
    hide_unimportant: bool = Query(False),
    severity: Optional[str] = Query(None, description="Komma-getrennt, z. B. CRITICAL,HIGH"),
    host_id: Optional[int] = Query(None),
    q: Optional[str] = Query(None),
    sort: str = Query("severity", pattern="^(severity|hosts|advisories|name)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: Optional[User] = Depends(get_current_user_optional),
):
    """Findings grouped by source package and version."""
    rank = func.max(SEV_RANK)
    hosts_n = func.count(distinct(T.inventory_id))
    adv_n = func.count(distinct(F.cve_entry_id))
    grouped = _filters(
        _base().add_columns(
            PKG_NAME.label("package"), PKG_VERSION.label("version"), rank.label("rank"),
            hosts_n.label("hosts"), adv_n.label("advisories"),
            func.max(case((IS_FIX, 1), else_=0)).label("fix_available"),
            func.max(C.cvss_score).label("max_cvss"),
        ),
        status, fix, hide_unimportant, severity, host_id, q,
    ).group_by(PKG_NAME, PKG_VERSION)
    order = {
        "severity": [rank.desc(), hosts_n.desc(), adv_n.desc()],
        "hosts": [hosts_n.desc(), rank.desc()],
        "advisories": [adv_n.desc(), rank.desc()],
        "name": [],
    }[sort] + [PKG_NAME, PKG_VERSION]
    total = await db.scalar(select(func.count()).select_from(grouped.subquery()))
    rows = (await db.execute(grouped.order_by(*order).limit(limit).offset(offset))).all()

    # Host names and fix versions for the packages on this page
    keys = [(r.package, r.version) for r in rows]
    detail: Dict[tuple, dict] = {k: {"hosts": set(), "fixes": set(), "binaries": set()} for k in keys}
    if keys:
        extra = _filters(
            _base().add_columns(PKG_NAME, PKG_VERSION, I.id, I.name, F.fixed_version, F.match_details, T.tool_name),
            status, fix, hide_unimportant, severity, host_id, q,
        ).where(PKG_NAME.in_({k[0] for k in keys}))
        for pkg, ver, inv_id, inv_name, fixed, md, tname in (await db.execute(extra)).all():
            d = detail.get((pkg, ver))
            if d is None:
                continue
            d["hosts"].add((inv_id, inv_name))
            if fixed:
                d["fixes"].add(fixed)
            try:
                d["binaries"].update(json.loads(md or "{}").get("binaries") or [tname])
            except ValueError:
                d["binaries"].add(tname)
    obsolete_all = await obsolete_keys(db)
    items = []
    for r in rows:
        d = detail[(r.package, r.version)]
        is_obsolete = bool(d["hosts"]) and all((h[0], r.package, r.version) in obsolete_all for h in d["hosts"])
        items.append({
            "package": r.package, "version": r.version, "severity": _sev(r.rank), "max_cvss": r.max_cvss,
            "hosts": r.hosts, "advisories": r.advisories, "fix_available": bool(r.fix_available),
            "fixed_version": _max_debian(d["fixes"]),
            "host_list": [{"id": i, "name": n} for i, n in sorted(d["hosts"], key=lambda h: h[1])],
            "binaries": sorted(d["binaries"]),
            "action": "remove" if is_obsolete else "upgrade",
        })
    return {"total": total or 0, "items": items, "limit": limit, "offset": offset}


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    status: str = Query("open"),
    fix: Optional[bool] = Query(None),
    hide_unimportant: bool = Query(False),
    severity: Optional[str] = Query(None),
    host_id: Optional[int] = Query(None),
    q: Optional[str] = Query(None),
    package: Optional[str] = Query(None),
    version: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: Optional[User] = Depends(get_current_user_optional),
):
    """Findings grouped by advisory."""
    stmt = _filters(
        _base().add_columns(
            C.id, C.cve_id, C.upstream_ids, C.title, C.severity, C.cvss_score,
            func.count(distinct(T.inventory_id)).label("hosts"),
            func.count(distinct(PKG_NAME)).label("packages"),
            func.max(case((IS_FIX, 1), else_=0)).label("fix_available"),
            func.max(F.fixed_version).label("fixed_version"),
            func.max(F.urgency).label("urgency"),
            func.max(PKG_NAME).label("package"),
        ),
        status, fix, hide_unimportant, severity, host_id, q,
    )
    if package:
        stmt = stmt.where(PKG_NAME == package)
    if version:
        stmt = stmt.where(PKG_VERSION == version)
    stmt = stmt.group_by(C.id, C.cve_id, C.upstream_ids, C.title, C.severity, C.cvss_score)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = (await db.execute(
        stmt.order_by(func.max(SEV_RANK).desc(), C.cvss_score.desc().nulls_last(), C.cve_id).limit(limit).offset(offset)
    )).all()
    return {
        "total": total or 0, "limit": limit, "offset": offset,
        "items": [{
            "cve_entry_id": r.id, "id": r.cve_id, "upstream": [u for u in (r.upstream_ids or "").split(",") if u],
            "title": r.title, "severity": (r.severity or "NONE").upper(), "cvss": r.cvss_score,
            "hosts": r.hosts, "packages": r.packages, "package": r.package, "fix_available": bool(r.fix_available),
            "fixed_version": r.fixed_version, "urgency": r.urgency,
        } for r in rows],
    }


@router.get("/vulnerabilities/{cve_entry_id}")
async def get_vulnerability(cve_entry_id: int, db: AsyncSession = Depends(get_db),
                            _: Optional[User] = Depends(get_current_user_optional)):
    cve = await db.get(C, cve_entry_id)
    if not cve:
        raise HTTPException(status_code=404, detail="Eintrag nicht gefunden")
    rows = (await db.execute(
        select(F, T, I).join(T, T.id == F.discovered_tool_id).join(I, I.id == T.inventory_id)
        .where(F.cve_entry_id == cve_entry_id).order_by(I.name)
    )).all()
    exceptions = (await db.execute(select(Suppression).where(Suppression.cve_id == cve.cve_id))).scalars().all()
    host_names = {i.id: i.name for _, _, i in rows}
    return {
        "cve_entry_id": cve.id, "id": cve.cve_id, "source": cve.source, "upstream": _upstream(cve),
        "title": cve.title, "description": cve.description, "severity": (cve.severity or "NONE").upper(),
        "cvss": cve.cvss_score, "cvss_vector": cve.cvss_vector,
        "published_at": _iso(cve.published_at), "modified_at": _iso(cve.modified_at),
        "links": _links(cve),
        "affected": [{
            **{k: v for k, v in _finding_row(f, t, cve).items() if k in (
                "finding_id", "status", "fix_available", "fixed_version", "urgency", "first_seen", "resolved_at", "binaries")},
            "host_id": i.id, "host": i.name, "package": t.source_name or t.tool_name,
            "installed_version": t.source_version or t.detected_version,
        } for f, t, i in rows],
        "exceptions": [_exception_dict(s, host_names.get(s.inventory_id)) for s in exceptions],
    }


# ---------------------------------------------------------------- exceptions (suppressions)


class ExceptionCreate(BaseModel):
    cve_id: str = Field(..., min_length=3, max_length=64, description="Advisory-ID, z. B. DEBIAN-CVE-2026-1234")
    inventory_id: Optional[int] = Field(None, description="Nur für diesen Host; leer = alle Hosts")
    reason: str = Field(..., min_length=3, max_length=2000)
    expires_at: Optional[datetime] = None


def _exception_dict(s: Suppression, host: Optional[str] = None) -> dict:
    return {
        "id": s.id, "cve_id": s.cve_id, "inventory_id": s.inventory_id, "host": host,
        "tool_name_pattern": s.tool_name_pattern, "reason": s.reason, "expires_at": _iso(s.expires_at),
        "expired": bool(s.expires_at and s.expires_at < datetime.utcnow()),
        "created_by": s.created_by, "created_at": _iso(s.created_at),
    }


def _matches(s: Suppression, tool: T, now: datetime) -> bool:
    if s.expires_at and s.expires_at < now:
        return False
    if s.inventory_id and s.inventory_id != tool.inventory_id:
        return False
    if s.tool_name_pattern and not fnmatch.fnmatch(tool.tool_name, s.tool_name_pattern):
        return False
    return True


async def _reapply(db: AsyncSession, cve_id: str) -> int:
    """Set open/suppressed status of the findings of one advisory according to the current exceptions."""
    now = datetime.utcnow()
    sups = (await db.execute(select(Suppression).where(Suppression.cve_id == cve_id))).scalars().all()
    rows = (await db.execute(
        select(F, T).join(T, T.id == F.discovered_tool_id).join(C, C.id == F.cve_entry_id)
        .where(C.cve_id == cve_id, F.status.in_(["open", "suppressed"]))
    )).all()
    changed = 0
    for f, t in rows:
        new = "suppressed" if any(_matches(s, t, now) for s in sups) else "open"
        if f.status != new:
            f.status = new
            changed += 1
    return changed


@router.get("/exceptions")
async def list_exceptions(db: AsyncSession = Depends(get_db), _: Optional[User] = Depends(get_current_user_optional)):
    rows = (await db.execute(
        select(Suppression, I.name).outerjoin(I, I.id == Suppression.inventory_id).order_by(Suppression.created_at.desc())
    )).all()
    counts = dict((await db.execute(
        select(C.cve_id, func.count(F.id)).join(F, F.cve_entry_id == C.id)
        .where(F.status == "suppressed").group_by(C.cve_id)
    )).all())
    return [{**_exception_dict(s, host), "suppressed_findings": counts.get(s.cve_id, 0)} for s, host in rows]


@router.post("/exceptions")
async def create_exception(body: ExceptionCreate, db: AsyncSession = Depends(get_db),
                           user: User = Depends(require_write_access)):
    if not await db.scalar(select(func.count()).select_from(C).where(C.cve_id == body.cve_id)):
        raise HTTPException(status_code=404, detail="Unbekannte Advisory-ID")
    if body.inventory_id and not await db.get(I, body.inventory_id):
        raise HTTPException(status_code=404, detail="Host nicht gefunden")
    expires = body.expires_at.replace(tzinfo=None) if body.expires_at else None
    s = Suppression(cve_id=body.cve_id, inventory_id=body.inventory_id, reason=body.reason.strip(),
                    expires_at=expires, created_by=user.username)
    db.add(s)
    await db.flush()
    changed = await _reapply(db, body.cve_id)
    await db.commit()
    return {**_exception_dict(s), "changed_findings": changed}


@router.delete("/exceptions/{exception_id}")
async def delete_exception(exception_id: int, db: AsyncSession = Depends(get_db),
                           _: User = Depends(require_write_access)):
    s = await db.get(Suppression, exception_id)
    if not s:
        raise HTTPException(status_code=404, detail="Ausnahme nicht gefunden")
    cve_id = s.cve_id
    await db.delete(s)
    await db.flush()
    changed = await _reapply(db, cve_id)
    await db.commit()
    return {"deleted": exception_id, "changed_findings": changed}
