"""Aggregated read APIs for the UI (overview, hosts, packages, vulnerabilities) and exceptions.

All aggregation happens in SQL. GROUP BY only uses plain columns or COALESCE of
columns (no bound literals), so the queries behave the same on PostgreSQL and SQLite.
"""

import fnmatch
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, case, distinct, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_current_user_optional, get_db, require_write_access
from vigilance.config import configured_vm_ids
from vigilance.cve.advisories import merge_advisories, same_vulnerability, vuln_key
from vigilance.cve.platforms import os_hint, os_label
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
    if cve.source == "tailscale":
        links.append({"label": "Tailscale Security Bulletin", "url": f"https://tailscale.com/security-bulletins/#{cve.cve_id.lower()}"})
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


# ---------------------------------------------------------------- remediation


def kernel_section(inv) -> Optional[dict]:
    """Kernel packages inside a container (from the scan's kernel check), with the cleanup command."""
    if not inv or inv.type != "lxc":
        return None
    from vigilance.actions.runner import kernel_command, kernel_info

    info = kernel_info(inv)
    if not info:
        return None
    return {**info, "command": kernel_command(info),
            "installed": [p["name"] for p in info["packages"] if p["status"] != "rc"],
            "remnants": [p["name"] for p in info["packages"] if p["status"] == "rc"]}


async def kernel_hosts(db: AsyncSession) -> List[dict]:
    """Running containers with kernel packages (never loaded in an LXC), for the overview."""
    rows = (await db.execute(
        select(I).where(I.type == "lxc", I.status == "running", I.removal_check.isnot(None)).order_by(I.vmid)
    )).scalars().all()
    out = []
    for inv in rows:
        k = kernel_section(inv)
        if k:
            out.append({"id": inv.id, "name": inv.name, "vmid": inv.vmid, "installed": len(k["installed"]),
                        "remnants": len(k["remnants"]), "extra": k.get("extra") or []})
    return out


def upgrade_command(binaries: List[str]) -> str:
    return "apt-get update && apt-get install --only-upgrade " + " ".join(sorted(binaries))


def remove_command(binaries: List[str]) -> str:
    return "apt-get purge " + " ".join(sorted(binaries))


async def newer_versions(db: AsyncSession, pairs: set) -> Dict[tuple, dict]:
    """For (inventory_id, source package) pairs: newest installed version and its binary packages.

    For an obsolete package this is what replaced it (libapt-pkg7.0 3.0.4 for libapt-pkg6.0 2.6.1).
    """
    if not pairs:
        return {}
    rows = (await db.execute(
        select(T.inventory_id, T.source_name, T.source_version, T.tool_name, T.detected_version)
        .where(T.inventory_id.in_({p[0] for p in pairs}), T.source_name.in_({p[1] for p in pairs}),
               T.removed_at.is_(None))
    )).all()
    versions: Dict[tuple, Dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for inv, src, sver, name, ver in rows:
        if (inv, src) in pairs and sver:
            versions[(inv, src)][sver].append((name, ver))
    out = {}
    for key, by_ver in versions.items():
        newest = _max_debian(by_ver)
        out[key] = {"version": newest, "packages": [f"{n} {v}" for n, v in sorted(by_ver[newest])]}
    return out


_DISTRO_URL = re.compile(r"(^|[/.])(debian\.org|ubuntu\.com)(/|$)")


def foreign_sources(check_json: Optional[str], tools: Dict[str, str]) -> List[dict]:
    """Installed packages from package sources other than Debian/Ubuntu, grouped by source.

    tools: {package name: installed version}. Three groups per source:
    covered    - checked through the Go vulnerability data (VENDOR_GO_MODULES)
    debian     - Debian/Ubuntu have a package of that name, so the Debian data is used; the
                 installed version is a build from this source, so results may be inexact
    uncovered  - no security data at all (e.g. pve-manager, docker-ce)
    """
    from vigilance.cve.ecosystems import vendor_go_module

    try:
        check = json.loads(check_json or "null") or {}
    except ValueError:
        return []
    origins = check.get("origins") or {}
    distro_also = set(check.get("distro_also") or [])
    groups: Dict[str, dict] = {}
    for pkg, urls in origins.items():
        if any(_DISTRO_URL.search(u) for u in urls):
            continue
        url = urls[0]
        host = url.split("://", 1)[-1].split("/", 1)[0]
        g = groups.setdefault(host, {"source": host, "url": url, "covered": [], "debian": [], "uncovered": []})
        vendor = vendor_go_module(pkg, tools.get(pkg))
        if vendor:
            g["covered"].append({"package": pkg, "module": vendor[0]})
        elif pkg in distro_also:
            g["debian"].append(pkg)
        else:
            g["uncovered"].append(pkg)
    for g in groups.values():
        g["uncovered"].sort()
        g["debian"].sort()
    return sorted(groups.values(), key=lambda g: (-len(g["uncovered"]), g["source"]))


def upgrade_availability(check_json: Optional[str], binaries: List[str], fixed: Optional[str]) -> dict:
    """Does the host's package source offer the fix? From the scan's `apt list --upgradable`.

    status: "available" (all packages have a candidate >= fix), "partial" (some do),
            "older" (newer versions exist, but below the fix), "missing" (no candidate at all),
            "unknown" (not checked yet).
    """
    try:
        check = json.loads(check_json or "null")
    except ValueError:
        check = None
    if not check:
        return {"status": "unknown", "lists_at": None, "installable": list(binaries), "candidates": {}}
    cands = check.get("candidates") or {}
    states = {}
    for b in binaries:
        c = cands.get(b)
        if c is None:
            states[b] = "missing"
            continue
        try:
            states[b] = "ok" if not fixed or compare_debian_versions(c, fixed) >= 0 else "older"
        except ValueError:
            states[b] = "ok"
    values = set(states.values())
    if values == {"ok"}:
        status = "available"
    elif "ok" in values:
        status = "partial"
    elif "older" in values:
        status = "older"
    else:
        status = "missing"
    return {"status": status, "lists_at": check.get("lists_at"),
            # only candidates at or above the fix: a newer version below the fix would not close the gap
            "installable": [b for b in binaries if states[b] == "ok"],
            "older": [b for b in binaries if states[b] == "older"],
            "candidates": {b: cands[b] for b in binaries if b in cands}}


_KERNEL_RE = re.compile(r"(linux-image|proxmox-kernel|pve-kernel)-\d")
_STEM_RE = re.compile(r"[a-z][a-z+.-]*?(?=[-.]?\d|$)")


def successors(replacement: Optional[dict], binaries: List[str]) -> Optional[dict]:
    """Keep only the packages that replace these binaries: libapt-pkg6.0 -> libapt-pkg7.0, not apt-utils.

    Matches on the name stem before the first digit (libapt-pkg, libglib, linux-image). If nothing
    matches, the full list of the newer version is kept.
    """
    if not replacement:
        return None
    stems = {m.group(0) for b in binaries if (m := _STEM_RE.match(b))}
    picked = [p for p in replacement["packages"] if any(p.split(" ")[0].startswith(st) for st in stems)]
    return {**replacement, "packages": picked or replacement["packages"]}


def removal_risk(check_json: Optional[str], binaries: List[str]) -> dict:
    """Summarise the scan's read-only removal check (discovery/removal.py) for these packages.

    status: "ok" (simulation removes only obsolete packages, nothing uses them),
            "check" (something else would be removed, or something still uses them),
            "unknown" (not checked yet or the check failed).
    """
    try:
        check = json.loads(check_json or "{}")
    except ValueError:
        check = {}
    checked = check.get("packages") or {}
    risk = {"status": "unknown", "checked_at": check.get("checked_at"), "would_remove": [], "extra": [],
            "in_use": [], "external": [], "errors": [], "not_reinstallable": [], "libraries_checked": False,
            "process_check_limited": check.get("root") is False, "running_kernel": [], "kernel": False}
    if check.get("error"):
        risk["errors"].append(check["error"])
    missing = [b for b in binaries if b not in checked]
    if not checked or missing:
        return risk
    obsolete_on_host = set(checked)
    for b in binaries:
        r = checked[b]
        for pkg in r.get("would_remove") or []:
            if pkg not in risk["would_remove"]:
                risk["would_remove"].append(pkg)
            if pkg not in obsolete_on_host and pkg not in risk["extra"]:
                risk["extra"].append(pkg)
        risk["in_use"] += [{**u, "package": b} for u in r.get("in_use") or []]
        risk["external"] += [x for x in r.get("external") or [] if x not in risk["external"]]
        if r.get("error"):
            risk["errors"].append(f"{b}: {r['error']}")
        if r.get("reinstallable") is False:
            risk["not_reinstallable"].append(b)
        if r.get("libraries"):
            risk["libraries_checked"] = True
        if _KERNEL_RE.match(b):
            risk["kernel"] = True
            if check.get("kernel") and check["kernel"] in b:
                risk["running_kernel"].append(b)
    if risk["errors"]:
        return risk
    risk["status"] = "check" if (risk["extra"] or risk["in_use"] or risk["external"] or risk["running_kernel"]) else "ok"
    return risk


# ---------------------------------------------------------------- hosts


def _host_level(row) -> str:
    if row["status"] != "running":
        return "stopped"
    if row["type"] == "qemu" and row["vmid"] not in configured_vm_ids():
        return "not_scanned"  # running VM that is not switched on for scanning
    if row["last_scan_status"] in ("unreachable", "no_ip") or (row["tools"] == 0 and row["last_scan_status"] != "ok"):
        return "unknown"
    if row["patchable_critical"] or row["patchable_high"]:
        return "critical"
    if row["patchable"]:
        return "warning"
    return "ok"


LEVEL_ORDER = {"critical": 0, "warning": 1, "unknown": 2, "ok": 3, "not_scanned": 4, "stopped": 5}


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
        .where(I.type.in_(["lxc", "qemu", "node"]))
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
        r["scan_configured"] = r["type"] != "qemu" or r["vmid"] in configured_vm_ids()
        if r["type"] == "qemu":
            from vigilance.core.runtime_settings import VM_SCAN_OVERRIDES
            r["scan_origin"] = "ui" if r["vmid"] in VM_SCAN_OVERRIDES else "config"
            r["scan_ip"] = (VM_SCAN_OVERRIDES.get(r["vmid"]) or {}).get("ip")
        os_name = {"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine", "windows": "Windows"}.get(r["os_id"] or "", r["os_id"] or "")
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


def source_note(source: Optional[str], title: Optional[str], description: Optional[str]) -> Optional[str]:
    """Limitation shown as (i) next to findings of sources whose data is less precise."""
    if source == "tailscale":
        from vigilance.cve.tailscale import limitation_note
        return limitation_note(title, description)
    return None


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
        # filtered: the advisory data restricts it to other systems; hint: only the title says so
        "only_on": [os_label(g) for g in details.get("goos") or []],
        "os_hint": os_hint(c.title, (c.description or "")[:300]),
        "note": source_note(c.source, c.title, c.description),
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
        .where(or_(F.status.in_(["open", "suppressed", "not_affected"]), and_(F.status == "fixed", F.resolved_at >= since)))
    )).all()

    # Installed binary packages per source package + version on this host
    binaries: Dict[tuple, List[str]] = defaultdict(list)
    for name, src, ver in (await db.execute(
        select(T.tool_name, PKG_NAME, PKG_VERSION).where(T.inventory_id == inventory_id, T.removed_at.is_(None))
    )).all():
        binaries[(src, ver)].append(name)
    obsolete = await obsolete_keys(db, inventory_id)

    groups: Dict[str, Dict[tuple, dict]] = {"patchable": {}, "without_fix": {}, "suppressed": {}, "fixed": {},
                                            "not_affected": {}}
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
            g["fixed_version"] = _max_debian(a["fixed_version"] for a in g["advisories"])
            g["advisories"] = merge_advisories(g["advisories"], max_fields=("cvss",))
            g["advisories"].sort(key=lambda a: (-SEVERITIES[::-1].index(a["severity"]), -(a["cvss"] or 0), a["label"]))
            g["severity"] = _sev(g.pop("max_rank"))
            g["count"] = len(g["advisories"])
            g["findings"] = sum(1 + len(a["also"]) for a in g["advisories"])
            # Obsolete libraries are named by the installed package (libapt-pkg6.0), not by the source (apt)
            g["display_name"] = ", ".join(g["binaries"]) if g["obsolete"] else g["package"]
            out.append(g)
        out.sort(key=lambda g: (-SEVERITIES[::-1].index(g["severity"]), -g["count"], g["package"]))
        return out

    patchable = finish("patchable")
    inv = await db.get(I, inventory_id)
    newer = await newer_versions(db, {(inventory_id, g["package"]) for g in patchable if g["obsolete"]})
    for g in patchable:
        if g["obsolete"]:
            g["remedy"] = {
                "action": "remove",
                "command": remove_command(g["binaries"]),
                "replacement": successors(newer.get((inventory_id, g["package"])), g["binaries"]),
                "risk": removal_risk(inv.removal_check if inv else None, g["binaries"]),
            }
        else:
            avail = upgrade_availability(inv.upgrade_check if inv else None, g["binaries"], g["fixed_version"])
            g["remedy"] = {"action": "upgrade", "target": g["fixed_version"], "availability": avail,
                           "command": upgrade_command(avail["installable"]) if avail["installable"] else None}
    upgrade = sorted({b for g in patchable if not g["obsolete"]
                      for b in g["remedy"]["availability"]["installable"]})
    remove = sorted({b for g in patchable if g["obsolete"] for b in g["binaries"]})
    return {
        **host,
        "patchable_list": patchable,
        "without_fix_list": finish("without_fix"),
        "suppressed_list": finish("suppressed"),
        "fixed_list": finish("fixed"),
        "not_affected_list": finish("not_affected"),
        "upgrade_command": upgrade_command(upgrade) if upgrade else None,
        "remove_command": remove_command(remove) if remove else None,
        "remove_simulation": f"apt-get -s purge {' '.join(remove)}" if remove else None,
        "remove_risk": removal_risk(inv.removal_check if inv else None, remove) if remove else None,
        "kernel": kernel_section(inv),
        "foreign_sources": foreign_sources(inv.upgrade_check if inv else None, {
            n: v for n, v in (await db.execute(
                select(T.tool_name, T.detected_version).where(T.inventory_id == inventory_id, T.removed_at.is_(None))
            )).all()}),
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
    # Count vulnerabilities, not advisories, and name obsolete libraries by their installed package
    top_detail: Dict[tuple, dict] = {(r.package, r.version): {"adv": {}, "bins": set(), "hosts": set()} for r in top}
    if top:
        for pkg, ver, adv, up, tname, inv_id in (await db.execute(
            select(PKG_NAME, PKG_VERSION, C.cve_id, C.upstream_ids, T.tool_name, T.inventory_id)
            .select_from(F).join(T, T.id == F.discovered_tool_id).join(C, C.id == F.cve_entry_id)
            .where(PATCHABLE, PKG_NAME.in_({r.package for r in top}))
        )).all():
            d = top_detail.get((pkg, ver))
            if d is not None:
                d["adv"][adv] = {"id": adv, "upstream": [u for u in (up or "").split(",") if u]}
                d["bins"].add(tname)
                d["hosts"].add(inv_id)

    last_scan = (await db.execute(
        select(ScanRun).where(ScanRun.scan_type != "cve_sync").order_by(ScanRun.started_at.desc()).limit(1)
    )).scalar_one_or_none()
    sources = [s for s in annotate_enabled((await db.execute(select(CVESyncStatus))).scalars().all()) if s.enabled]
    snaps = (await db.execute(
        select(FindingSnapshot).where(FindingSnapshot.day >= (now - timedelta(days=30)).date()).order_by(FindingSnapshot.day)
    )).scalars().all()
    hosts = [h for h in await host_summaries(db) if h["level"] != "not_scanned"]  # shown on the Hosts page only

    kpis = dict(kpi)
    kpis["patchable_upgrade"] = sum(h["upgrade_findings"] for h in hosts)
    kpis["patchable_remove"] = sum(h["remove_findings"] for h in hosts)
    return {
        "kpis": kpis,
        "hosts": hosts,
        "hosts_needing_attention": sum(1 for h in hosts if h["level"] in ("critical", "warning")),
        "hosts_unknown": sum(1 for h in hosts if h["level"] == "unknown"),
        "kernels": await kernel_hosts(db),
        "top_packages": [
            {"package": r.package, "version": r.version, "severity": _sev(r.rank),
             "advisories": len(merge_advisories(top_detail[(r.package, r.version)]["adv"].values())),
             "hosts": r.hosts, "host_ids": sorted(top_detail[(r.package, r.version)]["hosts"]), "action": "remove" if (r.package, r.version) in obsolete_pkgs else "upgrade",
             "display_name": (", ".join(sorted(top_detail[(r.package, r.version)]["bins"]))
                              if (r.package, r.version) in obsolete_pkgs else r.package)}
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
    elif status == "all":
        stmt = stmt.where(F.status != "source_off")  # findings of switched-off sources stay hidden
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

    # Host names, fix versions, binaries and advisories for the packages on this page
    keys = [(r.package, r.version) for r in rows]
    detail: Dict[tuple, dict] = {k: {"hosts": set(), "fixes": set(), "binaries": defaultdict(set), "advisories": {}}
                                 for k in keys}
    if keys:
        extra = _filters(
            _base().add_columns(PKG_NAME, PKG_VERSION, I.id, I.name, F.fixed_version, F.match_details, T.tool_name,
                                C.cve_id, C.upstream_ids),
            status, fix, hide_unimportant, severity, host_id, q,
        ).where(PKG_NAME.in_({k[0] for k in keys}))
        for pkg, ver, inv_id, inv_name, fixed, md, tname, adv, upstream in (await db.execute(extra)).all():
            d = detail.get((pkg, ver))
            if d is None:
                continue
            d["hosts"].add((inv_id, inv_name))
            if fixed:
                d["fixes"].add(fixed)
            d["advisories"][adv] = {"id": adv, "upstream": [u for u in (upstream or "").split(",") if u]}
            try:
                d["binaries"][inv_id].update(json.loads(md or "{}").get("binaries") or [tname])
            except ValueError:
                d["binaries"][inv_id].add(tname)
    obsolete_all = await obsolete_keys(db)
    remove_pairs = {(h[0], r.package) for r in rows for h in detail[(r.package, r.version)]["hosts"]
                    if (h[0], r.package, r.version) in obsolete_all}
    newer = await newer_versions(db, remove_pairs)
    host_ids = {h[0] for r in rows for h in detail[(r.package, r.version)]["hosts"]}
    checks, upgrades = {}, {}
    if host_ids:
        for i, rc, uc in (await db.execute(
            select(I.id, I.removal_check, I.upgrade_check).where(I.id.in_(host_ids))
        )).all():
            checks[i], upgrades[i] = rc, uc
    items = []
    for r in rows:
        d = detail[(r.package, r.version)]
        hosts = sorted(d["hosts"], key=lambda h: h[1])
        binaries = sorted({b for bs in d["binaries"].values() for b in bs})
        is_obsolete = bool(hosts) and all((h[0], r.package, r.version) in obsolete_all for h in hosts)
        fixed = _max_debian(d["fixes"])
        if not r.fix_available:
            remedy = {"action": "none"}
        elif is_obsolete:
            remedy = {"action": "remove", "hosts": [{
                "host_id": i, "host": n,
                "command": remove_command(sorted(d["binaries"][i])),
                "replacement": successors(newer.get((i, r.package)), sorted(d["binaries"][i])),
                "risk": removal_risk(checks.get(i), sorted(d["binaries"][i])),
            } for i, n in hosts]}
        else:
            per_host = {n: upgrade_availability(upgrades.get(i), sorted(d["binaries"][i]), fixed) for i, n in hosts}
            installable = sorted({b for a in per_host.values() for b in a["installable"]})
            statuses = {a["status"] for a in per_host.values()}
            remedy = {"action": "upgrade", "target": fixed,
                      "command": upgrade_command(installable) if installable else None,
                      "availability": {
                          "status": statuses.pop() if len(statuses) == 1 else "partial",
                          "missing_on": sorted(n for n, a in per_host.items() if a["status"] in ("missing", "older")),
                          "lists_at": min((a["lists_at"] for a in per_host.values() if a["lists_at"]), default=None),
                      }}
        items.append({
            "package": r.package, "version": r.version, "severity": _sev(r.rank), "max_cvss": r.max_cvss,
            "hosts": r.hosts, "advisories": len(merge_advisories(d["advisories"].values())),
            "fix_available": bool(r.fix_available),
            "fixed_version": fixed,
            "host_list": [{"id": i, "name": n} for i, n in hosts],
            "binaries": binaries,
            "display_name": ", ".join(binaries) if is_obsolete and binaries else r.package,
            "action": "remove" if is_obsolete else "upgrade",
            "remedy": remedy,
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
            C.id, C.cve_id, C.upstream_ids, C.title, C.severity, C.cvss_score, C.source,
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
    stmt = stmt.group_by(C.id, C.cve_id, C.upstream_ids, C.title, C.severity, C.cvss_score, C.source)
    # Merge advisories for the same CVE (DEBIAN-CVE-… + DSA-…) before paging; the filtered set
    # is at most a few thousand rows, so this happens in Python.
    rows = [{
        "cve_entry_id": r.id, "id": r.cve_id, "upstream": [u for u in (r.upstream_ids or "").split(",") if u],
        "title": r.title, "severity": (r.severity or "NONE").upper(), "cvss": r.cvss_score,
        "hosts": r.hosts, "packages": r.packages, "package": r.package, "fix_available": bool(r.fix_available),
        "fixed_version": r.fixed_version, "urgency": r.urgency, "os_hint": os_hint(r.title),
        "note": source_note(r.source, r.title, None),
    } for r in (await db.execute(stmt)).all()]
    merged = merge_advisories(rows, max_fields=("hosts", "packages", "cvss", "fix_available"))
    merged.sort(key=lambda v: (-SEVERITIES[::-1].index(v["severity"]), -(v["cvss"] or 0), v["label"]))
    return {"total": len(merged), "limit": limit, "offset": offset, "items": merged[offset:offset + limit]}


@router.get("/vulnerabilities/{cve_entry_id}")
async def get_vulnerability(cve_entry_id: int, db: AsyncSession = Depends(get_db),
                            _: Optional[User] = Depends(get_current_user_optional)):
    cve = await db.get(C, cve_entry_id)
    if not cve:
        raise HTTPException(status_code=404, detail="Eintrag nicht gefunden")
    siblings = await related_advisories(db, cve.cve_id)
    # findings of all advisories for this vulnerability, one row per package (this advisory's first)
    all_rows = (await db.execute(
        select(F, T, I).join(T, T.id == F.discovered_tool_id).join(I, I.id == T.inventory_id)
        .where(F.cve_entry_id.in_({cve_entry_id, *[s.id for s in siblings]})).order_by(I.name)
    )).all()
    rows, seen_tools = [], set()
    for f, t, i in sorted(all_rows, key=lambda r: (r[0].cve_entry_id != cve_entry_id, r[2].name, r[1].tool_name)):
        if t.id not in seen_tools:
            seen_tools.add(t.id)
            rows.append((f, t, i))
    rows.sort(key=lambda r: (r[2].name, r[1].tool_name))
    sups = (await db.execute(select(Suppression))).scalars().all()
    ups = await exception_upstreams(db, sups)
    exceptions = [x for x in sups if same_vulnerability(x.cve_id, cve.cve_id, cve.upstream_ids, ups.get(x.cve_id))]
    host_names = {i.id: i.name for _, _, i in rows}
    obsolete = await obsolete_keys(db)
    newer = await newer_versions(db, {(i.id, t.source_name or t.tool_name) for _, t, i in rows
                                      if (i.id, t.source_name or t.tool_name, t.source_version or t.detected_version) in obsolete})
    affected = []
    for f, t, i in rows:
        pkg, ver = t.source_name or t.tool_name, t.source_version or t.detected_version
        row = {
            **{k: v for k, v in _finding_row(f, t, cve).items() if k in (
                "finding_id", "status", "fix_available", "fixed_version", "urgency", "first_seen", "resolved_at", "binaries",
                "only_on")},
            "host_id": i.id, "host": i.name, "package": pkg, "installed_version": ver,
        }
        row["display_name"] = ", ".join(row["binaries"]) if (i.id, pkg, ver) in obsolete else pkg
        if f.status == "open" and f.fix_available:
            if (i.id, pkg, ver) in obsolete:
                row["remedy"] = {"action": "remove", "command": remove_command(row["binaries"]),
                                 "replacement": successors(newer.get((i.id, pkg)), row["binaries"]),
                                 "risk": removal_risk(i.removal_check, row["binaries"])}
            else:
                avail = upgrade_availability(i.upgrade_check, row["binaries"], f.fixed_version)
                row["remedy"] = {"action": "upgrade", "target": f.fixed_version, "availability": avail,
                                 "command": upgrade_command(avail["installable"]) if avail["installable"] else None}
        affected.append(row)
    key = vuln_key(cve.cve_id, cve.upstream_ids)
    return {
        "cve_entry_id": cve.id, "id": cve.cve_id, "label": key or cve.cve_id, "source": cve.source,
        "upstream": _upstream(cve),
        "also": [a.cve_id for a in siblings if a.id != cve.id],
        "title": cve.title, "description": cve.description, "severity": (cve.severity or "NONE").upper(),
        "cvss": cve.cvss_score, "cvss_vector": cve.cvss_vector,
        "published_at": _iso(cve.published_at), "modified_at": _iso(cve.modified_at),
        "links": _links(cve),
        "affected": affected,
        "os_hint": next((h for h in (os_hint(a.title, (a.description or "")[:300]) for a in [cve, *siblings]) if h), None),
        "note": next((n for n in (source_note(a.source, a.title, a.description) for a in [cve, *siblings]) if n), None),
        "exceptions": [_exception_dict(x, host_names.get(x.inventory_id)) for x in exceptions],
    }


async def exception_upstreams(db: AsyncSession, sups) -> Dict[str, Optional[str]]:
    """upstream_ids of the advisories the exceptions were created for (see same_vulnerability)."""
    ids = {s.cve_id for s in sups}
    if not ids:
        return {}
    return dict((await db.execute(select(C.cve_id, C.upstream_ids).where(C.cve_id.in_(ids)))).all())


async def related_advisories(db: AsyncSession, advisory_id: str) -> List[C]:
    """All advisories for the same vulnerability (DEBIAN-CVE-2026-1, DSA-… for CVE-2026-1, …)."""
    key = vuln_key(advisory_id)
    if key is None:
        cve = (await db.execute(select(C).where(C.cve_id == advisory_id))).scalar_one_or_none()
        key = vuln_key(advisory_id, cve.upstream_ids) if cve else None
    if key is None:
        return list((await db.execute(select(C).where(C.cve_id == advisory_id))).scalars().all())
    candidates = (await db.execute(
        select(C).where(or_(C.cve_id == advisory_id, C.cve_id.contains(key), C.upstream_ids.contains(key)))
    )).scalars().all()
    return [c for c in candidates if c.cve_id == advisory_id or vuln_key(c.cve_id, c.upstream_ids) == key]


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
    """Set open/suppressed status of the findings of one vulnerability according to the current exceptions.

    An exception for one advisory also covers the other advisories of the same CVE.
    """
    now = datetime.utcnow()
    entries = await related_advisories(db, cve_id)
    if not entries:
        return 0
    sups = (await db.execute(select(Suppression))).scalars().all()
    ups = await exception_upstreams(db, sups)
    rows = (await db.execute(
        select(F, T, C).join(T, T.id == F.discovered_tool_id).join(C, C.id == F.cve_entry_id)
        .where(C.id.in_([e.id for e in entries]), F.status.in_(["open", "suppressed"]))
    )).all()
    changed = 0
    for f, t, c in rows:
        applies = [x for x in sups if same_vulnerability(x.cve_id, c.cve_id, c.upstream_ids, ups.get(x.cve_id))]
        new = "suppressed" if any(_matches(x, t, now) for x in applies) else "open"
        if f.status != new:
            f.status = new
            changed += 1
    return changed


@router.get("/exceptions")
async def list_exceptions(db: AsyncSession = Depends(get_db), _: Optional[User] = Depends(get_current_user_optional)):
    rows = (await db.execute(
        select(Suppression, I.name).outerjoin(I, I.id == Suppression.inventory_id).order_by(Suppression.created_at.desc())
    )).all()
    suppressed = (await db.execute(
        select(C.cve_id, C.upstream_ids, func.count(F.id)).join(F, F.cve_entry_id == C.id)
        .where(F.status == "suppressed").group_by(C.cve_id, C.upstream_ids)
    )).all()

    ups = await exception_upstreams(db, [s for s, _ in rows])

    def count(s: Suppression) -> int:
        return sum(n for adv, up, n in suppressed if same_vulnerability(s.cve_id, adv, up, ups.get(s.cve_id)))

    return [{**_exception_dict(s, host), "suppressed_findings": count(s)} for s, host in rows]


@router.post("/exceptions")
async def create_exception(body: ExceptionCreate, db: AsyncSession = Depends(get_db),
                           user: User = Depends(require_write_access)):
    if not await db.scalar(select(func.count()).select_from(C).where(C.cve_id == body.cve_id)):
        raise HTTPException(status_code=404, detail="Unbekannte Advisory-ID")
    if body.inventory_id and not await db.get(I, body.inventory_id):
        raise HTTPException(status_code=404, detail="Host nicht gefunden")
    expires = body.expires_at
    if expires is not None and expires.tzinfo is not None:
        expires = expires.astimezone(timezone.utc)  # stored as naive UTC, like everything else
    expires = expires.replace(tzinfo=None) if expires else None
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


# ---------------------------------------------------------------- log of fixes (/vulnerabilities/fixed)

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
FIXES_LIMIT = 2000


@router.get("/fixes")
async def fixes_log(days: int = Query(7, ge=0, le=3650), host_id: Optional[int] = Query(None),
                    db: AsyncSession = Depends(get_db), _: Optional[User] = Depends(get_current_user_optional)):
    """Fixed findings, newest first, one entry per package on a host and day.

    How it was fixed is read from the package as it is now: removed, updated (the version differs from
    the one the finding was made for) or the advisory no longer matches (same version, e.g. changed data).
    days=0 means everything."""
    stmt = (select(F, T, I, C).join(T, T.id == F.discovered_tool_id).join(I, I.id == T.inventory_id)
            .join(C, C.id == F.cve_entry_id).where(F.status == "fixed", F.resolved_at.isnot(None)))
    if days:
        stmt = stmt.where(F.resolved_at >= datetime.utcnow() - timedelta(days=days))
    if host_id:
        stmt = stmt.where(I.id == host_id)
    rows = (await db.execute(stmt.order_by(F.resolved_at.desc()))).all()

    groups: Dict[tuple, dict] = {}
    truncated = False
    for f, t, i, c in rows:
        key = (t.id, f.resolved_at.date(), f.matched_version)
        g = groups.get(key)
        if g is None:
            if len(groups) >= FIXES_LIMIT:
                truncated = True
                continue
            if t.removed_at is not None:
                how = "removed"
            elif f.matched_version and t.detected_version and t.detected_version != f.matched_version:
                how = "updated"
            else:
                how = "data"
            g = groups[key] = {
                "resolved_at": f.resolved_at.isoformat() + "Z",
                "host": {"id": i.id, "name": i.name, "vmid": i.vmid, "type": i.type},
                "package": t.tool_name, "from_version": f.matched_version,
                "to_version": None if t.removed_at is not None else t.detected_version,
                "how": how, "severity": None, "advisories": [], "_vulns": set(),
            }
        g["advisories"].append({"id": c.cve_id, "entry_id": c.id, "severity": c.severity})
        g["_vulns"].add(vuln_key(c.cve_id, c.upstream_ids) or c.cve_id)
        if SEV_ORDER.get(c.severity or "", 0) > SEV_ORDER.get(g["severity"] or "", 0):
            g["severity"] = c.severity
    entries = []
    for g in groups.values():
        g["vulnerabilities"] = len(g.pop("_vulns"))
        g["advisories"].sort(key=lambda a: (-SEV_ORDER.get(a["severity"] or "", 0), a["id"]))
        entries.append(g)
    return {"days": days, "findings": len(rows), "entries": entries, "truncated": truncated}


# ---------------------------------------------------------------- switch a VM on/off for scanning


class VMScanSwitch(BaseModel):
    enabled: bool
    ip: Optional[str] = Field(None, max_length=64)


@router.put("/hosts/{inventory_id}/scan")
async def switch_vm_scan(inventory_id: int, body: VMScanSwitch, db: AsyncSession = Depends(get_db),
                         _: User = Depends(require_write_access)):
    """Switch scanning of a VM on or off (wins over `vms:` in config.yaml). On: a scan starts."""
    import ipaddress
    from vigilance.core import runtime_settings as rs
    from vigilance.core import scheduler as sched
    inv = await db.get(I, inventory_id)
    if not inv or inv.type != "qemu":
        raise HTTPException(status_code=404, detail="Keine VM")
    ip = (body.ip or "").strip() or None
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="Keine gültige IP-Adresse.")
    if body.enabled and inv.os_id == "windows":
        raise HTTPException(status_code=400, detail="Windows-VMs werden nicht gescannt.")
    await rs.set_vm_scan(db, inv.vmid, body.enabled, ip)
    if not body.enabled:
        inv.last_scan_status = "not_configured"
        inv.last_scan_error = "Nicht für den Scan aktiviert."
    await db.commit()
    started = False
    if body.enabled:
        sched._spawn(sched.trigger_scan_now(), name=f"scan-after-vm-{inv.vmid}")
        started = True
    return {"vmid": inv.vmid, "enabled": body.enabled, "ip": ip, "scan_started": started}
