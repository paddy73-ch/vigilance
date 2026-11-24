"""Match discovered tools against stored advisories and maintain the finding lifecycle.

* Direct sources (OSV, GHSA) already evaluated the exact package version
  server-side; their query results are turned into findings as they are.
* Range-based sources (NVD, Debian/Ubuntu trackers) are matched locally, on
  exact package names only (source package first, then binary name).
* Binary packages built from the same source (e.g. util-linux -> mount,
  bsdutils, libblkid1, ...) share their advisories. One finding is recorded
  per host and source package, on a representative tool; the other binary
  packages are listed in ``match_details["binaries"]``.
* Findings that no longer match are set to ``fixed`` (with ``resolved_at``)
  instead of being deleted — but only for sources that synced successfully in
  this run, so a failed sync never marks everything as fixed.
"""

import fnmatch
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from types import SimpleNamespace
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.cve.matcher import _extract_package_from_cpe, match_tool_against_cves
from vigilance.database.models import CVEEntry, DiscoveredTool, Suppression, VulnerabilityFinding

logger = logging.getLogger(__name__)

DIRECT_SOURCES = ("osv", "ghsa")


@dataclass
class DirectMatches:
    """Query results of a direct source: key function + {query key: advisory ids}."""
    key_for: Callable[[DiscoveredTool], Optional[tuple]]
    matches: Dict[tuple, Set[str]]


@dataclass
class MatchStats:
    new: int = 0
    reopened: int = 0
    fixed: int = 0
    open_total: int = 0
    new_findings: List[VulnerabilityFinding] = field(default_factory=list)


def _range_repo_names(cve: CVEEntry) -> Set[str]:
    names = set()
    try:
        ranges = json.loads(cve.affected_ranges or "[]")
    except json.JSONDecodeError:
        return names
    for r in ranges:
        repo = (r.get("repo") or "").lower()
        if not repo:
            continue
        if repo.startswith("cpe:"):
            repo = _extract_package_from_cpe(repo)
        names.add(repo)
    return names


def fixed_version_for(cve: CVEEntry, ecosystem: Optional[str], package: str) -> Optional[str]:
    """Pick the fix version for this ecosystem/package from the stored ranges."""
    try:
        ranges = json.loads(cve.affected_ranges or "[]")
    except json.JSONDecodeError:
        return None
    fixed = None
    for r in ranges:
        if (r.get("repo") or "").lower() != package.lower():
            continue
        if ecosystem and r.get("ecosystem") and r["ecosystem"] != ecosystem:
            continue
        if r.get("fixed"):
            fixed = r["fixed"]
    return fixed


def group_by_source_package(tools: Sequence[DiscoveredTool]) -> List[Tuple[DiscoveredTool, List[str]]]:
    """Return (representative tool, binary package names) per host + source package/version."""
    groups: Dict[tuple, List[DiscoveredTool]] = {}
    for tool in tools:
        if tool.source_name:
            key = (tool.inventory_id, tool.package_manager, tool.source_name,
                   tool.source_version or tool.detected_version)
        else:
            key = (tool.inventory_id, tool.source_type, tool.tool_name, tool.id)
        groups.setdefault(key, []).append(tool)
    result = []
    for members in groups.values():
        members.sort(key=lambda t: (t.tool_name != t.source_name, t.tool_name))
        result.append((members[0], sorted(t.tool_name for t in members)))
    return result


def urgency_for(cve: CVEEntry, ecosystem: Optional[str], package: str) -> Optional[str]:
    """Distribution urgency (Debian: unimportant/low/medium/high/not yet assigned) from the raw OSV record."""
    try:
        raw = json.loads(cve.raw_data or "{}")
    except json.JSONDecodeError:
        return None
    for affected in raw.get("affected", []) or []:
        pkg = affected.get("package") or {}
        if pkg.get("name") == package and (not ecosystem or pkg.get("ecosystem") == ecosystem):
            return (affected.get("ecosystem_specific") or {}).get("urgency")
    return None


def _suppressed(suppressions: Sequence[Suppression], cve_id: str, tool: DiscoveredTool, now: datetime) -> bool:
    for s in suppressions:
        if s.cve_id != cve_id:
            continue
        if s.expires_at and s.expires_at < now:
            continue
        if s.tool_name_pattern and not fnmatch.fnmatch(tool.tool_name, s.tool_name_pattern):
            continue
        if s.inventory_id and s.inventory_id != tool.inventory_id:
            continue
        return True
    return False


async def match_findings(
    db: AsyncSession,
    tools: Iterable[DiscoveredTool],
    direct: Dict[str, DirectMatches],
    active_sources: Set[str],
    scan_run_id: Optional[int] = None,
) -> MatchStats:
    """Create/update findings for all tools. Does not commit."""
    now = datetime.utcnow()
    stats = MatchStats()
    tools = list(tools)

    cves = (await db.execute(select(CVEEntry))).scalars().all()
    by_cve_id = {c.cve_id: c for c in cves}
    by_name: Dict[str, List[CVEEntry]] = {}
    for cve in cves:
        if cve.source in DIRECT_SOURCES:
            continue
        for name in _range_repo_names(cve):
            by_name.setdefault(name, []).append(cve)

    suppressions = (await db.execute(select(Suppression))).scalars().all()
    existing: Dict[Tuple[int, int], VulnerabilityFinding] = {
        (f.discovered_tool_id, f.cve_entry_id): f
        for f in (await db.execute(select(VulnerabilityFinding))).scalars().all()
    }
    seen: Set[Tuple[int, int]] = set()

    def record(tool: DiscoveredTool, cve: CVEEntry, fixed: Optional[str], details: dict):
        key = (tool.id, cve.id)
        if key in seen:
            return
        seen.add(key)
        status = "suppressed" if _suppressed(suppressions, cve.cve_id, tool, now) else "open"
        finding = existing.get(key)
        if finding is None:
            finding = VulnerabilityFinding(
                discovered_tool_id=tool.id,
                cve_entry_id=cve.id,
                status=status,
                matched_version=tool.detected_version,
                fixed_version=fixed,
                match_details=json.dumps(details),
                fix_available=bool(fixed),
                urgency=details.get("urgency"),
                first_seen_at=now,
                last_seen_at=now,
                scan_run_id=scan_run_id,
            )
            db.add(finding)
            existing[key] = finding
            if status == "open":
                stats.new += 1
                finding.tool = tool
                finding.cve = cve
                stats.new_findings.append(finding)
            return
        if finding.status == "fixed" and status == "open":
            stats.reopened += 1
        finding.status = status
        finding.resolved_at = None
        finding.matched_version = tool.detected_version
        finding.fixed_version = fixed
        finding.match_details = json.dumps(details)
        finding.fix_available = bool(fixed)
        finding.urgency = details.get("urgency")
        finding.last_seen_at = now
        if scan_run_id:
            finding.scan_run_id = scan_run_id

    for tool, binaries in group_by_source_package(tools):
        extra = {"binaries": binaries} if len(binaries) > 1 else {}
        # 1. Direct sources: the advisory database already evaluated this exact version
        for source, dm in direct.items():
            qkey = dm.key_for(tool)
            if not qkey:
                continue
            for advisory_id in dm.matches.get(qkey, ()):
                cve = by_cve_id.get(advisory_id)
                if not cve:
                    continue
                ecosystem, package, version = qkey
                fixed = fixed_version_for(cve, ecosystem, package)
                record(tool, cve, fixed, {
                    "source": source, "ecosystem": ecosystem, "package": package, "version": version,
                    "fix_available": bool(fixed), "urgency": urgency_for(cve, ecosystem, package), **extra,
                })

        # 2. Range-based sources: exact name match, source package before binary name
        candidates = []
        if tool.source_name:
            candidates.append((tool.source_name, tool.source_version or tool.detected_version))
        if tool.tool_name and tool.tool_name != tool.source_name:
            candidates.append((tool.tool_name, tool.detected_version))
        for name, version in candidates:
            if not version:
                continue
            proxy = SimpleNamespace(
                tool_name=name,
                detected_version=version,
                cpe_name=tool.cpe_name,
                package_manager=tool.package_manager,
            )
            for cve in by_name.get(name.lower(), ()):
                match = match_tool_against_cves(proxy, cve)
                if match.affected:
                    details = dict(match.details or {})
                    details.update({"source": cve.source, "package": name, "version": version,
                                    "fix_available": bool(match.fixed_version), **extra})
                    record(tool, cve, match.fixed_version, details)

    # 3. Lifecycle: no longer matching -> fixed (only for sources that synced successfully)
    source_of = {c.id: c.source for c in cves}
    for key, finding in existing.items():
        if key in seen or finding.status not in ("open", "suppressed", "unknown_version"):
            continue
        if source_of.get(finding.cve_entry_id) not in active_sources:
            continue
        finding.status = "fixed"
        finding.resolved_at = now
        stats.fixed += 1

    stats.open_total = sum(1 for f in existing.values() if f.status == "open")
    await db.flush()
    logger.info(
        "Matching: %d new, %d reopened, %d fixed, %d open in total",
        stats.new, stats.reopened, stats.fixed, stats.open_total,
    )
    return stats
