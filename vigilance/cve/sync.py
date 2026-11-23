"""CVE sync: fetch advisories only for the discovered tools, then match.

Flow per run (see core.scheduler.run_pipeline):
    scan (tools) -> sync (only for those tools) -> match -> lifecycle/notifications
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Awaitable, Callable, Dict, List, Optional, Sequence, Set

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from vigilance.config import settings
from vigilance.cve import ghsa as ghsa_mod
from vigilance.cve import osv as osv_mod
from vigilance.cve.debian import sync_debian
from vigilance.cve.findings import DirectMatches, MatchStats, match_findings
from vigilance.cve.matcher import _extract_package_from_cpe
from vigilance.cve.models import CVEData
from vigilance.cve.nvd import sync_nvd
from vigilance.cve.ubuntu import sync_ubuntu
from vigilance.database import crud
from vigilance.database.models import CVEEntry, DiscoveredTool

logger = logging.getLogger(__name__)

ALL_SOURCES = ("osv", "ghsa", "nvd", "debian", "ubuntu")


def _source_enabled(source: str) -> bool:
    if not settings.cve_sync:
        return source in ("osv", "ghsa")
    cfg = getattr(settings.cve_sync, source, {}) or {}
    return bool(cfg.get("enabled", False))


def tool_lookup_names(tools: Sequence[DiscoveredTool]) -> Set[str]:
    """Exact (lower-case) names used to filter range-based sources: source package + binary name."""
    names = set()
    for tool in tools:
        if tool.source_name:
            names.add(tool.source_name.lower())
        if tool.tool_name:
            names.add(tool.tool_name.lower())
    return names


def cve_affects_names(cve_data: CVEData, names: Set[str]) -> bool:
    """True if one of the advisory's packages is exactly one of the given names."""
    for r in cve_data.affected_ranges or []:
        repo = (r.repo or "").lower()
        if not repo:
            continue
        if repo.startswith("cpe:"):
            repo = _extract_package_from_cpe(repo)
        if repo in names:
            return True
    return False


class CVESyncOrchestrator:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.last_match: Optional[MatchStats] = None
        self._rolled_back = False

    async def _load_tools(self) -> List[DiscoveredTool]:
        result = await self.db.execute(select(DiscoveredTool).options(selectinload(DiscoveredTool.inventory)))
        return list(result.scalars().all())

    async def sync_all(self, sources: Optional[Sequence[str]] = None, scan_run_id: Optional[int] = None) -> Dict[str, dict]:
        """Sync the given (default: all enabled) sources for the discovered tools, then match."""
        wanted = [s for s in (sources or ALL_SOURCES) if s in ALL_SOURCES and (sources or _source_enabled(s))]
        tools = await self._load_tools()
        results: Dict[str, dict] = {}
        direct: Dict[str, DirectMatches] = {}

        if not tools:
            logger.info("No discovered tools yet - skipping CVE sync")
            return {s: {"status": "skipped", "count": 0, "message": "No discovered tools"} for s in wanted}

        names = tool_lookup_names(tools)

        if "osv" in wanted:
            known = await self._known_osv_records()

            async def run_osv():
                outcome = await osv_mod.sync_osv_for_tools(tools, known)
                direct["osv"] = DirectMatches(osv_mod.tool_query_key, outcome.matches)
                return outcome.cves

            results["osv"] = await self._sync_source("osv", run_osv)

        if "ghsa" in wanted:
            if any(ghsa_mod.tool_query_key(t) for t in tools):
                async def run_ghsa():
                    outcome = await ghsa_mod.sync_ghsa_for_tools(tools)
                    direct["ghsa"] = DirectMatches(ghsa_mod.tool_query_key, outcome.matches)
                    return outcome.cves

                results["ghsa"] = await self._sync_source("ghsa", run_ghsa)
            else:
                results["ghsa"] = {"status": "skipped", "count": 0,
                                   "message": "No packages from GHSA ecosystems (pip, npm, ...) discovered"}
                await self._set_status("ghsa", status="idle", entries_count=0,
                                       error_message=results["ghsa"]["message"])

        if "nvd" in wanted:
            cfg = settings.cve_sync.nvd if settings.cve_sync else {}
            results["nvd"] = await self._sync_source(
                "nvd", lambda: sync_nvd(30, max_pages=cfg.get("max_pages", 0)), names)

        if "debian" in wanted:
            suites = (settings.cve_sync.debian if settings.cve_sync else {}).get("suites", ["bookworm", "trixie"])
            results["debian"] = await self._sync_source("debian", lambda: sync_debian(suites), names)

        if "ubuntu" in wanted:
            releases = (settings.cve_sync.ubuntu if settings.cve_sync else {}).get("releases", ["noble", "jammy"])
            results["ubuntu"] = await self._sync_source("ubuntu", lambda: sync_ubuntu(releases), names)

        if self._rolled_back:
            # A rollback expires all loaded objects; reload before matching (no lazy loads in async).
            tools = await self._load_tools()
        active = {s for s, r in results.items() if r.get("status") == "success"}
        self.last_match = await match_findings(self.db, tools, direct, active, scan_run_id=scan_run_id)
        await self.db.commit()
        await self._notify(self.last_match)
        return results

    async def _known_osv_records(self) -> Dict[str, Optional[datetime]]:
        """OSV ids already stored with the current parser (so unchanged ones are not re-downloaded)."""
        rows = await self.db.execute(
            select(CVEEntry.cve_id, CVEEntry.modified_at).where(
                CVEEntry.source == "osv",
                CVEEntry.raw_data.contains(osv_mod.PARSER_MARKER),
            )
        )
        return {cve_id: modified for cve_id, modified in rows.all()}

    async def _set_status(self, source: str, **kwargs):
        await crud.update_sync_status(self.db, source, **kwargs)
        await self.db.commit()

    async def _store(self, cve_data_list: List[CVEData]) -> int:
        for cve_data in cve_data_list:
            await crud.upsert_cve_entry(
                self.db,
                cve_id=cve_data.cve_id,
                source=cve_data.source,
                title=cve_data.title,
                description=cve_data.description,
                severity=cve_data.severity,
                cvss_score=cve_data.cvss_score,
                cvss_vector=cve_data.cvss_vector,
                affected_ranges=json.dumps([r.__dict__ for r in cve_data.affected_ranges]),
                references=json.dumps([r.__dict__ for r in cve_data.references]),
                published_at=cve_data.published_at,
                modified_at=cve_data.modified_at,
                raw_data=json.dumps(cve_data.raw_data),
                fetched_at=datetime.utcnow(),
            )
        await self.db.flush()
        return len(cve_data_list)

    async def _sync_source(
        self,
        source: str,
        sync_func: Callable[[], Awaitable[List[CVEData]]],
        names: Optional[Set[str]] = None,
    ) -> dict:
        """Run one source. ``names`` filters range-based sources to exact package names."""
        start_time = datetime.utcnow()
        try:
            await self._set_status(source, status="running", error_message=None)
            logger.info("Starting CVE sync for %s", source)
            cve_data_list = await sync_func()

            if names is not None:
                before = len(cve_data_list)
                cve_data_list = [c for c in cve_data_list if cve_affects_names(c, names)]
                logger.info("%s: kept %d of %d advisories matching discovered packages",
                            source, len(cve_data_list), before)

            count = await self._store(cve_data_list)
            await self.db.commit()
            total = await crud.count_cve_entries(self.db, source)
            interval = settings.cve_sync_interval_hours or 6
            await self._set_status(
                source,
                last_sync_at=datetime.utcnow(),
                last_success_at=datetime.utcnow(),
                entries_count=total,
                status="success",
                error_message=None,
                next_sync_at=datetime.utcnow() + timedelta(hours=interval),
            )
            logger.info("Completed CVE sync for %s: %d stored/updated, %d total", source, count, total)
            return {"status": "success", "count": count, "total": total,
                    "duration": (datetime.utcnow() - start_time).total_seconds()}
        except Exception as e:
            from tenacity import RetryError
            if isinstance(e, RetryError) and e.last_attempt.failed and e.last_attempt.exception() is not None:
                e = e.last_attempt.exception()
            await self.db.rollback()
            self._rolled_back = True
            error_msg = str(e) or e.__class__.__name__
            logger.error("CVE sync failed for %s: %s", source, error_msg)
            await self._set_status(source, last_sync_at=datetime.utcnow(), status="error", error_message=error_msg)
            return {"status": "error", "error": error_msg,
                    "duration": (datetime.utcnow() - start_time).total_seconds()}

    async def _notify(self, stats: MatchStats):
        if not stats or not stats.new_findings:
            return
        from vigilance.core.notifications import notify_finding
        for finding in stats.new_findings:
            try:
                await notify_finding(finding, finding.tool, finding.tool.inventory, finding.cve)
            except Exception as exc:
                logger.warning("Notification failed for finding %s: %s", finding.id, exc)


async def sync_cve_source(source: str) -> dict:
    """Sync a single CVE source and re-match (manual trigger / CLI)."""
    if source not in ALL_SOURCES:
        raise ValueError(f"Unknown CVE source: {source}")
    from vigilance.database.base import async_session_maker
    async with async_session_maker() as db:
        results = await CVESyncOrchestrator(db).sync_all(sources=[source])
        return results.get(source, {})
