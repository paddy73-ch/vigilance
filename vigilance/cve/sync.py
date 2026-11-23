import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List

from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.config import settings
from vigilance.database import crud
from vigilance.database.models import CVEEntry, CVESyncStatus
from vigilance.cve.models import CVEData
from vigilance.cve.osv import sync_osv_for_tools
from vigilance.cve.ghsa import sync_ghsa
from vigilance.cve.nvd import sync_nvd
from vigilance.cve.debian import sync_debian
from vigilance.cve.ubuntu import sync_ubuntu

logger = logging.getLogger(__name__)


class CVESyncOrchestrator:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def sync_all(self) -> Dict[str, dict]:
        """Sync CVE data from all enabled sources."""
        results = {}

        # OSV
        if settings.cve_sync and settings.cve_sync.osv.get("enabled", True):
            from sqlalchemy import select
            from vigilance.database.models import DiscoveredTool
            tool_result = await self.db.execute(select(DiscoveredTool))
            results["osv"] = await self._sync_source(
                "osv", lambda: sync_osv_for_tools(tool_result.scalars().all())
            )

        # GHSA
        if settings.cve_sync and settings.cve_sync.ghsa.get("enabled", True):
            # Load discovered tool names to filter GHSA advisories
            tool_names = await crud.get_discovered_tool_names(self.db)
            max_pages = settings.cve_sync.ghsa.get("max_pages") if settings.cve_sync else None
            if tool_names:
                results["ghsa"] = await self._sync_source(
                    "ghsa", lambda: sync_ghsa(max_pages=max_pages, package_names=tool_names)
                )
            else:
                # No tools discovered yet: do NOT fetch GHSA advisories
                results["ghsa"] = {"status": "skipped", "count": 0, "message": "No discovered tools, skipping GHSA sync"}

        # NVD
        if settings.cve_sync and settings.cve_sync.nvd.get("enabled", False):
            max_pages = settings.cve_sync.nvd.get("max_pages", 0)
            results["nvd"] = await self._sync_source("nvd", lambda: sync_nvd(30, max_pages=max_pages))

        # Debian
        if settings.cve_sync and settings.cve_sync.debian.get("enabled", True):
            suites = settings.cve_sync.debian.get("suites", ["bookworm", "bullseye", "trixie"])
            results["debian"] = await self._sync_source("debian", lambda: sync_debian(suites))

        # Ubuntu
        if settings.cve_sync and settings.cve_sync.ubuntu.get("enabled", True):
            releases = settings.cve_sync.ubuntu.get("releases", ["noble", "jammy", "focal"])
            results["ubuntu"] = await self._sync_source("ubuntu", lambda: sync_ubuntu(releases))

        # After sync, re-match findings
        await self._rematch_findings()

        return results

    async def _sync_source(self, source: str, sync_func) -> dict:
        """Sync a single source and update database."""
        start_time = datetime.utcnow()
        try:
            await crud.update_sync_status(self.db, source, status="running", error_message=None)
            await self.db.commit()
            logger.info(f"Starting CVE sync for {source}")
            cve_data_list = await sync_func()

            # Upsert into database
            count = 0
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
                )
                count += 1

            await self.db.commit()

            # Update sync status
            await crud.update_sync_status(
                self.db,
                source,
                last_sync_at=datetime.utcnow(),
                last_success_at=datetime.utcnow(),
                entries_count=count,
                status="success",
                error_message=None,
                next_sync_at=datetime.utcnow() + timedelta(hours=6),
            )
            await self.db.commit()

            logger.info(f"Completed CVE sync for {source}: {count} entries")
            return {"status": "success", "count": count, "duration": (datetime.utcnow() - start_time).total_seconds()}

        except Exception as e:
            # Unwrap tenacity RetryError to get the actual inner exception
            from tenacity import RetryError
            if isinstance(e, RetryError) and e.last_attempt.failed:
                inner = e.last_attempt.exception()
                if inner is not None:
                    e = inner
            error_msg = str(e)
            logger.error(f"CVE sync failed for {source}: {error_msg}")
            await crud.update_sync_status(
                self.db,
                source,
                last_sync_at=datetime.utcnow(),
                status="error",
                error_message=error_msg,
            )
            await self.db.commit()
            return {"status": "error", "error": error_msg, "duration": (datetime.utcnow() - start_time).total_seconds()}

    async def _rematch_findings(self):
        """Re-match all open findings against updated CVE database."""
        logger.info("Re-matching findings after CVE sync")
        from vigilance.cve.matcher import match_tool_against_cves
        from vigilance.core.notifications import notify_finding

        from vigilance.database.models import DiscoveredTool
        from sqlalchemy import select
        from vigilance.cve.matcher import match_tool_against_cves

        result = await self.db.execute(select(DiscoveredTool))
        tools = result.scalars().all()
        cves = await crud.get_cve_entries(self.db, limit=10000)
        # Index CVEs by affected package/CPE instead of testing every CVE against every tool.
        cves_by_repo = {}
        for cve in cves:
            try:
                ranges = json.loads(cve.affected_ranges or "[]")
            except json.JSONDecodeError:
                ranges = []
            for range_obj in ranges:
                repo = (range_obj.get("repo") or "").lower()
                if repo:
                    cves_by_repo.setdefault(repo, []).append(cve)
        for tool in tools:
            tool_name = tool.tool_name.lower()
            candidates = cves_by_repo.get(tool_name, [])
            for repo, repo_cves in cves_by_repo.items():
                if repo != tool_name and (repo in tool_name or tool_name in repo):
                    candidates.extend(repo_cves)
            for cve in candidates:
                if await crud.is_suppressed(self.db, cve.cve_id, tool.tool_name, tool.inventory_id):
                    continue
                match = match_tool_against_cves(tool, cve)
                if match.affected:
                    await crud.upsert_finding(
                        self.db,
                        discovered_tool_id=tool.id,
                        cve_entry_id=cve.id,
                        status="open",
                        matched_version=tool.detected_version,
                        fixed_version=match.fixed_version,
                        match_details=json.dumps(match.details),
                    )
        await self.db.commit()


async def sync_cve_source(source: str) -> dict:
    """Sync a single CVE source (for manual triggering)."""
    from vigilance.database.base import async_session_maker
    async with async_session_maker() as db:
        orchestrator = CVESyncOrchestrator(db)
        if source == "osv":
            from sqlalchemy import select
            from vigilance.database.models import DiscoveredTool
            result = await db.execute(select(DiscoveredTool))
            return await orchestrator._sync_source(
                source, lambda: sync_osv_for_tools(result.scalars().all())
            )
        if source == "ghsa":
            tool_names = await crud.get_discovered_tool_names(db)
            max_pages = settings.cve_sync.ghsa.get("max_pages") if settings.cve_sync else None
            if tool_names:
                return await orchestrator._sync_source(
                    source, lambda: sync_ghsa(max_pages=max_pages, package_names=tool_names)
                )
            return {"status": "skipped", "count": 0, "message": "No discovered tools, skipping GHSA sync"}
        return await orchestrator._sync_source(source, _get_sync_func(source))


def _get_sync_func(source: str):
    if source == "osv":
        return sync_osv_for_tools
    elif source == "ghsa":
        return sync_ghsa
    elif source == "nvd":
        return lambda: sync_nvd(30)
    elif source == "debian":
        suites = settings.cve_sync.debian.get("suites", ["bookworm", "bullseye", "trixie"]) if settings.cve_sync else ["bookworm", "bullseye", "trixie"]
        return lambda: sync_debian(suites)
    elif source == "ubuntu":
        releases = settings.cve_sync.ubuntu.get("releases", ["noble", "jammy", "focal"]) if settings.cve_sync else ["noble", "jammy", "focal"]
        return lambda: sync_ubuntu(releases)
    raise ValueError(f"Unknown CVE source: {source}")
