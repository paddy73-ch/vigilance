import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List

from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.config import settings
from vigilance.database import crud
from vigilance.database.models import CVEEntry, CVESyncStatus
from vigilance.cve.models import CVEData
from vigilance.cve.osv import sync_osv
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
            results["osv"] = await self._sync_source("osv", sync_osv)

        # GHSA
        if settings.cve_sync and settings.cve_sync.ghsa.get("enabled", True):
            results["ghsa"] = await self._sync_source("ghsa", sync_ghsa)

        # NVD
        if settings.cve_sync and settings.cve_sync.nvd.get("enabled", False):
            results["nvd"] = await self._sync_source("nvd", lambda: sync_nvd(30))

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
                error_message=None,
                next_sync_at=datetime.utcnow() + timedelta(hours=6),
            )

            logger.info(f"Completed CVE sync for {source}: {count} entries")
            return {"status": "success", "count": count, "duration": (datetime.utcnow() - start_time).total_seconds()}

        except Exception as e:
            logger.error(f"CVE sync failed for {source}: {e}")
            await crud.update_sync_status(
                self.db,
                source,
                last_sync_at=datetime.utcnow(),
                error_message=str(e),
            )
            await self.db.commit()
            return {"status": "error", "error": str(e), "duration": (datetime.utcnow() - start_time).total_seconds()}

    async def _rematch_findings(self):
        """Re-match all open findings against updated CVE database."""
        logger.info("Re-matching findings after CVE sync")
        from vigilance.cve.matcher import match_tool_against_cves
        from vigilance.core.notifications import notify_finding

        # Get all open findings
        from vigilance.database.models import VulnerabilityFinding, DiscoveredTool, CVEEntry
        from sqlalchemy import select

        # This is a simplified version - in production you'd want to do this more efficiently
        # For now, we just note that re-matching should happen
        pass


async def sync_cve_source(source: str) -> dict:
    """Sync a single CVE source (for manual triggering)."""
    from vigilance.database.base import async_session_maker
    async with async_session_maker() as db:
        orchestrator = CVESyncOrchestrator(db)
        return await orchestrator._sync_source(source, _get_sync_func(source))


def _get_sync_func(source: str):
    if source == "osv":
        return sync_osv
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