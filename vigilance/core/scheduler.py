import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.config import settings
from vigilance.database.base import async_session_maker
from vigilance.database import crud
from vigilance.discovery.orchestrator import DiscoveryOrchestrator
from vigilance.cve.sync import CVESyncOrchestrator
from vigilance.core.notifications import get_digest_queue, notify_digest

logger = logging.getLogger(__name__)

scheduler: Optional[AsyncIOScheduler] = None


async def run_scan_job():
    """Background job to run full discovery scan."""
    logger.info("Starting scheduled scan job")
    async with async_session_maker() as db:
        scan_run = await crud.create_scan_run(db, "incremental" if settings.scan and settings.scan.incremental else "full")
        try:
            orchestrator = DiscoveryOrchestrator(db)
            result = await orchestrator.discover_all(scan_run.id)
            await crud.complete_scan_run(
                db, scan_run.id, "completed",
                nodes_scanned=result.nodes_scanned,
                tools_found=result.tools_found,
                new_findings=result.new_findings,
            )
            await db.commit()
            logger.info(f"Scan completed: {result}")
        except Exception as e:
            logger.error(f"Scan job failed: {e}")
            await crud.complete_scan_run(db, scan_run.id, "failed", error_message=str(e))


async def run_cve_sync_job():
    """Background job to sync CVE data from all sources."""
    logger.info("Starting scheduled CVE sync job")
    async with async_session_maker() as db:
        orchestrator = CVESyncOrchestrator(db)
        try:
            await orchestrator.sync_all()
            logger.info("CVE sync completed")
        except Exception as e:
            logger.error(f"CVE sync job failed: {e}")


async def run_digest_job():
    """Background job to send digest notifications."""
    logger.info("Running digest notification job")
    findings = await get_digest_queue()
    if findings:
        await notify_digest(findings)
        logger.info(f"Sent digest with {len(findings)} findings")
    else:
        logger.info("Digest queue empty, nothing to send")


def init_scheduler() -> AsyncIOScheduler:
    global scheduler
    scheduler = AsyncIOScheduler(timezone="UTC")

    # Scan job
    scan_interval = settings.scan.interval_hours if settings.scan else 24
    scheduler.add_job(
        run_scan_job,
        IntervalTrigger(hours=scan_interval, jitter=300),
        id="scan_job",
        name="Discovery Scan",
        misfire_grace_time=600,
        max_instances=1,
    )

    # CVE Sync job - daily at 07:00 UTC
    scheduler.add_job(
        run_cve_sync_job,
        CronTrigger(hour=7, minute=0, timezone="UTC"),
        id="cve_sync_job",
        name="CVE Sync (daily 07:00 UTC)",
        misfire_grace_time=3600,
        max_instances=1,
    )

    # Digest job (if enabled)
    if settings.notifications and settings.notifications.gotify and settings.notifications.gotify.digest_mode:
        digest_interval = settings.notifications.gotify.digest_interval_minutes
        scheduler.add_job(
            run_digest_job,
            IntervalTrigger(minutes=digest_interval, jitter=60),
            id="digest_job",
            name="Gotify Digest",
            misfire_grace_time=300,
            max_instances=1,
        )

    return scheduler


async def start_scheduler():
    global scheduler
    if scheduler is None:
        scheduler = init_scheduler()
    scheduler.start()
    logger.info("Scheduler started")


async def shutdown_scheduler():
    global scheduler
    if scheduler:
        scheduler.shutdown(wait=True)
        scheduler = None
        logger.info("Scheduler stopped")


async def trigger_scan_now(full: bool = False) -> int:
    """Manually trigger a scan, returns scan_run_id."""
    async with async_session_maker() as db:
        scan_type = "full" if full else "incremental"
        scan_run = await crud.create_scan_run(db, scan_type)
        orchestrator = DiscoveryOrchestrator(db)
        result = await orchestrator.discover_all(scan_run.id)
        await crud.complete_scan_run(
            db, scan_run.id, "completed",
            nodes_scanned=result.nodes_scanned,
            tools_found=result.tools_found,
            new_findings=result.new_findings,
        )
        await db.commit()
        return scan_run.id


async def trigger_cve_sync_now() -> dict:
    """Manually trigger CVE sync, returns results per source."""
    async with async_session_maker() as db:
        orchestrator = CVESyncOrchestrator(db)
        return await orchestrator.sync_all()


@asynccontextmanager
async def lifespan(app):
    # Startup
    await start_scheduler()
    # Run initial scan if configured
    if settings.scan and settings.scan.full_scan_on_start:
        logger.info("Running initial scan on startup")
        # Do not hold the HTTP server healthcheck open while offline guests time out.
        asyncio.create_task(trigger_scan_now(full=True), name="initial-scan")
    # Run initial CVE sync on startup
    logger.info("Running initial CVE sync on startup")
    asyncio.create_task(trigger_cve_sync_now(), name="initial-cve-sync")
    yield
    # Shutdown
    await shutdown_scheduler()
