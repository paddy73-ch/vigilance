"""Background jobs.

One pipeline does the whole work in the right order:

    scan (discover tools) -> CVE sync for exactly those tools -> match -> lifecycle/notifications

* ``pipeline_job`` runs it every ``scan_interval_hours``.
* ``cve_sync_job`` runs sync + match (no scan) every ``cve_sync_interval_hours``
  so new advisories for already known packages show up between scans.
  With the CVE sync set to "Nach Scan" (``after_scan``) this job stays paused:
  the sync then only runs inside the pipeline, right after each scan.

Both share a lock, so they never overlap. Intervals follow the values saved on
the settings page (``reschedule_jobs()``).
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Sequence

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from vigilance.config import settings
from vigilance.core import schedule
from vigilance.core.notifications import get_digest_queue, notify_digest
from vigilance.cve.sync import CVESyncOrchestrator
from vigilance.database import crud
from vigilance.database.base import async_session_maker
from vigilance.discovery.orchestrator import DiscoveryOrchestrator

logger = logging.getLogger(__name__)

scheduler: Optional[AsyncIOScheduler] = None
_pipeline_lock = asyncio.Lock()
_background_tasks: set = set()


async def run_pipeline(
    with_scan: bool = True,
    full: bool = False,
    scan_run_id: Optional[int] = None,
    sources: Optional[Sequence[str]] = None,
) -> Dict[str, dict]:
    """Scan (optional) -> sync for discovered tools -> match. Returns the sync results."""
    async with _pipeline_lock:
        async with async_session_maker() as db:
            run_id = scan_run_id
            result = None
            try:
                if with_scan:
                    if run_id is None:
                        run = await crud.create_scan_run(db, "full" if full else "incremental")
                        await db.commit()
                        run_id = run.id
                    result = await DiscoveryOrchestrator(db).discover_all(run_id)
                    await db.commit()

                sync = CVESyncOrchestrator(db)
                sync_results = await sync.sync_all(sources=sources, scan_run_id=run_id if with_scan else None)

                if with_scan:
                    await crud.complete_scan_run(
                        db, run_id, "completed",
                        nodes_scanned=result.nodes_scanned,
                        tools_found=result.tools_found,
                        new_findings=sync.last_match.new if sync.last_match else 0,
                    )
                    await db.commit()
                logger.info("Pipeline finished (scan=%s): %s", with_scan, sync.last_match)
                return sync_results
            except Exception as e:
                logger.exception("Pipeline failed (scan=%s): %s", with_scan, e)
                if with_scan and run_id is not None:
                    await db.rollback()
                    await crud.complete_scan_run(db, run_id, "failed", error_message=str(e))
                    await db.commit()
                raise


async def run_scan_job():
    """Scheduled: full pipeline."""
    try:
        await run_pipeline(with_scan=True, full=bool(settings.scan and not settings.scan.incremental))
    except Exception:
        pass  # already logged and recorded on the scan run


async def run_cve_sync_job():
    """Scheduled: sync + match for the known tools (no scan)."""
    try:
        await run_pipeline(with_scan=False)
    except Exception:
        pass


async def run_digest_job():
    """Background job to send digest notifications."""
    logger.info("Running digest notification job")
    findings = await get_digest_queue()
    if findings:
        await notify_digest(findings)
        logger.info(f"Sent digest with {len(findings)} findings")
    else:
        logger.info("Digest queue empty, nothing to send")


def _hours(value, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def init_scheduler() -> AsyncIOScheduler:
    global scheduler
    scheduler = AsyncIOScheduler(timezone="UTC")

    first_scan = None
    if settings.scan and settings.scan.full_scan_on_start:
        first_scan = datetime.now(timezone.utc) + timedelta(minutes=1)

    scheduler.add_job(
        run_scan_job,
        schedule.build_trigger("scan"),
        id="scan_job",
        name="Scan -> CVE sync -> match",
        # next_run_time=None would add the job *paused* (APScheduler 3), so pass it only when set
        **({"next_run_time": first_scan} if first_scan else {}),
        misfire_grace_time=3600,
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        run_cve_sync_job,
        schedule.build_trigger("cve_sync"),
        id="cve_sync_job",
        name="CVE sync -> match",
        # "Nach Scan": no runs of its own; next_run_time=None adds the job paused (APScheduler 3)
        **({"next_run_time": None} if schedule.after_scan("cve_sync") else {}),
        misfire_grace_time=3600,
        coalesce=True,
        max_instances=1,
    )

    _add_digest_job(scheduler)
    return scheduler


def _add_digest_job(sched):
    g = settings.notifications.gotify if settings.notifications else None
    if g and g.enabled and g.digest_mode:
        sched.add_job(
            run_digest_job,
            IntervalTrigger(minutes=max(5, int(g.digest_interval_minutes or 60)), jitter=60),
            id="digest_job",
            name="Gotify Digest",
            misfire_grace_time=300,
            max_instances=1,
            replace_existing=True,
        )


def apply_digest_job():
    """Add, change or remove the digest job after the Gotify settings changed."""
    if not scheduler:
        return
    if scheduler.get_job("digest_job"):
        scheduler.remove_job("digest_job")
    _add_digest_job(scheduler)


def reschedule_jobs():
    """Apply changed scan / CVE sync intervals (called after saving settings)."""
    if not scheduler:
        return
    scheduler.reschedule_job("scan_job", trigger=schedule.build_trigger("scan"))
    # reschedule_job also resumes a paused job, so pause it again for "Nach Scan"
    scheduler.reschedule_job("cve_sync_job", trigger=schedule.build_trigger("cve_sync"))
    if schedule.after_scan("cve_sync"):
        scheduler.pause_job("cve_sync_job")
    logger.info("Rescheduled jobs: scan %s, CVE sync %s", schedule.describe("scan"), schedule.describe("cve_sync"))


def next_runs() -> dict:
    """Next start of the scan and the CVE sync (UTC, ISO), for the settings page."""
    out = {}
    for kind, job_id in (("scan", "scan_job"), ("cve_sync", "cve_sync_job")):
        job = scheduler.get_job(job_id) if scheduler else None
        when = getattr(job, "next_run_time", None) if job else None
        out[kind] = when.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if when else None
    return out


async def start_scheduler():
    global scheduler
    if scheduler is None:
        scheduler = init_scheduler()
    scheduler.start()
    logger.info("Scheduler started")


async def shutdown_scheduler():
    global scheduler
    if scheduler:
        scheduler.shutdown(wait=False)
        scheduler = None
        logger.info("Scheduler stopped")


def _spawn(coro, name: str):
    task = asyncio.create_task(coro, name=name)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


async def trigger_scan_now(full: bool = False, wait: bool = False) -> int:
    """Start the pipeline; returns the scan_run_id immediately unless ``wait`` is set.
    With ``wait`` a failure is raised to the caller (the CLI reports it); it is also stored on the run."""
    async with async_session_maker() as db:
        run = await crud.create_scan_run(db, "full" if full else "incremental")
        await db.commit()
        run_id = run.id

    async def job():
        try:
            await run_pipeline(with_scan=True, full=full, scan_run_id=run_id)
        except Exception:
            pass  # logged and stored on the scan run

    if wait:
        await run_pipeline(with_scan=True, full=full, scan_run_id=run_id)
    else:
        _spawn(job(), name=f"pipeline-{run_id}")
    return run_id


async def trigger_cve_sync_now(sources: Optional[Sequence[str]] = None) -> dict:
    """Sync + match now (waits for the result)."""
    return await run_pipeline(with_scan=False, sources=sources)


@asynccontextmanager
async def lifespan(app):
    # Startup - load persisted settings from DB
    async with async_session_maker() as db:
        for key in ("scan_interval_hours", "cve_sync_interval_hours", "ssh_timeout", "ssh_parallel_jobs"):
            val = await crud.get_setting(db, key)
            if val is not None:
                try:
                    setattr(settings, key, int(val))
                except (ValueError, TypeError):
                    pass
        from vigilance.core import runtime_settings
        await runtime_settings.load(db)  # Gotify and CVE sources as set in the UI
        await schedule.load(db)  # fixed times for scan / CVE sync
    # Remediation runs that were cut off by a restart
    from vigilance.actions.runner import mark_interrupted
    async with async_session_maker() as db:
        if await mark_interrupted(db):
            await db.commit()
    await start_scheduler()
    logger.info(
        "Application started. Scan interval: %sh, CVE sync: %sh, SSH timeout: %ss, SSH parallel: %s",
        settings.scan_interval_hours, settings.cve_sync_interval_hours, settings.ssh_timeout, settings.ssh_parallel_jobs,
    )
    yield
    await shutdown_scheduler()
