"""When the scan and the CVE sync run: every N hours, or at fixed times of day.

Fixed times are set with the clock in Verwaltung › Einstellungen and stored as JSON in
``app_settings`` under ``schedule.scan`` / ``schedule.cve_sync``:

    {"mode": "times", "times": ["03:00", "15:30"], "days": [0, 1, 2, 3, 4], "timezone": "Europe/Zurich"}

``days`` are weekdays, Monday = 0; empty or missing means every day. Without an entry (or with
``mode: "interval"``) the job runs every ``scan_interval_hours`` / ``cve_sync_interval_hours``.
"""

import json
import re
from typing import Dict, List, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.triggers.combining import OrTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.config import settings
from vigilance.database import crud

KINDS = {"scan": ("scan_interval_hours", 24), "cve_sync": ("cve_sync_interval_hours", 6)}
PREFIX = "schedule."
DEFAULT_TZ = "Europe/Zurich"
MAX_TIMES = 12
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_CRON_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

# Fixed-time schedules as loaded from the database; kind -> dict. Interval mode is not kept here.
SCHEDULES: Dict[str, dict] = {}


class ScheduleError(ValueError):
    pass


def normalize(data: dict) -> Optional[dict]:
    """Validate a schedule from the UI. Returns the dict to store, or None for interval mode."""
    if (data or {}).get("mode", "interval") == "interval":
        return None
    if data.get("mode") != "times":
        raise ScheduleError("Unbekannte Art des Zeitplans")
    times = []
    for t in data.get("times") or []:
        if not isinstance(t, str) or not _TIME.match(t.strip()):
            raise ScheduleError(f"Ungültige Uhrzeit: {t!r} (erwartet HH:MM)")
        if t.strip() not in times:
            times.append(t.strip())
    if not times:
        raise ScheduleError("Mindestens eine Uhrzeit angeben")
    if len(times) > MAX_TIMES:
        raise ScheduleError(f"Höchstens {MAX_TIMES} Uhrzeiten")
    days = sorted({int(d) for d in data.get("days") or []})
    if any(d < 0 or d > 6 for d in days):
        raise ScheduleError("Ungültiger Wochentag")
    tz = (data.get("timezone") or DEFAULT_TZ).strip()
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise ScheduleError(f"Unbekannte Zeitzone: {tz}")
    return {"mode": "times", "times": sorted(times), "days": days if len(days) < 7 else [], "timezone": tz}


def build_trigger(kind: str):
    """APScheduler trigger for a job, from the fixed times or the interval."""
    sched = SCHEDULES.get(kind)
    if not sched:
        attr, default = KINDS[kind]
        try:
            hours = max(1, int(getattr(settings, attr)))
        except (TypeError, ValueError):
            hours = default
        return IntervalTrigger(hours=hours)
    tz = ZoneInfo(sched["timezone"])
    dow = ",".join(_CRON_DAYS[d] for d in sched["days"]) if sched["days"] else "*"
    triggers: List[CronTrigger] = []
    for t in sched["times"]:
        h, m = t.split(":")
        triggers.append(CronTrigger(hour=int(h), minute=int(m), day_of_week=dow, timezone=tz))
    return triggers[0] if len(triggers) == 1 else OrTrigger(triggers)


def describe(kind: str) -> dict:
    """For the settings page."""
    sched = SCHEDULES.get(kind)
    if sched:
        return dict(sched)
    attr, default = KINDS[kind]
    return {"mode": "interval", "hours": getattr(settings, attr, default)}


async def load(db: AsyncSession) -> None:
    for kind in KINDS:
        raw = await crud.get_setting(db, PREFIX + kind)
        SCHEDULES.pop(kind, None)
        if not raw:
            continue
        try:
            sched = normalize(json.loads(raw))
        except (ValueError, TypeError):
            continue
        if sched:
            SCHEDULES[kind] = sched


async def save(db: AsyncSession, kind: str, data: dict) -> Optional[dict]:
    if kind not in KINDS:
        raise ScheduleError("Unbekannter Auftrag")
    sched = normalize(data)
    if sched is None:
        hours = (data or {}).get("hours")
        if hours is not None:
            try:
                hours = int(hours)
            except (TypeError, ValueError):
                raise ScheduleError("Stunden müssen eine Zahl sein")
            if not 1 <= hours <= 168:
                raise ScheduleError("Stunden zwischen 1 und 168")
            attr = KINDS[kind][0]
            await crud.set_setting(db, attr, str(hours), attr)
            setattr(settings, attr, hours)
        await crud.set_setting(db, PREFIX + kind, json.dumps({"mode": "interval"}), "Schedule")
        SCHEDULES.pop(kind, None)
    else:
        await crud.set_setting(db, PREFIX + kind, json.dumps(sched), "Schedule")
        SCHEDULES[kind] = sched
    return sched
