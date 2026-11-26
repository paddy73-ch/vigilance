"""Zeitplan: feste Uhrzeiten (Uhr) oder Intervall."""
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
from apscheduler.triggers.interval import IntervalTrigger

from tests.unit.test_views import AUTH, client  # noqa: F401  (fixture)
from vigilance.core import schedule

ZRH = ZoneInfo("Europe/Zurich")


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setattr(schedule, "SCHEDULES", {})


def test_normalize_validates():
    s = schedule.normalize({"mode": "times", "times": ["15:30", "03:00", "03:00"], "days": [0, 1, 2, 3, 4, 5, 6],
                            "timezone": "Europe/Zurich"})
    assert s == {"mode": "times", "times": ["03:00", "15:30"], "days": [], "timezone": "Europe/Zurich"}
    assert schedule.normalize({"mode": "interval"}) is None
    for bad in ({"mode": "times", "times": []}, {"mode": "times", "times": ["24:00"]},
                {"mode": "times", "times": ["3:00"]}, {"mode": "times", "times": ["03:00"], "days": [7]},
                {"mode": "times", "times": ["03:00"], "timezone": "Mars/Base"}):
        with pytest.raises(schedule.ScheduleError):
            schedule.normalize(bad)


def test_trigger_fires_at_the_times_in_local_time():
    schedule.SCHEDULES["scan"] = schedule.normalize(
        {"mode": "times", "times": ["03:00", "15:30"], "days": [0, 1, 2, 3, 4], "timezone": "Europe/Zurich"})
    trig = schedule.build_trigger("scan")
    thu = datetime(2026, 11, 26, 12, 0, tzinfo=ZRH)
    assert trig.get_next_fire_time(None, thu) == datetime(2026, 11, 26, 15, 30, tzinfo=ZRH)
    fri_late = datetime(2026, 11, 27, 16, 0, tzinfo=ZRH)  # next is Monday 03:00, not the weekend
    assert trig.get_next_fire_time(None, fri_late) == datetime(2026, 11, 30, 3, 0, tzinfo=ZRH)


def test_without_times_the_interval_applies():
    assert isinstance(schedule.build_trigger("cve_sync"), IntervalTrigger)


@pytest.mark.asyncio
async def test_api_saves_and_switches_back(client):  # noqa: F811
    body = {"mode": "times", "times": ["09:00", "15:30"], "days": [0, 1, 2, 3, 4], "timezone": "Europe/Zurich"}
    r = await client.put("/api/settings/schedule/scan", headers=AUTH, json=body)
    assert r.status_code == 200, r.text
    assert r.json()["schedule"]["times"] == ["09:00", "15:30"]
    s = (await client.get("/api/settings")).json()
    assert s["schedules"]["scan"]["mode"] == "times" and s["schedules"]["cve_sync"]["mode"] == "interval"
    r = await client.put("/api/settings/schedule/scan", headers=AUTH, json={"mode": "interval", "hours": 12})
    assert r.status_code == 200 and r.json()["schedule"] == {"mode": "interval", "hours": 12}
    assert (await client.put("/api/settings/schedule/scan", headers=AUTH,
                             json={"mode": "times", "times": ["25:00"]})).status_code == 400
    assert (await client.put("/api/settings/schedule/other", headers=AUTH, json={})).status_code == 404
    assert (await client.put("/api/settings/schedule/scan", json=body)).status_code in (401, 403)


@pytest.mark.asyncio
async def test_scan_job_is_not_paused():
    """Without full_scan_on_start the job used to be added with next_run_time=None, which pauses it."""
    from vigilance.core import scheduler as sched
    s = sched.init_scheduler()
    s.start(paused=True)
    try:
        assert s.get_job("scan_job").next_run_time is not None
        assert s.get_job("cve_sync_job").next_run_time is not None
    finally:
        s.shutdown(wait=False)
        sched.scheduler = None


def test_after_scan_only_for_cve_sync():
    assert schedule.normalize({"mode": "after_scan"}, "cve_sync") == {"mode": "after_scan"}
    with pytest.raises(schedule.ScheduleError):
        schedule.normalize({"mode": "after_scan"}, "scan")


@pytest.mark.asyncio
async def test_after_scan_pauses_the_sync_job():
    """"Nach Scan": the CVE sync has no runs of its own, the scan job keeps running."""
    from vigilance.core import scheduler as sched
    schedule.SCHEDULES["cve_sync"] = {"mode": "after_scan"}
    s = sched.init_scheduler()
    s.start(paused=True)
    try:
        assert s.get_job("cve_sync_job").next_run_time is None
        assert s.get_job("scan_job").next_run_time is not None
        sched.reschedule_jobs()  # reschedule_job would resume it
        assert s.get_job("cve_sync_job").next_run_time is None
        schedule.SCHEDULES.pop("cve_sync")
        sched.reschedule_jobs()  # back to the interval
        assert s.get_job("cve_sync_job").next_run_time is not None
    finally:
        s.shutdown(wait=False)
        sched.scheduler = None


@pytest.mark.asyncio
async def test_api_after_scan(client):  # noqa: F811
    r = await client.put("/api/settings/schedule/cve_sync", headers=AUTH, json={"mode": "after_scan"})
    assert r.status_code == 200, r.text
    assert r.json()["schedule"] == {"mode": "after_scan"}
    assert (await client.get("/api/settings")).json()["schedules"]["cve_sync"] == {"mode": "after_scan"}
    assert (await client.put("/api/settings/schedule/scan", headers=AUTH,
                             json={"mode": "after_scan"})).status_code == 400
    r = await client.put("/api/settings/schedule/cve_sync", headers=AUTH, json={"mode": "interval", "hours": 6})
    assert r.status_code == 200 and r.json()["schedule"] == {"mode": "interval", "hours": 6}
