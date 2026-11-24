"""Gotify and CVE sources as set in the UI (Verwaltung)."""
import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.unit.test_views import AUTH, client  # noqa: F401  (fixture)
from vigilance.config import NotificationsConfig, settings
from vigilance.core import notifications as notif
from vigilance.core import runtime_settings as rs
from vigilance.database import crud
from vigilance.database.models import VulnerabilityFinding


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(settings, "notifications", NotificationsConfig({"gotify": {"url": "http://env-gotify", "token": "env-secret"}}))
    monkeypatch.setattr(rs, "gotify_origin", "config")
    monkeypatch.setattr(rs, "SOURCE_OVERRIDES", {})
    import vigilance.core.scheduler as sched
    monkeypatch.setattr(sched, "apply_digest_job", lambda: None)


@pytest.mark.asyncio
async def test_gotify_settings_never_return_the_token(client, any_engine):
    g = (await client.get("/api/settings")).json()["gotify"]
    assert g["url"] == "http://env-gotify" and g["token_set"] and g["origin"] == "config"
    assert "env-secret" not in json.dumps(g)

    body = {"enabled": True, "url": "https://gotify.test/", "token": "", "min_severity": "CRITICAL",
            "digest_mode": True, "digest_interval_minutes": 30}
    assert (await client.put("/api/settings/gotify", json=body)).status_code == 401  # write access only
    r = await client.put("/api/settings/gotify", json=body, headers=AUTH)
    assert r.status_code == 200
    g = r.json()
    assert g == {"enabled": True, "ready": True, "url": "https://gotify.test", "token_set": True, "min_severity": "CRITICAL",
                 "digest_mode": True, "digest_interval_minutes": 30, "origin": "ui"}
    assert settings.notifications.gotify.token == "env-secret"  # empty token field = keep

    # stored in the DB and applied again at startup, also with the .env values gone
    settings.notifications = NotificationsConfig({})
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        await rs.load(db)
    gc = settings.notifications.gotify
    assert (gc.url, gc.token, gc.min_severity, gc.digest_mode, gc.digest_interval_minutes) == \
        ("https://gotify.test", "env-secret", "CRITICAL", True, 30)

    r = await client.put("/api/settings/gotify", json={**body, "url": "ftp://x"}, headers=AUTH)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_gotify_test_does_not_send_stored_token_elsewhere(client, monkeypatch):
    sent = []

    async def fake_send(config, title, message, priority=5, extras=None):
        sent.append((config.url, config.token))
        return True, None

    monkeypatch.setattr(notif, "send_gotify_message", fake_send)
    r = (await client.post("/api/settings/gotify/test", json={"url": "https://evil.example", "token": ""}, headers=AUTH)).json()
    assert not r["success"] and sent == []
    r = (await client.post("/api/settings/gotify/test", json={"url": "http://env-gotify/", "token": ""}, headers=AUTH)).json()
    assert r["success"] and sent == [("http://env-gotify", "env-secret")]
    r = (await client.post("/api/settings/gotify/test", json={"url": "https://new.example", "token": "typed"}, headers=AUTH)).json()
    assert r["success"] and sent[-1] == ("https://new.example", "typed")


@pytest.mark.asyncio
async def test_source_off_hides_findings_and_on_brings_them_back(client, any_engine, monkeypatch):
    started = []

    async def fake_sync(sources=None):
        started.append(sources)
        return {}

    import vigilance.core.scheduler as sched
    monkeypatch.setattr(sched, "trigger_cve_sync_now", fake_sync)
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)

    async def open_count():
        async with maker() as db:
            return len((await db.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.status == "open"))).scalars().all())

    before = await open_count()
    assert before > 0
    status = {s["source"]: s for s in (await client.get("/api/cve-sources")).json()}
    assert status["osv"]["enabled"] is True

    assert (await client.put("/api/cve-sources/osv", json={"enabled": False})).status_code == 401
    r = await client.put("/api/cve-sources/osv", json={"enabled": False}, headers=AUTH)
    assert r.status_code == 200 and r.json()["hidden"] == before
    assert await open_count() == 0
    assert (await client.get("/api/overview")).json()["kpis"]["patchable"] == 0
    async with maker() as db:  # the matching step leaves them hidden while the source is off
        from vigilance.cve.findings import match_findings
        from vigilance.database.models import DiscoveredTool
        tools = (await db.execute(select(DiscoveredTool))).scalars().all()
        await match_findings(db, tools, {}, {"debian"}, disabled_sources={"osv"})
        await db.commit()
    assert await open_count() == 0

    r = await client.put("/api/cve-sources/osv", json={"enabled": True}, headers=AUTH)
    assert r.status_code == 200 and r.json()["restored"] == before and r.json()["sync_started"]
    assert await open_count() == before
    assert started == [["osv"]]
    async with maker() as db:
        assert await crud.get_setting(db, "source_enabled.osv") == "true"

    assert (await client.put("/api/cve-sources/nope", json={"enabled": True}, headers=AUTH)).status_code == 404
