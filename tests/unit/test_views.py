"""Aggregated UI endpoints, obsolete-package detection, exceptions - on SQLite and PostgreSQL."""
import json
from datetime import datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vigilance.config import settings
from vigilance.core import auth_token
from vigilance.database import crud
from vigilance.database.base import get_db
from vigilance.database.models import VulnerabilityFinding
from vigilance.main import app


async def _seed(db):
    node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
    hosts = {}
    for vmid, name, status in [(100, "adguard", "running"), (110, "dev", "running"), (103, "box", "stopped")]:
        hosts[name] = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=vmid, name=name, type="lxc",
                                                  status=status, os_id="debian", os_version_id="13", os_codename="trixie")
    hosts["adguard"].last_scan_status = "ok"
    hosts["dev"].last_scan_status = "ok"
    hosts["box"].last_scan_status = "stopped"

    def tool(host, name, src, ver):
        return crud.upsert_discovered_tool(db, inventory_id=hosts[host].id, source_type="ssh_pkg", tool_name=name,
                                           detected_version=ver, package_manager="dpkg", source_name=src, source_version=ver)

    # adguard: glib leftover from bookworm next to the trixie version, plus curl with a real update
    old_glib = await tool("adguard", "libglib2.0-0", "glib2.0", "2.74.6-2+deb12u7")
    await tool("adguard", "libglib2.0-0t64", "glib2.0", "2.84.4-3~deb13u5")
    curl = await tool("adguard", "curl", "curl", "8.14.1-2+deb13u7")
    libcurl = await tool("adguard", "libcurl4t64", "curl", "8.14.1-2+deb13u7")
    dev_curl = await tool("dev", "curl", "curl", "8.14.1-2+deb13u7")
    gone = await tool("dev", "oldpkg", "oldpkg", "1.0")
    gone.removed_at = datetime.utcnow()

    def cve(cid, sev, cvss=None, upstream=None):
        return crud.upsert_cve_entry(db, cve_id=cid, source="osv", severity=sev, cvss_score=cvss, title=upstream,
                                     upstream_ids=upstream, references=json.dumps([{"url": "javascript:x"}]))
    c1 = await cve("DEBIAN-CVE-2024-52533", "CRITICAL", 9.8, "CVE-2024-52533")
    c2 = await cve("DEBIAN-CVE-2026-2001", "MEDIUM", 6.1, "CVE-2026-2001")
    c3 = await cve("DEBIAN-CVE-2026-3001", "HIGH", 7.5, "CVE-2026-3001")

    def finding(t, c, fix, urgency=None, status="open", resolved=None):
        f = VulnerabilityFinding(discovered_tool_id=t.id, cve_entry_id=c.id, status=status, fix_available=bool(fix),
                                 fixed_version=fix, urgency=urgency, matched_version=t.detected_version,
                                 match_details=json.dumps({"binaries": [t.tool_name]}),
                                 first_seen_at=datetime.utcnow(), last_seen_at=datetime.utcnow(), resolved_at=resolved)
        db.add(f)
        return f
    finding(old_glib, c1, "2.84.4-3~deb13u5")
    finding(curl, c2, "8.14.1-2+deb13u8")
    finding(dev_curl, c2, "8.14.1-2+deb13u8")
    finding(dev_curl, c3, None, urgency="unimportant")
    finding(libcurl, c3, None)
    finding(gone, c3, None, status="fixed", resolved=datetime.utcnow() - timedelta(days=2))
    await db.commit()
    return hosts


@pytest_asyncio.fixture
async def client(any_engine, monkeypatch):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with maker() as session:
            yield session
            await session.commit()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(settings, "api_token", "test-token")
    auth_token.reset_failures()
    async with maker() as db:
        hosts = await _seed(db)
    transport = httpx.ASGITransport(app=app, client=("192.0.2.47", 51000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        c.hosts = hosts
        yield c
    app.dependency_overrides.clear()


AUTH = {"Authorization": "Bearer test-token"}


@pytest.mark.asyncio
async def test_overview(client):
    d = (await client.get("/api/overview")).json()
    k = d["kpis"]
    assert (k["patchable"], k["patchable_crit_high"], k["without_fix"], k["without_fix_unimportant"], k["fixed_7d"]) == (3, 1, 2, 1, 1)
    assert (k["patchable_upgrade"], k["patchable_remove"]) == (2, 1)
    top = {t["package"]: t for t in d["top_packages"]}
    assert top["glib2.0"]["action"] == "remove" and top["glib2.0"]["severity"] == "CRITICAL"
    assert top["curl"]["action"] == "upgrade" and top["curl"]["hosts"] == 2
    levels = {h["name"]: h["level"] for h in d["hosts"]}
    assert levels == {"adguard": "critical", "dev": "warning", "box": "stopped"}
    assert d["hosts"][0]["name"] == "adguard"  # most urgent first


@pytest.mark.asyncio
async def test_host_detail_commands(client):
    h = (await client.get(f"/api/hosts/{client.hosts['adguard'].id}")).json()
    assert h["upgrade_command"] == "apt-get update && apt-get install --only-upgrade curl libcurl4t64"
    # only the old binary is purged, never the current libglib2.0-0t64
    assert h["remove_command"] == "apt-get -s purge libglib2.0-0"
    pkgs = {p["package"]: p for p in h["patchable_list"]}
    assert pkgs["glib2.0"]["obsolete"] is True and pkgs["curl"]["obsolete"] is False
    assert pkgs["curl"]["fixed_version"] == "8.14.1-2+deb13u8"
    dev = (await client.get(f"/api/hosts/{client.hosts['dev'].id}")).json()
    assert dev["tools"] == 1  # removed package not counted
    assert [g["package"] for g in dev["fixed_list"]] == ["oldpkg"]
    assert (await client.get("/api/hosts/99999")).status_code == 404


@pytest.mark.asyncio
async def test_packages_and_filters(client):
    d = (await client.get("/api/packages?fix=true")).json()
    assert d["total"] == 2
    curl = next(i for i in d["items"] if i["package"] == "curl")
    assert curl["hosts"] == 2 and curl["action"] == "upgrade" and [h["name"] for h in curl["host_list"]] == ["adguard", "dev"]
    assert (await client.get("/api/packages?fix=false&hide_unimportant=true")).json()["total"] == 1
    assert (await client.get("/api/packages?q=CVE-2024-52533")).json()["items"][0]["package"] == "glib2.0"
    assert (await client.get("/api/packages?severity=CRITICAL,HIGH")).json()["total"] == 2
    assert (await client.get(f"/api/packages?host_id={client.hosts['dev'].id}&sort=name")).json()["total"] == 1


@pytest.mark.asyncio
async def test_vulnerabilities_and_detail(client):
    d = (await client.get("/api/vulnerabilities?package=curl")).json()
    assert [i["id"] for i in d["items"]] == ["DEBIAN-CVE-2026-3001", "DEBIAN-CVE-2026-2001"]  # HIGH before MEDIUM
    vid = d["items"][1]["cve_entry_id"]
    v = (await client.get(f"/api/vulnerabilities/{vid}")).json()
    assert {a["host"] for a in v["affected"]} == {"adguard", "dev"}
    assert all(l["url"].startswith("http") for l in v["links"])  # javascript: reference dropped
    assert v["links"][0]["url"] == "https://security-tracker.debian.org/tracker/CVE-2026-2001"


@pytest.mark.asyncio
async def test_exceptions_apply_immediately(client):
    body = {"cve_id": "DEBIAN-CVE-2026-2001", "inventory_id": client.hosts["dev"].id, "reason": "nur intern erreichbar"}
    assert (await client.post("/api/exceptions", json=body)).status_code == 401  # token required
    r = await client.post("/api/exceptions", json=body, headers=AUTH)
    assert r.status_code == 200 and r.json()["changed_findings"] == 1
    k = (await client.get("/api/overview")).json()["kpis"]
    assert k["patchable"] == 2 and k["suppressed"] == 1
    ex = (await client.get("/api/exceptions")).json()
    assert ex[0]["host"] == "dev" and ex[0]["suppressed_findings"] == 1
    r = await client.delete(f"/api/exceptions/{ex[0]['id']}", headers=AUTH)
    assert r.json()["changed_findings"] == 1
    assert (await client.get("/api/overview")).json()["kpis"]["patchable"] == 3
    bad = await client.post("/api/exceptions", json={**body, "cve_id": "NOPE-1"}, headers=AUTH)
    assert bad.status_code == 404


@pytest.mark.asyncio
async def test_snapshot(any_engine):
    from vigilance.core.snapshots import write_daily_snapshot
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        await _seed(db)
        snap = await write_daily_snapshot(db)
        await write_daily_snapshot(db)  # same day: overwritten, not duplicated
        await db.commit()
        assert (snap.patchable, snap.without_fix, snap.fixed_total) == (3, 2, 1)
        assert json.loads(snap.patchable_by_severity) == {"CRITICAL": 1, "MEDIUM": 2}
