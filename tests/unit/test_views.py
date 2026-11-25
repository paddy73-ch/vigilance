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
    assert top["glib2.0"]["host_ids"] == [client.hosts["adguard"].id]  # one host -> link to its page
    assert top["curl"]["host_ids"] == sorted([client.hosts["adguard"].id, client.hosts["dev"].id])
    levels = {h["name"]: h["level"] for h in d["hosts"]}
    assert levels == {"adguard": "critical", "dev": "warning", "box": "stopped"}
    assert d["hosts"][0]["name"] == "adguard"  # most urgent first


@pytest.mark.asyncio
async def test_host_detail_commands(client):
    h = (await client.get(f"/api/hosts/{client.hosts['adguard'].id}")).json()
    assert h["upgrade_command"] == "apt-get update && apt-get install --only-upgrade curl libcurl4t64"
    # only the old binary is purged, never the current libglib2.0-0t64
    assert h["remove_command"] == "apt-get purge libglib2.0-0"
    assert h["remove_simulation"] == "apt-get -s purge libglib2.0-0"
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
    # an expiry with a time zone is converted to UTC, not just stripped of its offset
    r = await client.post("/api/exceptions", json={**body, "expires_at": "2099-06-01T12:00:00+02:00"}, headers=AUTH)
    assert r.json()["expires_at"].startswith("2099-06-01T10:00:00")


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


async def _add_dsa_and_check(any_engine, hosts, check):
    """A DSA for the same CVE as DEBIAN-CVE-2026-2001 on adguard's curl, plus a removal check."""
    from sqlalchemy import select
    from vigilance.database.models import CVEEntry, DiscoveredTool, Inventory
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        dsa = await crud.upsert_cve_entry(db, cve_id="DSA-6001-1", source="osv", severity="MEDIUM",
                                          upstream_ids="CVE-2026-2001,DEBIAN-CVE-2026-2001")
        curl = (await db.execute(select(DiscoveredTool).where(
            DiscoveredTool.inventory_id == hosts["adguard"].id, DiscoveredTool.tool_name == "curl"))).scalar_one()
        db.add(VulnerabilityFinding(discovered_tool_id=curl.id, cve_entry_id=dsa.id, status="open", fix_available=True,
                                    fixed_version="8.14.1-2+deb13u8", match_details=json.dumps({"binaries": ["curl"]}),
                                    first_seen_at=datetime.utcnow(), last_seen_at=datetime.utcnow()))
        inv = await db.get(Inventory, hosts["adguard"].id)
        inv.removal_check = json.dumps(check)
        await db.commit()


CHECK_OK = {"checked_at": "2026-11-24T08:00:00Z", "packages": {
    "libglib2.0-0": {"would_remove": ["libglib2.0-0"], "in_use": [], "external": [], "error": None,
                     "libraries": 3, "reinstallable": False}}}


@pytest.mark.asyncio
async def test_same_cve_is_one_vulnerability(client, any_engine):
    await _add_dsa_and_check(any_engine, client.hosts, CHECK_OK)
    # package list counts vulnerabilities, not advisories
    curl = next(i for i in (await client.get("/api/packages?fix=true")).json()["items"] if i["package"] == "curl")
    assert curl["advisories"] == 1
    # advisory list: one row with the DSA as additional ID
    d = (await client.get("/api/vulnerabilities?package=curl&fix=true")).json()
    assert d["total"] == 1 and d["items"][0]["label"] == "CVE-2026-2001"
    assert d["items"][0]["also"] in (["DSA-6001-1"], ["DEBIAN-CVE-2026-2001"])
    # host detail
    h = (await client.get(f"/api/hosts/{client.hosts['adguard'].id}")).json()
    g = next(g for g in h["patchable_list"] if g["package"] == "curl")
    assert g["count"] == 1 and g["findings"] == 2
    # drawer lists the other advisory
    v = (await client.get(f"/api/vulnerabilities/{d['items'][0]['cve_entry_id']}")).json()
    assert v["label"] == "CVE-2026-2001" and len(v["also"]) == 1


@pytest.mark.asyncio
async def test_exception_covers_all_advisories_of_a_cve(client, any_engine):
    await _add_dsa_and_check(any_engine, client.hosts, CHECK_OK)
    body = {"cve_id": "DEBIAN-CVE-2026-2001", "inventory_id": client.hosts["adguard"].id, "reason": "intern"}
    r = await client.post("/api/exceptions", json=body, headers=AUTH)
    assert r.json()["changed_findings"] == 2  # DEBIAN-CVE and DSA on adguard
    ex = (await client.get("/api/exceptions")).json()
    assert ex[0]["suppressed_findings"] == 2
    await client.delete(f"/api/exceptions/{ex[0]['id']}", headers=AUTH)
    assert (await client.get("/api/overview")).json()["kpis"]["suppressed"] == 0


@pytest.mark.asyncio
async def test_remedy_and_removal_risk(client, any_engine):
    await _add_dsa_and_check(any_engine, client.hosts, CHECK_OK)
    h = (await client.get(f"/api/hosts/{client.hosts['adguard'].id}")).json()
    glib = next(g for g in h["patchable_list"] if g["package"] == "glib2.0")
    assert glib["display_name"] == "libglib2.0-0"
    assert glib["remedy"]["action"] == "remove" and glib["remedy"]["command"] == "apt-get purge libglib2.0-0"
    assert glib["remedy"]["replacement"] == {"version": "2.84.4-3~deb13u5", "packages": ["libglib2.0-0t64 2.84.4-3~deb13u5"]}
    assert glib["remedy"]["risk"]["status"] == "ok" and glib["remedy"]["risk"]["libraries_checked"] is True
    assert glib["remedy"]["risk"]["not_reinstallable"] == ["libglib2.0-0"]
    curl = next(g for g in h["patchable_list"] if g["package"] == "curl")
    assert curl["remedy"]["target"] == "8.14.1-2+deb13u8" and curl["remedy"]["availability"]["status"] == "unknown"
    assert curl["remedy"]["command"] == "apt-get update && apt-get install --only-upgrade curl libcurl4t64"
    p = next(i for i in (await client.get("/api/packages?fix=true")).json()["items"] if i["package"] == "glib2.0")
    assert p["display_name"] == "libglib2.0-0" and p["remedy"]["hosts"][0]["risk"]["status"] == "ok"
    top = {t["package"]: t for t in (await client.get("/api/overview")).json()["top_packages"]}
    assert top["glib2.0"]["display_name"] == "libglib2.0-0"


@pytest.mark.asyncio
async def test_removal_risk_flags_dependents_and_users(client, any_engine):
    check = {"checked_at": "2026-11-24T08:00:00Z", "packages": {"libglib2.0-0": {
        "would_remove": ["libglib2.0-0", "some-tool"], "in_use": [{"pid": 42, "command": "/usr/bin/old"}],
        "external": ["/opt/app/bin/x"], "error": None}}}
    await _add_dsa_and_check(any_engine, client.hosts, check)
    h = (await client.get(f"/api/hosts/{client.hosts['adguard'].id}")).json()
    risk = next(g for g in h["patchable_list"] if g["package"] == "glib2.0")["remedy"]["risk"]
    assert risk["status"] == "check" and risk["extra"] == ["some-tool"]
    assert risk["in_use"][0]["pid"] == 42 and risk["external"] == ["/opt/app/bin/x"]
    assert h["remove_risk"]["status"] == "check"


@pytest.mark.asyncio
async def test_removal_risk_unknown_without_check(client):
    h = (await client.get(f"/api/hosts/{client.hosts['adguard'].id}")).json()
    risk = next(g for g in h["patchable_list"] if g["package"] == "glib2.0")["remedy"]["risk"]
    assert risk["status"] == "unknown"


def test_removal_risk_kernel_and_unprivileged():
    from vigilance.api.routes.views import removal_risk
    pkg = {"would_remove": [], "in_use": [], "external": [], "error": None, "libraries": 0, "reinstallable": True}
    check = {"checked_at": "x", "root": False, "kernel": "7.0.14-30-pve", "packages": {
        "proxmox-kernel-7.0.14-30-pve-signed": {**pkg, "would_remove": ["proxmox-kernel-7.0.14-30-pve-signed"]},
        "proxmox-kernel-7.0.14-29-pve-signed": {**pkg, "would_remove": ["proxmox-kernel-7.0.14-29-pve-signed"]},
        "libfoo1": {**pkg, "would_remove": ["libfoo1"], "libraries": 2}}}
    running = removal_risk(json.dumps(check), ["proxmox-kernel-7.0.14-30-pve-signed"])
    assert running["status"] == "check" and running["running_kernel"] == ["proxmox-kernel-7.0.14-30-pve-signed"]
    fallback = removal_risk(json.dumps(check), ["proxmox-kernel-7.0.14-29-pve-signed"])
    assert fallback["status"] == "ok" and fallback["kernel"] is True and fallback["running_kernel"] == []
    lib = removal_risk(json.dumps(check), ["libfoo1"])
    assert lib["process_check_limited"] is True and lib["kernel"] is False


@pytest.mark.asyncio
async def test_proxmox_host_is_listed(client, any_engine):
    from vigilance.database.models import ProxmoxNode
    from sqlalchemy import select
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = (await db.execute(select(ProxmoxNode))).scalar_one()
        await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=0, name="pve", type="node", status="running")
        await db.commit()
    hosts = {h["name"]: h for h in (await client.get("/api/hosts")).json()}
    assert hosts["pve"]["type"] == "node"


@pytest.mark.asyncio
async def test_node_host_scan_uses_own_user(any_engine, monkeypatch):
    from vigilance.config import ProxmoxNodeConfig
    from vigilance.discovery.orchestrator import DiscoveryOrchestrator, ScanResult
    cfg = ProxmoxNodeConfig({"name": "pve", "url": "x", "ssh": {"host": "192.0.2.49", "user": "root",
                                                                  "key_path": "/k", "scan_host": True}})
    monkeypatch.setattr(type(settings), "proxmox_nodes", property(lambda self: [cfg]), raising=False)
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
        orch = DiscoveryOrchestrator(db)
        seen = {}

        async def fake(inventory, ssh_config, scan_run_id, result):
            seen.update(ssh_config, inv=(inventory.type, inventory.vmid, inventory.name))
        monkeypatch.setattr(orch, "_run_ssh_discovery", fake)
        await orch._scan_node_host(node, 1, ScanResult())
        assert seen["user"] == "vigilance-scan" and seen["host"] == "192.0.2.49"
        assert seen["inv"] == ("node", 0, "pve")
        # containers still use the configured (root) user
        assert cfg.ssh_user == "root"
        cfg.scan_host = False
        seen.clear()
        await orch._scan_node_host(node, 1, ScanResult())
        assert seen == {}



def test_upgrade_availability():
    from vigilance.api.routes.views import upgrade_availability
    check = json.dumps({"lists_at": "2026-11-24T07:20:00Z", "candidates": {
        "curl": "8.14.1-2+deb13u8", "libcurl4t64": "8.14.1-2+deb13u8", "old": "1.0-1"}})
    assert upgrade_availability(None, ["curl"], "1")["status"] == "unknown"
    a = upgrade_availability(check, ["curl", "libcurl4t64"], "8.14.1-2+deb13u8")
    assert a["status"] == "available" and a["installable"] == ["curl", "libcurl4t64"]
    assert upgrade_availability(check, ["curl", "intel-microcode"], "8.14.1-2+deb13u8")["status"] == "partial"
    o = upgrade_availability(check, ["old"], "2.0-1")
    # a newer version below the fix must not be suggested as the remedy
    assert o["status"] == "older" and o["installable"] == [] and o["older"] == ["old"]
    m = upgrade_availability(check, ["intel-microcode"], "3.20260925.1~deb13u1")
    assert m["status"] == "missing" and m["installable"] == []


@pytest.mark.asyncio
async def test_upgrade_not_in_sources_has_no_command(client, any_engine):
    from vigilance.database.models import Inventory
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        inv = await db.get(Inventory, client.hosts["adguard"].id)
        inv.upgrade_check = json.dumps({"lists_at": "2026-11-24T07:20:00Z", "candidates": {}})
        await db.commit()
    h = (await client.get(f"/api/hosts/{client.hosts['adguard'].id}")).json()
    curl = next(g for g in h["patchable_list"] if g["package"] == "curl")
    assert curl["remedy"]["availability"]["status"] == "missing" and curl["remedy"]["command"] is None
    assert h["upgrade_command"] is None
    p = next(i for i in (await client.get("/api/packages?fix=true")).json()["items"] if i["package"] == "curl")
    assert p["remedy"]["availability"]["missing_on"] == ["adguard"]


@pytest.mark.asyncio
async def test_overview_lists_containers_with_kernel_packages(client, any_engine):
    from vigilance.database.models import Inventory
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    kernel = {"packages": [{"status": "ii", "name": "linux-image-6.12.118+deb13-rt-amd64"},
                           {"status": "rc", "name": "linux-image-6.12.105+deb13-rt-amd64"}],
              "would_remove": ["wireguard"], "extra": ["wireguard"], "running_kernel": "7.0.14-30-pve", "error": None}
    async with maker() as db:
        for name in ("dev", "box"):  # box is stopped and must not be listed
            inv = await db.get(Inventory, client.hosts[name].id)
            inv.removal_check = json.dumps({"packages": {}, "kernel": kernel})
        await db.commit()
    ks = (await client.get("/api/overview")).json()["kernels"]
    assert ks == [{"id": client.hosts["dev"].id, "name": "dev", "vmid": 110, "installed": 1, "remnants": 1,
                   "extra": ["wireguard"]}]


@pytest.mark.asyncio
async def test_dsa_exception_and_detail_cover_sibling_advisories(client, any_engine):
    """Regression: an exception created on a DSA row must also cover DEBIAN-CVE-… of the same CVE,
    and the detail view of the DSA must list the hosts that only have the sibling advisory."""
    await _add_dsa_and_check(any_engine, client.hosts, CHECK_OK)
    from sqlalchemy import select
    from vigilance.database.models import CVEEntry
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        dsa_id = (await db.execute(select(CVEEntry.id).where(CVEEntry.cve_id == "DSA-6001-1"))).scalar_one()
    detail = (await client.get(f"/api/vulnerabilities/{dsa_id}")).json()
    assert {a["host"] for a in detail["affected"]} == {"adguard", "dev"}  # dev only via DEBIAN-CVE-2026-2001
    assert len([a for a in detail["affected"] if a["host"] == "adguard"]) == 1  # one row per package

    r = await client.post("/api/exceptions", json={"cve_id": "DSA-6001-1", "reason": "nur intern"}, headers=AUTH)
    assert r.status_code == 200
    async with maker() as db:
        rows = (await db.execute(
            select(VulnerabilityFinding.status, CVEEntry.cve_id).join(CVEEntry, CVEEntry.id == VulnerabilityFinding.cve_entry_id)
            .where(CVEEntry.cve_id.in_(["DSA-6001-1", "DEBIAN-CVE-2026-2001"])))).all()
    assert rows and all(status == "suppressed" for status, _ in rows), rows
    ex = (await client.get("/api/exceptions")).json()
    assert ex[0]["suppressed_findings"] == len(rows)


@pytest.mark.asyncio
async def test_fixes_log(client, any_engine):
    """Log behind "behoben in 7 Tagen": one entry per package and day, with how it was fixed."""
    from datetime import datetime, timedelta
    from sqlalchemy import select
    from vigilance.database.models import DiscoveredTool
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    now = datetime.utcnow()
    before = (await client.get("/api/fixes?days=7")).json()
    async with maker() as db:
        rows = (await db.execute(select(VulnerabilityFinding, DiscoveredTool)
                                 .join(DiscoveredTool, DiscoveredTool.id == VulnerabilityFinding.discovered_tool_id))).all()
        by_host = {}
        for f, t in rows:
            by_host.setdefault((t.inventory_id, t.tool_name), []).append((f, t))
        ag = client.hosts["adguard"].id
        dev = client.hosts["dev"].id
        for f, t in by_host[(ag, "curl")]:  # updated
            f.status, f.resolved_at, f.matched_version = "fixed", now - timedelta(hours=1), "8.14.1-2"
            t.detected_version = "8.14.1-2+deb13u2"
        for f, t in by_host[(dev, "curl")]:  # removed, 10 days ago
            f.status, f.resolved_at = "fixed", now - timedelta(days=10)
            t.removed_at = now - timedelta(days=10)
        await db.commit()
        n_ag = len(by_host[(ag, "curl")])

    r = (await client.get("/api/fixes?days=7")).json()
    assert r["findings"] == before["findings"] + n_ag and len(r["entries"]) == len(before["entries"]) + 1
    e = next(x for x in r["entries"] if x["host"]["name"] == "adguard" and x["package"] == "curl")
    assert (e["how"], e["from_version"], e["to_version"]) == ("updated", "8.14.1-2", "8.14.1-2+deb13u2")
    assert e["vulnerabilities"] >= 1 and e["advisories"]
    assert r["entries"][0] is e  # newest first
    assert (await client.get("/api/overview")).json()["kpis"]["fixed_7d"] == r["findings"]  # same number as the KPI

    r = (await client.get("/api/fixes?days=30")).json()
    gone = next(x for x in r["entries"] if x["host"]["name"] == "dev" and x["package"] == "curl")
    assert gone["how"] == "removed" and gone["to_version"] is None
    r = (await client.get(f"/api/fixes?days=0&host_id={dev}")).json()
    assert {x["host"]["name"] for x in r["entries"]} == {"dev"}  # host filter
