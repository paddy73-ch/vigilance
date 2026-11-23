import json

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from vigilance.cve import osv as osv_mod
from vigilance.cve.findings import DirectMatches, match_findings
from vigilance.cve.osv import tool_query_key
from vigilance.database import crud
from vigilance.database.models import DiscoveredTool, Suppression, VulnerabilityFinding


async def _setup(db):
    node = await crud.create_proxmox_node(db, name="pve", url="https://pve:8006", token_id="t", token_secret="s")
    inv = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=110, name="dev", type="lxc",
                                      status="running", ip_address="192.0.2.110",
                                      os_id="debian", os_version_id="13", os_codename="trixie")
    tool = await crud.upsert_discovered_tool(db, inventory_id=inv.id, source_type="ssh_pkg", tool_name="libssl3t64",
                                             detected_version="3.5.9-1~deb13u1", package_manager="dpkg",
                                             source_name="openssl", source_version="3.5.9-1~deb13u1")
    osv_cve = await crud.upsert_cve_entry(db, cve_id="DEBIAN-CVE-2026-1", source="osv", severity="HIGH",
                                          affected_ranges=json.dumps([
                                              {"type": "ECOSYSTEM", "repo": "openssl", "ecosystem": "Debian:13",
                                               "introduced": "0", "fixed": "3.5.9-1~deb13u2"},
                                              {"type": "ECOSYSTEM", "repo": "openssl", "ecosystem": "Debian:14",
                                               "introduced": "0", "fixed": "3.6.0-1"}]))
    # Range-based source on the *source* package name (as the Debian tracker stores it)
    tracker_cve = await crud.upsert_cve_entry(db, cve_id="CVE-2026-2", source="debian", severity="MEDIUM",
                                              affected_ranges=json.dumps([
                                                  {"type": "DEBIAN", "repo": "openssl", "introduced": "0",
                                                   "fixed": "3.5.9-1~deb13u2"}]))
    # Substring trap: must not match "openssl"
    await crud.upsert_cve_entry(db, cve_id="CVE-2026-3", source="debian",
                                affected_ranges=json.dumps([{"type": "DEBIAN", "repo": "ssl", "introduced": "0",
                                                             "fixed": "99"}]))
    await db.commit()
    tools = (await db.execute(select(DiscoveredTool).options(selectinload(DiscoveredTool.inventory)))).scalars().all()
    return tools, osv_cve, tracker_cve


async def _findings(db):
    return {f.cve_entry_id: f for f in (await db.execute(select(VulnerabilityFinding))).scalars().all()}


@pytest.mark.asyncio
async def test_lifecycle_new_fixed_reopened(db_session):
    db = db_session
    tools, osv_cve, tracker_cve = await _setup(db)
    key = tool_query_key(tools[0])
    assert key == ("Debian:13", "openssl", "3.5.9-1~deb13u1")

    hit = {"osv": DirectMatches(tool_query_key, {key: {"DEBIAN-CVE-2026-1"}})}
    stats = await match_findings(db, tools, hit, {"osv", "debian"})
    await db.commit()
    f = await _findings(db)
    assert stats.new == 2 and set(f) == {osv_cve.id, tracker_cve.id}  # CVE-2026-3 ("ssl") not matched
    assert f[osv_cve.id].fixed_version == "3.5.9-1~deb13u2"  # fix for Debian:13, not forky

    # OSV sync failed this run -> its findings stay open
    stats = await match_findings(db, tools, {}, {"debian"})
    await db.commit()
    assert (await _findings(db))[osv_cve.id].status == "open"

    # OSV synced fine and no longer reports it -> fixed (kept, not deleted)
    stats = await match_findings(db, tools, {"osv": DirectMatches(tool_query_key, {})}, {"osv", "debian"})
    await db.commit()
    f = await _findings(db)
    assert stats.fixed == 1 and f[osv_cve.id].status == "fixed" and f[osv_cve.id].resolved_at is not None

    # Reported again -> reopened
    stats = await match_findings(db, tools, hit, {"osv", "debian"})
    await db.commit()
    f = await _findings(db)
    assert stats.reopened == 1 and f[osv_cve.id].status == "open" and f[osv_cve.id].resolved_at is None


@pytest.mark.asyncio
async def test_suppression_sets_status(db_session):
    db = db_session
    tools, osv_cve, _ = await _setup(db)
    db.add(Suppression(cve_id="DEBIAN-CVE-2026-1", reason="accepted risk"))
    await db.commit()
    key = tool_query_key(tools[0])
    stats = await match_findings(db, tools, {"osv": DirectMatches(tool_query_key, {key: {"DEBIAN-CVE-2026-1"}})},
                                 {"osv"})
    await db.commit()
    assert (await _findings(db))[osv_cve.id].status == "suppressed"
    assert all(nf.cve_entry_id != osv_cve.id for nf in stats.new_findings)


@pytest.mark.asyncio
async def test_osv_sync_only_queries_discovered_versions(monkeypatch, db_session):
    tools, _, _ = await _setup(db_session)
    calls = {"batch": [], "detail": []}

    def handler(request: httpx.Request):
        if request.url.path == "/v1/querybatch":
            body = json.loads(request.content)
            calls["batch"].append(body["queries"])
            q = body["queries"][0]
            if "page_token" not in q:
                return httpx.Response(200, json={"results": [{
                    "vulns": [{"id": "DEBIAN-CVE-2026-1", "modified": "2026-11-01T00:00:00Z"}],
                    "next_page_token": "p2"}]})
            return httpx.Response(200, json={"results": [{
                "vulns": [{"id": "DEBIAN-CVE-2026-9", "modified": "2026-11-02T00:00:00Z"}]}]})
        calls["detail"].append(request.url.path)
        vid = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"id": vid, "modified": "2026-11-02T00:00:00Z", "affected": []})

    class MockClient(osv_mod.OSVClient):
        def __init__(self):
            self.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(osv_mod, "OSVClient", MockClient)
    known = {"DEBIAN-CVE-2026-1": osv_mod._parse_date("2026-11-01T00:00:00Z")}  # unchanged -> not re-fetched
    outcome = await osv_mod.sync_osv_for_tools(tools, known)

    assert calls["batch"][0] == [{"package": {"name": "openssl", "ecosystem": "Debian:13"},
                                  "version": "3.5.9-1~deb13u1"}]
    assert len(calls["batch"]) == 2  # second call follows next_page_token
    assert calls["detail"] == ["/v1/vulns/DEBIAN-CVE-2026-9"]
    assert outcome.matches == {("Debian:13", "openssl", "3.5.9-1~deb13u1"): {"DEBIAN-CVE-2026-1", "DEBIAN-CVE-2026-9"}}


@pytest.mark.asyncio
async def test_orchestrator_end_to_end(monkeypatch, db_session):
    """sync_all: OSV results are stored and turned into findings; GHSA is skipped for dpkg-only hosts."""
    from vigilance.cve import sync as sync_mod
    from vigilance.cve.osv import OSVSyncOutcome, parse_vuln
    tools, _, _ = await _setup(db_session)

    async def fake_osv(tools_arg, known):
        key = ("Debian:13", "openssl", "3.5.9-1~deb13u1")
        vuln = parse_vuln({"id": "DEBIAN-CVE-2026-50", "modified": "2026-11-20T00:00:00Z",
                           "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                           "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:13"},
                                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                                                       {"fixed": "3.5.9-1~deb13u3"}]}]}]})
        return OSVSyncOutcome(cves=[vuln], matches={key: {"DEBIAN-CVE-2026-50"}}, queried=1)

    monkeypatch.setattr(sync_mod.osv_mod, "sync_osv_for_tools", fake_osv)
    orch = sync_mod.CVESyncOrchestrator(db_session)
    results = await orch.sync_all(sources=["osv", "ghsa"])
    assert results["osv"]["status"] == "success"
    assert results["ghsa"]["status"] == "skipped"
    entry = await crud.get_cve_entry(db_session, "DEBIAN-CVE-2026-50")
    assert entry.severity == "CRITICAL"
    f = (await db_session.execute(select(VulnerabilityFinding).where(
        VulnerabilityFinding.cve_entry_id == entry.id))).scalar_one()
    assert f.status == "open" and f.fixed_version == "3.5.9-1~deb13u3"
    # Stored with the current parser -> counted as known for the next run
    assert "DEBIAN-CVE-2026-50" in await orch._known_osv_records()


@pytest.mark.asyncio
async def test_one_finding_per_source_package(db_session):
    db = db_session
    tools, osv_cve, _ = await _setup(db)
    inv_id = tools[0].inventory_id
    for name in ("openssl", "libssl-dev"):
        await crud.upsert_discovered_tool(db, inventory_id=inv_id, source_type="ssh_pkg", tool_name=name,
                                          detected_version="3.5.9-1~deb13u1", package_manager="dpkg",
                                          source_name="openssl", source_version="3.5.9-1~deb13u1")
    await db.commit()
    tools = (await db.execute(select(DiscoveredTool).options(selectinload(DiscoveredTool.inventory)))).scalars().all()
    key = ("Debian:13", "openssl", "3.5.9-1~deb13u1")
    await match_findings(db, tools, {"osv": DirectMatches(tool_query_key, {key: {"DEBIAN-CVE-2026-1"}})}, {"osv"})
    await db.commit()
    rows = (await db.execute(select(VulnerabilityFinding).options(selectinload(VulnerabilityFinding.tool)).where(
        VulnerabilityFinding.cve_entry_id == osv_cve.id))).scalars().all()
    assert len(rows) == 1
    assert rows[0].tool.tool_name == "openssl"  # binary named like the source package is the representative
    details = json.loads(rows[0].match_details)
    assert details["binaries"] == ["libssl-dev", "libssl3t64", "openssl"]
    assert details["fix_available"] is True
