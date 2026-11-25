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
    from vigilance.cve.sync import annotate_enabled
    statuses = {st.source: st for st in annotate_enabled(await crud.get_all_sync_status(db_session))}
    assert statuses["ghsa"].status == "skipped"  # not shown as an error
    assert statuses["osv"].status == "success" and statuses["osv"].enabled is True
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


@pytest.mark.asyncio
async def test_fix_and_urgency_filters(db_session):
    db = db_session
    tools, osv_cve, tracker_cve = await _setup(db)
    # osv: fix available; second osv advisory: no fix, Debian "unimportant"
    await crud.upsert_cve_entry(db, cve_id="DEBIAN-CVE-2026-7", source="osv", severity="CRITICAL",
                                affected_ranges=json.dumps([{"type": "ECOSYSTEM", "repo": "openssl",
                                                             "ecosystem": "Debian:13", "introduced": "0"}]),
                                raw_data=json.dumps({"affected": [{"package": {"name": "openssl", "ecosystem": "Debian:13"},
                                                                   "ecosystem_specific": {"urgency": "unimportant"}}]}))
    await db.commit()
    key = tool_query_key(tools[0])
    await match_findings(db, tools, {"osv": DirectMatches(tool_query_key, {key: {"DEBIAN-CVE-2026-1", "DEBIAN-CVE-2026-7"}})},
                         {"osv", "debian"})
    await db.commit()

    assert await crud.count_filtered_findings(db, status="open") == 3
    assert await crud.count_filtered_findings(db, status="open", fix_available=True) == 2  # osv + tracker
    assert await crud.count_filtered_findings(db, status="open", fix_available=False) == 1
    assert await crud.count_filtered_findings(db, status="open", hide_unimportant=True) == 2
    assert await crud.count_filtered_findings(db, status="open", severity="CRITICAL", fix_available=False) == 1
    found = await crud.get_findings(db, status="open", tool_name="openssl", hide_unimportant=True)
    assert {f.cve.cve_id for f in found} == {"DEBIAN-CVE-2026-1", "CVE-2026-2"}
    stats = await crud.get_finding_stats(db)
    assert stats["open_with_fix"] == 2 and stats["open_unimportant"] == 1
    single = await crud.get_finding(db, found[0].id)
    assert single.tool.inventory.os_codename == "trixie"


@pytest.mark.asyncio
async def test_removed_packages_are_marked_and_not_matched(db_session):
    db = db_session
    tools, osv_cve, _ = await _setup(db)
    inv_id = tools[0].inventory_id
    keep = await crud.upsert_discovered_tool(db, inventory_id=inv_id, source_type="ssh_pkg", tool_name="curl",
                                             detected_version="8.14.1-2", package_manager="dpkg")
    assert await crud.mark_removed_tools(db, inv_id, "ssh_pkg", {keep.id}) == 1  # libssl3t64 is gone
    await db.commit()
    from vigilance.cve.sync import CVESyncOrchestrator
    loaded = await CVESyncOrchestrator(db)._load_tools()
    assert [t.tool_name for t in loaded] == ["curl"]
    again = await crud.upsert_discovered_tool(db, inventory_id=inv_id, source_type="ssh_pkg", tool_name="libssl3t64",
                                              detected_version="3.5.9-1~deb13u2", package_manager="dpkg")
    assert again.removed_at is None  # seen again -> active


@pytest.mark.asyncio
async def test_notify_new_findings_loads_relations(db_session, monkeypatch):
    """Regression: the Gotify message reads inventory.node; that lazy load failed (MissingGreenlet)."""
    from vigilance.config import GotifyConfig, NotificationsConfig, settings
    from vigilance.core import notifications as notif
    from vigilance.cve.sync import CVESyncOrchestrator

    db = db_session
    tools, osv_cve, _ = await _setup(db)
    hit = {"osv": DirectMatches(tool_query_key, {tool_query_key(tools[0]): {"DEBIAN-CVE-2026-1"}})}
    stats = await match_findings(db, tools, hit, {"osv", "debian"})
    await db.commit()
    db.expunge_all()  # like a fresh session: nothing beyond what match_findings set is loaded

    sent = []

    async def fake_send(config, title, message, priority=5, extras=None):
        sent.append((title, message))
        return True, None

    notifications = NotificationsConfig({"gotify": {"url": "http://gotify", "token": "x", "min_severity": "HIGH"}})
    monkeypatch.setattr(settings, "notifications", notifications)
    monkeypatch.setattr(settings, "public_url", "https://vigilance.test/")
    monkeypatch.setattr(notif, "send_gotify_message", fake_send)

    await CVESyncOrchestrator(db)._notify(stats)

    assert len(sent) == 1  # HIGH only; the MEDIUM tracker finding is below the threshold
    title, message = sent[0]
    assert "DEBIAN-CVE-2026-1" in message and "**Proxmox Node:** pve" in message
    assert "https://vigilance.test/hosts/" in message and "8006" not in message


@pytest.mark.asyncio
async def test_failed_package_manager_does_not_mark_its_packages_removed(db_session):
    """Regression: if one manager answers and another fails, only the answering one may mark removals."""
    from vigilance.discovery.orchestrator import DiscoveryOrchestrator, ScanResult
    from vigilance.discovery.packages import PackageInfo
    db = db_session
    tools, _, _ = await _setup(db)
    inv = tools[0].inventory
    apk_tool = await crud.upsert_discovered_tool(db, inventory_id=inv.id, source_type="ssh_pkg", tool_name="musl",
                                                 detected_version="1.2.5-r0", package_manager="apk")
    await db.commit()
    orch = DiscoveryOrchestrator.__new__(DiscoveryOrchestrator)
    orch.db = db
    # this scan: dpkg answered with curl only (libssl3t64 is gone), the apk query failed (no packages)
    await orch._save_package_discovery(inv, [PackageInfo(name="curl", version="8.14.1-2", manager="dpkg")], 1, ScanResult())
    await db.commit()
    state = {t.tool_name: t.removed_at for t in (await db.execute(select(DiscoveredTool))).scalars().all()}
    assert state["libssl3t64"] is not None  # dpkg answered without it -> removed
    assert state["musl"] is None and apk_tool.removed_at is None  # apk did not answer -> left alone


def test_cli_scan_now_reports_failure(monkeypatch):
    """Regression: `vigilance scan-now` printed "Scan completed" although the pipeline failed."""
    from typer.testing import CliRunner
    import vigilance.cli as cli
    import vigilance.core.scheduler as sched

    async def fake_create(db, scan_type):
        from types import SimpleNamespace
        return SimpleNamespace(id=7)

    class FakeSession:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def commit(self):
            pass

    async def failing_pipeline(**kwargs):
        raise RuntimeError("Proxmox nicht erreichbar")

    monkeypatch.setattr(sched, "async_session_maker", lambda: FakeSession())
    monkeypatch.setattr(sched.crud, "create_scan_run", fake_create)
    monkeypatch.setattr(sched, "run_pipeline", failing_pipeline)
    res = CliRunner().invoke(cli.app, ["scan-now"])
    assert res.exit_code == 1 and "Scan failed" in res.output and "completed" not in res.output
