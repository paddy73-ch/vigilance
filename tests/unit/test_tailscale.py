"""Tailscale security bulletins: classification of the RSS bodies, sync and matching."""
from html import escape

import pytest
from sqlalchemy import select

from vigilance.cve import tailscale as ts
from vigilance.database import crud
from vigilance.database.models import CVEEntry, VulnerabilityFinding


def _item(bid, body, date="Mon, 26 Oct 2026 00:00:00 GMT"):
    return (f"<item><title>{bid}</title><link>https://tailscale.com/security-bulletins/#{bid.lower()}</link>"
            f"<pubDate>{date}</pubDate><description>{escape(body)}</description></item>")


# Bodies follow the structure of the real feed (shortened, own wording)
NEW_CLIENT = ("<p><strong><em>Description</em></strong>: Serve could reach privileged sockets.</p>"
              "<h4>What happened?</h4><p>Details.</p><p>This vulnerability is fixed in Tailscale version 1.104.4 or newer.</p>")
OPERATOR = ("<p><strong><em>Description</em></strong>: A fallback in the Tailscale Kubernetes operator's proxy.</p>"
            "<p>This vulnerability is fixed in Tailscale version 1.104.7 or newer.</p>")
SERVER = ("<p><strong><em>Description</em></strong>: An issue in the Tailscale coordination server.</p>"
          "<p>No action is required.</p>")
OLD_FREEBSD = ("<p><strong><em>Reference</em></strong>: CVE-2023-28436</p><p><strong>Severity</strong>: Medium</p>"
               "<p>CVSS vector string: CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:N/A:N</p>"
               "<p><strong>Description</strong>: Group ID issue in Tailscale SSH on FreeBSD.</p>"
               "<p><strong>Affected platforms</strong>: FreeBSD</p><p><strong>Patched Tailscale client versions</strong>: v1.38.2 or later</p>")
OLD_ALL = ("<p>Reference: CVE-2022-41925</p><p>Severity: Low</p><p>Description: Peer API reachable from websites.</p>"
           "<p>Affected platforms: All</p><p>Patched Tailscale client versions: v1.32.3 or later</p><p>What happened?</p>")
LINUX_SPECIFIC = ("<p>Description: On Windows before Tailscale version 1.52 and on Linux before Tailscale 1.54, "
                  "serve allowed reading directories.</p>")
RANGE = ("<p>Description: Logging of auth keys.</p><p>Clients running Tailscale versions between 1.84.0 and 1.86.2 "
         "on macOS and iOS are affected. Tailscale version 1.86.4 redacts the auth key.</p>")
ABUSE = "<p>Description: Funnel abused for phishing.</p><p>We blocked the domains.</p>"

FEED = ("<?xml version='1.0'?><rss version='2.0'><channel><title>Security Bulletins on Tailscale</title>"
        + _item("TS-2026-016", NEW_CLIENT) + _item("TS-2026-018", OPERATOR) + _item("TS-2025-007", SERVER)
        + _item("TS-2023-003", OLD_FREEBSD) + _item("TS-2022-005", OLD_ALL) + _item("TS-2024-001", LINUX_SPECIFIC)
        + _item("TS-2025-005", RANGE) + _item("TS-2024-012", ABUSE) + "</channel></rss>")


def test_parse_and_classify():
    b = {x.cve_id: x for x in ts.parse_feed(FEED)}
    assert b["TS-2026-016"].raw_data["classification"] == "client"
    assert b["TS-2026-016"].affected_ranges[0].fixed == "1.104.4" and b["TS-2026-016"].affected_ranges[0].repo == "tailscale"
    assert b["TS-2026-016"].title == "Serve could reach privileged sockets."
    assert b["TS-2026-018"].raw_data["classification"] == "other" and b["TS-2026-018"].affected_ranges == []
    assert b["TS-2025-007"].raw_data["classification"] == "other"
    fb = b["TS-2023-003"]
    assert fb.raw_data["classification"] == "platform" and fb.raw_data["platforms"] == "FreeBSD"
    assert fb.aliases == ["CVE-2023-28436"] and fb.severity == "MEDIUM" and fb.affected_ranges == []
    assert fb.title == "Group ID issue in Tailscale SSH on FreeBSD."
    assert b["TS-2022-005"].affected_ranges[0].fixed == "1.32.3" and b["TS-2022-005"].severity == "LOW"
    assert b["TS-2024-001"].affected_ranges[0].fixed == "1.54"  # the Linux statement, not Windows 1.52
    r = b["TS-2025-005"].affected_ranges[0]
    assert (r.introduced, r.fixed) == ("1.84.0", "1.86.4")
    assert b["TS-2024-012"].raw_data["classification"] == "unparsed"
    s = ts.summary(list(b.values()))
    assert s.startswith("8 Bulletins: 4 mit Fix-Version") and "TS-2024-012" in s


@pytest.mark.asyncio
async def test_sync_matches_installed_tailscale(monkeypatch, db_session):
    from vigilance.cve import sync as sync_mod
    db = db_session
    node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
    inv = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=110, name="dev", type="lxc", status="running",
                                      os_id="debian", os_version_id="13")
    await crud.upsert_discovered_tool(db, inventory_id=inv.id, source_type="ssh_pkg", tool_name="tailscale",
                                      detected_version="1.90.6", package_manager="dpkg",
                                      source_name="tailscale", source_version="1.90.6")
    await db.commit()

    async def fake_fetch():
        return ts.parse_feed(FEED)
    monkeypatch.setattr(sync_mod.tailscale_mod, "fetch_bulletins", fake_fetch)
    results = await sync_mod.CVESyncOrchestrator(db).sync_all(sources=["tailscale"])
    assert results["tailscale"]["status"] == "success"
    rows = (await db.execute(select(CVEEntry.cve_id, VulnerabilityFinding.status, VulnerabilityFinding.fixed_version)
                             .join(VulnerabilityFinding, VulnerabilityFinding.cve_entry_id == CVEEntry.id))).all()
    found = {r[0]: (r[1], r[2]) for r in rows}
    # 1.90.6 < 1.104.4 -> affected; 1.32.3, 1.54, 1.86.4 are older fixes -> not affected
    assert found == {"TS-2026-016": ("open", "1.104.4")}
    st = await crud.get_sync_status(db, "tailscale")
    assert st.status == "success" and st.error_message.startswith("8 Bulletins")


@pytest.mark.asyncio
async def test_sync_skipped_without_tailscale(monkeypatch, db_session):
    from vigilance.cve import sync as sync_mod
    db = db_session
    node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
    inv = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=110, name="dev", type="lxc", status="running",
                                      os_id="debian", os_version_id="13")
    await crud.upsert_discovered_tool(db, inventory_id=inv.id, source_type="ssh_pkg", tool_name="curl",
                                      detected_version="8.14.1-2", package_manager="dpkg")
    await db.commit()

    async def boom():
        raise AssertionError("must not be fetched")
    monkeypatch.setattr(sync_mod.tailscale_mod, "fetch_bulletins", boom)
    results = await sync_mod.CVESyncOrchestrator(db).sync_all(sources=["tailscale"])
    assert results["tailscale"]["status"] == "skipped"
