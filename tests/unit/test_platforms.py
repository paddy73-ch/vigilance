"""Advisories restricted to other operating systems (Go goos), and text hints."""
import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from vigilance.cve.findings import DirectMatches, match_findings
from vigilance.cve.osv import tool_query_key
from vigilance.cve.platforms import goos_restriction, not_for_host, os_hint
from vigilance.database import crud
from vigilance.database.models import DiscoveredTool, VulnerabilityFinding


def _rec(goos_lists, package="tailscale.com"):
    imports = [{"path": "x", **({"goos": g} if g is not None else {})} for g in goos_lists]
    return {"affected": [{"package": {"name": package, "ecosystem": "Go"},
                          "ecosystem_specific": {"imports": imports} if imports else {}}]}


def test_goos_restriction():
    assert goos_restriction(_rec([["freebsd"]])) == {"freebsd"}
    assert goos_restriction(_rec([["windows"], ["darwin", "windows"]])) == {"windows", "darwin"}
    assert goos_restriction(_rec([["windows"], None])) is None  # one import affects all systems
    assert goos_restriction(_rec([])) is None  # field missing (e.g. unreviewed entries)
    assert goos_restriction(_rec([["linux", "freebsd"]])) == {"linux", "freebsd"}
    assert not_for_host({"freebsd"}) and not not_for_host({"linux", "freebsd"}) and not not_for_host(None)


def test_os_hint():
    assert os_hint("Non-interactive Tailscale SSH sessions on FreeBSD may use the effective group ID") == "FreeBSD"
    assert os_hint("Path traversal on Windows in path/filepath") == "Windows"
    assert os_hint("Issue on Linux and Windows") is None
    assert os_hint("Heap overflow in libfoo") is None
    assert os_hint(None, "Affects users on macOS only") == "macOS"
    assert os_hint("Heap overflow", "On Debian and other Linux distributions ... on Windows") is None


@pytest.mark.asyncio
async def test_go_restriction_marks_not_affected_also_for_ghsa_alias(db_session):
    db = db_session
    node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
    inv = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=110, name="dev", type="lxc", status="running",
                                      os_id="debian", os_version_id="13")
    await crud.upsert_discovered_tool(db, inventory_id=inv.id, source_type="ssh_pkg", tool_name="tailscale",
                                      detected_version="1.38.1", package_manager="dpkg",
                                      source_name="tailscale", source_version="1.38.1")
    ranges = json.dumps([{"type": "SEMVER", "repo": "tailscale.com", "ecosystem": "Go",
                          "introduced": "1.34.0", "fixed": "1.38.2"}])
    go = await crud.upsert_cve_entry(db, cve_id="GO-2099-0001", source="osv", upstream_ids="CVE-2099-10001,GHSA-aaaa",
                                     affected_ranges=ranges, raw_data=json.dumps(_rec([["freebsd"]])))
    ghsa = await crud.upsert_cve_entry(db, cve_id="GHSA-aaaa", source="osv", upstream_ids="CVE-2099-10001,GO-2099-0001",
                                       affected_ranges=ranges, raw_data=json.dumps(_rec([])))
    other = await crud.upsert_cve_entry(db, cve_id="GO-2099-0002", source="osv", upstream_ids="CVE-2099-10002",
                                        affected_ranges=ranges, raw_data=json.dumps(_rec([])))
    await db.commit()
    tools = (await db.execute(select(DiscoveredTool).options(selectinload(DiscoveredTool.inventory)))).scalars().all()
    key = tool_query_key(tools[0])
    assert key == ("Go", "tailscale.com", "1.38.1")
    stats = await match_findings(db, tools, {"osv": DirectMatches(tool_query_key, {key: {"GO-2099-0001", "GHSA-aaaa",
                                                                                      "GO-2099-0002"}})}, {"osv"})
    await db.commit()
    f = {x.cve_entry_id: x for x in (await db.execute(select(VulnerabilityFinding))).scalars().all()}
    assert f[go.id].status == "not_affected" and json.loads(f[go.id].match_details)["goos"] == ["freebsd"]
    assert f[ghsa.id].status == "not_affected"  # inherits the restriction of the GO record
    assert f[other.id].status == "open" and f[other.id].fixed_version == "1.38.2"
    assert stats.new == 1  # only the open one counts as new
