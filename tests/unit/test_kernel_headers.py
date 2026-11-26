"""Kernel CVEs on packages that only hold kernel headers (linux-libc-dev) are "not affected"."""
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from vigilance.cve.findings import kernel_headers_only, match_findings
from vigilance.database import crud
from vigilance.database.models import DiscoveredTool, VulnerabilityFinding
from tests.unit.test_platforms import DirectMatches, tool_query_key


@pytest.mark.parametrize("source, names, expected", [
    ("linux", ["linux-libc-dev"], True),
    ("linux", ["linux-libc-dev:amd64", "linux-headers-6.12.118-amd64", "linux-kbuild-6.12.118"], True),
    ("linux", ["linux-libc-dev", "linux-image-6.12.118-amd64"], False),  # a real Debian kernel is installed
    ("linux", ["linux-image-amd64"], False),
    ("linux-base", ["linux-base"], False),
    ("glibc", ["libc6-dev"], False),
])
def test_kernel_headers_only(source, names, expected):
    tool = SimpleNamespace(source_name=source, tool_name=names[0])
    details = {"binaries": names} if len(names) > 1 else {}
    assert kernel_headers_only(tool, details) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize("binaries, expected", [(["linux-libc-dev"], "not_affected"),
                                                (["linux-libc-dev", "linux-image-6.12.118-amd64"], "open")])
async def test_match_marks_headers_not_affected(db_session, binaries, expected):
    db = db_session
    node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
    inv = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=0, name="pve", type="node", status="running",
                                      os_id="debian", os_version_id="13")
    for b in binaries:
        await crud.upsert_discovered_tool(db, inventory_id=inv.id, source_type="ssh_pkg", tool_name=b,
                                          detected_version="6.12.118-1", package_manager="dpkg",
                                          source_name="linux", source_version="6.12.118-1")
    cve = await crud.upsert_cve_entry(db, cve_id="CVE-2099-20001", source="debian")
    await db.commit()
    tools = (await db.execute(select(DiscoveredTool).options(selectinload(DiscoveredTool.inventory)))).scalars().all()
    keys = {tool_query_key(t) for t in tools}
    await match_findings(db, tools, {"debian": DirectMatches(tool_query_key, {k: {"CVE-2099-20001"} for k in keys})},
                         {"debian"})
    await db.commit()
    f = (await db.execute(select(VulnerabilityFinding))).scalars().all()
    assert [x.status for x in f] == [expected]
    assert json.loads(f[0].match_details).get("headers_only", False) is (expected == "not_affected")
