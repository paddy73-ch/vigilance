"""Compilers / build tools: ask whether still needed; old kernel headers always suggested."""
import json

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.unit.test_views import AUTH, client  # noqa: F401  (fixture)
from vigilance.actions.runner import build_plan
from vigilance.database import crud
from vigilance.discovery.packages import PackageInfo
from vigilance.discovery.removal import orphan_headers, parse_build_output

PVE_OUTPUT = """##BROOT build-essential
##BROOT gcc
##BROOT g++
##BROOT dkms
##BOLD proxmox-headers-6.2
##BOLD proxmox-headers-6.2.16-19-pve
##BDKMS i915-sriov-dkms/6.5: added
##BOSIM proxmox-headers-6.2
##BOSIM proxmox-headers-6.2.16-19-pve
##BSIM dkms
##BSIM build-essential
##BSIM g++
##BSIM gcc
##BSIM cpp
##BSIM g++-14
##BSIM libstdc++-14-dev
##BSIM proxmox-headers-6.2
##BSIM proxmox-headers-6.2.16-19-pve
##BSIM sudo
##BPSIM dkms
##BPSIM build-essential
##BPSIM g++
##BPSIM gcc
##BPSIM proxmox-headers-6.2
##BPSIM proxmox-headers-6.2.16-19-pve
"""


def _pkg(name):
    return PackageInfo(name=name, version="1", manager="dpkg")


def test_orphan_headers():
    pkgs = [_pkg(n) for n in ("proxmox-kernel-7.0.14-30-pve-signed", "proxmox-kernel-7.0.6-2-pve-signed",
                              "proxmox-headers-6.2", "proxmox-headers-6.2.16-19-pve", "pve-headers-6.2",
                              "proxmox-headers-7.0.14-30-pve", "proxmox-headers-7.0", "gcc")]
    assert orphan_headers(pkgs) == ["proxmox-headers-6.2", "proxmox-headers-6.2.16-19-pve", "pve-headers-6.2"]
    assert orphan_headers([_pkg("linux-headers-6.1.0-9-amd64")]) == []  # no kernel at all: nothing to compare


def test_parse_pve():
    info = parse_build_output(PVE_OUTPUT)
    assert info["roots"] == ["build-essential", "gcc", "g++", "dkms"]
    assert info["dkms"] == ["i915-sriov-dkms/6.5: added"]
    assert info["extra"] == ["sudo"] and info["plain_extra"] == [] and info["old_extra"] == []
    assert parse_build_output("") is None


def test_plan_old_headers_always_tools_only_after_no():
    info = parse_build_output(PVE_OUTPUT)
    p = build_plan(info, None, "sudo -n ")
    assert p["command"] == "sudo -n apt-get purge -y proxmox-headers-6.2 proxmox-headers-6.2.16-19-pve"
    assert build_plan(info, "keep")["command"] == p["command"].replace("sudo -n ", "")
    # "no longer needed": autoremove would take sudo along, so sudo is kept (and marked manual) with "sudo+"
    p = build_plan(info, "remove")
    assert p["command"] == ("apt-get purge -y --autoremove build-essential gcc g++ dkms "
                            "proxmox-headers-6.2 proxmox-headers-6.2.16-19-pve sudo+")
    assert "sudo" in p["note"] and not p["skipped"]


def test_plan_autoremove_when_clean_and_skip_when_not():
    clean = {"roots": ["gcc"], "old_headers": [], "extra": [], "plain_extra": [], "old_extra": [], "error": None}
    assert build_plan(clean, "remove")["command"] == "apt-get purge -y --autoremove gcc"
    dirty = {**clean, "extra": ["myapp"], "plain_extra": ["myapp"]}  # myapp depends on gcc: cannot be kept
    p = build_plan(dirty, "remove")
    assert p["command"] is None and "myapp" in p["skipped"][0]["reason"]
    sneaky = {**clean, "extra": ["x; rm -rf /"], "plain_extra": []}
    assert build_plan(sneaky, "remove")["command"] == "apt-get purge -y --autoremove gcc"  # odd names never reach the shell
    assert build_plan({**clean, "error": "E: x"}, "remove")["skipped"][0]["reason"].startswith("Simulation")


@pytest.mark.asyncio
async def test_answer_in_api(client, any_engine):  # noqa: F811
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = await crud.get_proxmox_node_by_name(db, "pve") or \
            await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
        inv = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=133, name="buildbox", type="lxc",
                                          status="running")
        inv.removal_check = json.dumps({"build": parse_build_output(PVE_OUTPUT.replace("##BSIM sudo\n", ""))})
        await db.commit()
        hid = inv.id
    h = (await client.get(f"/api/hosts/{hid}")).json()["build_tools"]
    assert h["decision"] is None and "build-essential" not in (h["suggested_command"] or "")
    r = await client.put(f"/api/hosts/{hid}/build-tools", headers=AUTH, json={"needed": False})
    assert r.status_code == 200
    bt = r.json()["build_tools"]
    assert bt["decision"] == "remove" and bt["suggested_command"].startswith("apt-get purge -y --autoremove build-essential")
    r = await client.put(f"/api/hosts/{hid}/build-tools", headers=AUTH, json={"needed": None})
    assert r.json()["build_tools"]["decision"] is None
    assert (await client.put(f"/api/hosts/{hid}/build-tools", json={"needed": True})).status_code in (401, 403)
