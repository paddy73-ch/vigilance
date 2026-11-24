"""Remediation actions: planning, safety rules, simulation parsing, background execution (SSH mocked)."""
import asyncio
import json

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vigilance.actions import runner
from vigilance.database import crud
from vigilance.database.models import ActionRun, Inventory
from tests.unit.test_views import AUTH, CHECK_OK, _add_dsa_and_check, client  # noqa: F401  (fixture)


class Res:
    def __init__(self, out, code=0):
        self.stdout, self.stderr, self.exit_code, self.success = out, "", code, code == 0


SIM = """NOTE: This is only a simulation!
Inst curl [8.14.1-2+deb13u7] (8.14.1-2+deb13u8 Debian-Security:13/stable-security [amd64])
Inst libnew1 (1.0-1 Debian:13/stable [amd64])
Purg libglib2.0-0 [2.74.6-2+deb12u7]
Conf curl (8.14.1-2+deb13u8 Debian-Security:13/stable-security [amd64])"""


def test_parse_simulation():
    c = runner.parse_simulation(SIM)
    assert c["upgrade"] == ["curl 8.14.1-2+deb13u7 → 8.14.1-2+deb13u8"]
    assert c["install"] == ["libnew1 1.0-1"] and c["remove"] == ["libglib2.0-0"]


def test_simulation_script_never_updates_and_simulates():
    s = runner.simulation_script(["apt-get update", "apt-get install -y --only-upgrade curl", "apt-get purge -y x"])
    assert "apt-get update" not in s
    assert all(l.startswith("apt-get -s ") for l in s.splitlines()[1:])
    assert "Dir::Log::Planner=/dev/null" in s


def test_blocked_reason():
    inv = Inventory(type="node", status="running", last_scan_status="ok", os_id="debian")
    assert "nie" in runner.blocked_reason(inv)
    inv.type = "qemu"
    assert runner.blocked_reason(inv)
    inv.type, inv.status = "lxc", "stopped"
    assert runner.blocked_reason(inv) == "Container läuft nicht."
    inv.status = "running"
    assert runner.blocked_reason(inv) is None


@pytest.mark.asyncio
async def test_plan_suggested_skips_unchecked_removal(client, any_engine):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        inv = await db.get(Inventory, client.hosts["adguard"].id)
        p = await runner.plan(db, inv, "suggested")
    assert p["blocked"] is None
    assert p["commands"][0] == "apt-get update"
    assert p["commands"][1].endswith("--only-upgrade curl libcurl4t64")
    assert not any("purge" in c for c in p["commands"])
    assert p["skipped"] == [{"package": "libglib2.0-0", "reason": "Risikoprüfung noch nicht gelaufen"}]


@pytest.mark.asyncio
async def test_plan_suggested_with_ok_check_and_missing_fix(client, any_engine):
    await _add_dsa_and_check(any_engine, client.hosts, CHECK_OK)
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        inv = await db.get(Inventory, client.hosts["adguard"].id)
        inv.upgrade_check = json.dumps({"lists_at": None, "candidates": {"curl": "8.14.1-2+deb13u8"}})
        await db.commit()
        p = await runner.plan(db, inv, "suggested")
    assert p["commands"][-1] == "apt-get purge -y libglib2.0-0"
    assert p["commands"][1].endswith("--only-upgrade curl")
    assert {"package": "libcurl4t64", "reason": "Fix nicht in den Paketquellen des Containers"} in p["skipped"]


@pytest.mark.asyncio
async def test_plan_full_upgrade_and_blocked(client, any_engine):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        p = await runner.plan(db, await db.get(Inventory, client.hosts["dev"].id), "full_upgrade")
        assert p["commands"][0] == "apt-get update" and p["commands"][1].endswith("full-upgrade")
        box = await runner.plan(db, await db.get(Inventory, client.hosts["box"].id), "full_upgrade")
        assert box["blocked"] and box["commands"] == []


@pytest.mark.asyncio
async def test_execute_batch_never_touches_node(client, any_engine, monkeypatch):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node_inv = await crud.upsert_inventory(db, proxmox_node_id=client.hosts["adguard"].proxmox_node_id, vmid=0,
                                               name="pve", type="node", status="running", last_scan_status="ok",
                                               os_id="debian")
        await db.commit()
        node_id = node_inv.id

    calls = []

    async def fake_run(target, body, timeout):
        calls.append((target["host"], body))
        return Res("Reading package lists...\nDone")

    async def fake_target(db, inv):
        return {"host": inv.name}

    scans = []

    async def fake_scan(*a, **k):
        scans.append(1)
        return 1

    import vigilance.core.scheduler as sched
    import vigilance.database.base as base
    monkeypatch.setattr(runner, "_run", fake_run)
    monkeypatch.setattr(runner, "_ssh_target", fake_target)
    monkeypatch.setattr(sched, "trigger_scan_now", fake_scan)
    monkeypatch.setattr(base, "async_session_maker", maker)

    ids = [client.hosts["adguard"].id, client.hosts["box"].id, node_id]
    r = await client.post("/api/actions", json={"kind": "full_upgrade", "host_ids": ids})
    assert r.status_code == 401  # token required
    r = await client.post("/api/actions", json={"kind": "full_upgrade", "host_ids": ids}, headers=AUTH)
    assert r.status_code == 200
    batch = r.json()["batch_id"]
    for _ in range(50):
        await asyncio.sleep(0.02)
        if not runner.is_busy():
            break
    runs = {x["host"]: x for x in (await client.get(f"/api/actions?batch_id={batch}")).json()["runs"]}
    assert runs["adguard"]["status"] == "ok" and runs["adguard"]["exit_code"] == 0
    assert runs["box"]["status"] == "skipped"
    assert runs["pve"]["status"] == "skipped" and "nie" in runs["pve"]["output"]
    assert [c[0] for c in calls] == ["adguard"]  # only the running container
    assert calls[0][1].startswith("set -e\nexport DEBIAN_FRONTEND=noninteractive")
    assert scans == [1]  # rescan after the batch
    # history without output, single run with output
    hist = (await client.get("/api/actions")).json()["runs"]
    assert "output" not in hist[0]
    assert (await client.get(f"/api/actions/{runs['adguard']['id']}")).json()["output"].endswith("Done")


@pytest.mark.asyncio
async def test_all_targets_exclude_node(client, any_engine):
    from vigilance.api.routes.actions import _targets
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        await crud.upsert_inventory(db, proxmox_node_id=client.hosts["adguard"].proxmox_node_id, vmid=0,
                                    name="pve", type="node", status="running")
        await db.commit()
        names = [i.name for i in await _targets(db, None)]
    assert names == ["adguard", "dev"]


@pytest.mark.asyncio
async def test_mark_interrupted(any_engine):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        db.add(ActionRun(batch_id="b", host_name="x", kind="suggested", status="running"))
        await db.commit()
        assert await runner.mark_interrupted(db) == 1
        await db.commit()
        run = (await db.execute(select(ActionRun))).scalar_one()
        assert run.status == "interrupted"
