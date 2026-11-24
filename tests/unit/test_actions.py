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


def test_blocked_reason(monkeypatch):
    inv = Inventory(type="node", status="running", last_scan_status="ok", os_id="debian")
    monkeypatch.setattr(runner, "node_config_for", lambda i: None)
    assert "scan_host" in runner.blocked_reason(inv)
    monkeypatch.setattr(runner, "node_config_for", lambda i: object())
    assert runner.blocked_reason(inv, "suggested") is None
    assert runner.blocked_reason(inv, "kernel_cleanup") == "Auf dem Proxmox-Host nicht verfügbar."
    inv.type = "qemu"
    assert runner.blocked_reason(inv) == "VMs werden nicht verändert."
    inv.type, inv.status = "lxc", "stopped"
    assert runner.blocked_reason(inv) == "Host läuft nicht."
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
    assert {"package": "libcurl4t64", "reason": "Fix nicht in den Paketquellen"} in p["skipped"]


@pytest.mark.asyncio
async def test_plan_full_upgrade_and_blocked(client, any_engine):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        p = await runner.plan(db, await db.get(Inventory, client.hosts["dev"].id), "full_upgrade")
        assert p["commands"][0] == "apt-get update" and p["commands"][1].endswith("full-upgrade")
        box = await runner.plan(db, await db.get(Inventory, client.hosts["box"].id), "full_upgrade")
        assert box["blocked"] and box["commands"] == []


def _patch_exec(monkeypatch, maker, calls, scans, detached=None):
    async def fake_run(target, body, timeout):
        calls.append((target["host"], body))
        return Res("Reading package lists...\nDone")

    async def fake_target(db, inv):
        return {"host": inv.name}

    async def fake_scan(*a, **k):
        scans.append(1)
        return 1

    import vigilance.core.scheduler as sched
    import vigilance.database.base as base
    monkeypatch.setattr(runner, "_run", fake_run)
    monkeypatch.setattr(runner, "_ssh_target", fake_target)
    monkeypatch.setattr(sched, "trigger_scan_now", fake_scan)
    monkeypatch.setattr(base, "async_session_maker", maker)
    if detached is not None:
        async def fake_detached(target, body, timeout):
            detached.append((target["host"], body))
            return Res("Setting up pve-manager ...")
        monkeypatch.setattr(runner, "_run_detached", fake_detached)


async def _wait_batch(client, batch):
    for _ in range(100):
        await asyncio.sleep(0.02)
        if not runner.is_busy():
            break
    return {x["host"]: x for x in (await client.get(f"/api/actions?batch_id={batch}")).json()["runs"]}


async def _node(client, any_engine):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node_inv = await crud.upsert_inventory(db, proxmox_node_id=client.hosts["adguard"].proxmox_node_id, vmid=0,
                                               name="pve", type="node", status="running", last_scan_status="ok",
                                               os_id="debian")
        await db.commit()
        return node_inv.id


@pytest.mark.asyncio
async def test_execute_batch_containers(client, any_engine, monkeypatch):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    calls, scans = [], []
    _patch_exec(monkeypatch, maker, calls, scans)
    ids = [client.hosts["adguard"].id, client.hosts["box"].id]
    r = await client.post("/api/actions", json={"kind": "full_upgrade", "host_ids": ids})
    assert r.status_code == 401  # token required
    r = await client.post("/api/actions", json={"kind": "full_upgrade", "host_ids": ids}, headers=AUTH)
    assert r.status_code == 200
    runs = await _wait_batch(client, r.json()["batch_id"])
    assert runs["adguard"]["status"] == "ok" and runs["adguard"]["exit_code"] == 0
    assert runs["box"]["status"] == "skipped"
    assert [c[0] for c in calls] == ["adguard"]  # only the running container
    assert calls[0][1].startswith("set -e\nexport DEBIAN_FRONTEND=noninteractive")
    assert "sudo" not in calls[0][1]
    assert scans == [1]  # rescan after the batch
    hist = (await client.get("/api/actions")).json()["runs"]
    assert "output" not in hist[0]
    assert (await client.get(f"/api/actions/{runs['adguard']['id']}")).json()["output"].endswith("Done")


@pytest.mark.asyncio
async def test_node_only_alone_and_confirmed(client, any_engine, monkeypatch):
    node_id = await _node(client, any_engine)
    both = {"kind": "suggested", "host_ids": [client.hosts["adguard"].id, node_id], "confirm_host": True}
    r = await client.post("/api/actions", json=both, headers=AUTH)
    assert r.status_code == 400 and "einzeln" in r.json()["detail"]
    r = await client.post("/api/actions", json={"kind": "full_upgrade", "host_ids": [node_id]}, headers=AUTH)
    assert r.status_code == 400 and "Bestätigung" in r.json()["detail"]


@pytest.mark.asyncio
async def test_node_upgrade_runs_detached_with_sudo(client, any_engine, monkeypatch):
    node_id = await _node(client, any_engine)
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    calls, scans, detached = [], [], []
    _patch_exec(monkeypatch, maker, calls, scans, detached)
    monkeypatch.setattr(runner, "node_config_for", lambda i: object() if i.type == "node" else None)
    body = {"kind": "full_upgrade", "host_ids": [node_id], "confirm_host": True}
    r = await client.post("/api/actions", json=body, headers=AUTH)
    assert r.status_code == 200
    runs = await _wait_batch(client, r.json()["batch_id"])
    assert runs["pve"]["status"] == "ok"
    assert calls == [] and len(detached) == 1  # never through the plain SSH run
    script = detached[0][1]
    assert "sudo -n apt-get update" in script and "sudo -n apt-get -y" in script and script.endswith("dist-upgrade")


@pytest.mark.asyncio
async def test_node_without_scan_host_is_skipped(client, any_engine, monkeypatch):
    node_id = await _node(client, any_engine)
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    calls, scans, detached = [], [], []
    _patch_exec(monkeypatch, maker, calls, scans, detached)
    monkeypatch.setattr(runner, "node_config_for", lambda i: None)
    r = await client.post("/api/actions", json={"kind": "full_upgrade", "host_ids": [node_id], "confirm_host": True},
                          headers=AUTH)
    runs = await _wait_batch(client, r.json()["batch_id"])
    assert runs["pve"]["status"] == "skipped" and calls == [] and detached == []


KERNEL = {"packages": [{"status": "ii", "name": "linux-image-rt-amd64"},
                       {"status": "ii", "name": "linux-image-6.12.118+deb13-rt-amd64"},
                       {"status": "rc", "name": "linux-image-6.12.95+deb13-rt-amd64"}],
          "would_remove": ["linux-image-rt-amd64", "initramfs-tools", "wireguard"], "extra": ["wireguard"],
          "running_kernel": "7.0.14-30-pve", "error": None}


async def _set_kernel(any_engine, host_id, info):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        inv = await db.get(Inventory, host_id)
        inv.removal_check = json.dumps({"checked_at": "x", "packages": {}, "kernel": info})
        await db.commit()
        return maker


@pytest.mark.asyncio
async def test_kernel_cleanup_plans(client, any_engine):
    maker = await _set_kernel(any_engine, client.hosts["dev"].id, KERNEL)
    async with maker() as db:
        inv = await db.get(Inventory, client.hosts["dev"].id)
        k = await runner.plan(db, inv, "kernel_cleanup")
        assert k["commands"] == ["apt-get purge -y --autoremove linux-image-rt-amd64 "
                                 "linux-image-6.12.118+deb13-rt-amd64 linux-image-6.12.95+deb13-rt-amd64"]
        s = await runner.plan(db, inv, "suggested")  # wireguard would go too: not automatic
        assert not any("--autoremove" in c for c in s["commands"])
        assert any(x["package"] == "Kernel im Container" and "wireguard" in x["reason"] for x in s["skipped"])
    await _set_kernel(any_engine, client.hosts["dev"].id, {**KERNEL, "extra": []})
    async with maker() as db:
        s = await runner.plan(db, await db.get(Inventory, client.hosts["dev"].id), "suggested")
        assert s["commands"][-1].startswith("apt-get purge -y --autoremove linux-image-rt-amd64")
        none = await runner.plan(db, await db.get(Inventory, client.hosts["adguard"].id), "kernel_cleanup")
        assert none["blocked"] and none["commands"] == []


def test_simulation_drops_sudo():
    s = runner.simulation_script(["sudo -n apt-get update", "sudo -n apt-get -y -o X full-upgrade"])
    assert "sudo" not in s and "apt-get -s " in s and "update" not in s.replace("full-upgrade", "")


@pytest.mark.asyncio
async def test_run_detached_polls_until_exit_code(monkeypatch):
    seen = []
    answers = iter(["", "", "0\n"])

    async def fake_run(target, body, timeout):
        seen.append(body)
        if "VIGILANCE_SCRIPT" in body:
            assert "nohup" in body
            return Res("VIGILANCE_STARTED")
        if body.startswith("cat"):
            return Res(next(answers))
        return Res("apt output")
    monkeypatch.setattr(runner, "_run", fake_run)
    monkeypatch.setattr(runner, "POLL_INTERVAL", 0)
    res = await runner._run_detached({"host": "pve"}, "set -e\nsudo -n apt-get update", 60)
    assert res.exit_code == 0 and res.stdout == "apt output"
    assert sum(1 for b in seen if b.startswith("cat")) == 3


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


@pytest.mark.asyncio
async def test_batch_runs_parallel_after_apt_proxy(client, any_engine, monkeypatch):
    """Hosts with apt-cacher-ng run first and alone; the rest in parallel, at most PARALLEL at once."""
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    calls, scans = [], []
    _patch_exec(monkeypatch, maker, calls, scans)
    async with maker() as db:
        node_id = client.hosts["adguard"].proxmox_node_id
        extra = {}
        for vmid, name in [(104, "cache"), (120, "web1"), (121, "web2")]:
            extra[name] = await crud.upsert_inventory(db, proxmox_node_id=node_id, vmid=vmid, name=name, type="lxc",
                                                      status="running", last_scan_status="ok", os_id="debian")
        await crud.upsert_discovered_tool(db, inventory_id=extra["cache"].id, source_type="ssh_pkg",
                                          tool_name="apt-cacher-ng", detected_version="3.7", package_manager="dpkg")
        await db.commit()

    events, active, peak = [], [0], [0]

    async def slow_run(target, body, timeout):
        active[0] += 1
        peak[0] = max(peak[0], active[0])
        events.append(("start", target["host"]))
        await asyncio.sleep(0.05)
        events.append(("end", target["host"]))
        active[0] -= 1
        return Res("ok")

    monkeypatch.setattr(runner, "_run", slow_run)
    monkeypatch.setattr(runner, "PARALLEL", 2)
    ids = [client.hosts["adguard"].id, client.hosts["dev"].id] + [h.id for h in extra.values()]
    r = await client.post("/api/actions", json={"kind": "full_upgrade", "host_ids": ids}, headers=AUTH)
    runs = await _wait_batch(client, r.json()["batch_id"])
    assert {h: x["status"] for h, x in runs.items()} == {n: "ok" for n in ["adguard", "dev", "cache", "web1", "web2"]}
    assert events[:2] == [("start", "cache"), ("end", "cache")]  # the apt proxy alone, before everyone else
    assert peak[0] == 2  # parallel, but not more than PARALLEL
    assert scans == [1]
