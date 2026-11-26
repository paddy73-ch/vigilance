"""VMs from config.yaml (`vms:`), scanned like the containers."""
import aiohttp
import pytest

from vigilance.config import ProxmoxNodeConfig
from vigilance.discovery.orchestrator import DiscoveryOrchestrator
from tests.unit.test_views import client  # noqa: F401  (fixture)
from vigilance.discovery.proxmox import ProxmoxVM


def test_vms_config_accepts_ids_and_dicts():
    cfg = ProxmoxNodeConfig({"name": "pve", "vms": [201, {"vmid": "202", "ip": "192.0.2.202"}, {"ip": "x"}, "bad"]})
    assert cfg.vms == [{"vmid": 201, "ip": None}, {"vmid": 202, "ip": "192.0.2.202"}]


def test_ip_from_agent_skips_loopback_and_bridges():
    data = {"result": [
        {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
        {"name": "docker0", "ip-addresses": [{"ip-address": "172.17.0.1", "ip-address-type": "ipv4"}]},
        {"name": "ens18", "ip-addresses": [{"ip-address": "fe80::1", "ip-address-type": "ipv6"},
                                           {"ip-address": "192.0.2.201", "ip-address-type": "ipv4"}]},
    ]}
    assert DiscoveryOrchestrator._ip_from_agent(data) == "192.0.2.201"
    assert DiscoveryOrchestrator._ip_from_agent({"result": []}) is None


def _vm(vmid, name, status="running"):
    return ProxmoxVM(vmid=vmid, name=name, status=status, node="pve", type="qemu", maxmem=0, maxdisk=0, cpu=0,
                     netin=0, netout=0, diskread=0, diskwrite=0, uptime=0)


class FakeClient:
    def __init__(self, agent_error=None):
        self.agent_error = agent_error

    async def get_vms(self, node):
        return [_vm(201, "pve-vm"), _vm(150, "w11"), _vm(112, "haos", "stopped"), _vm(300, "other")]

    async def get_vm_config(self, node, vmid):
        return {"ostype": "win11" if vmid == 150 else "l26"}

    async def get_vm_interfaces(self, node, vmid):
        if self.agent_error:
            raise self.agent_error
        return {"result": [{"name": "ens18", "ip-addresses": [{"ip-address": "192.0.2.201", "ip-address-type": "ipv4"}]}]}


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_error, expect_ip", [(None, "192.0.2.201"), ("403", None), ("down", None)])
async def test_discover_vms(db_session, monkeypatch, agent_error, expect_ip):
    from vigilance.config import settings
    from vigilance.database import crud
    from vigilance.database.models import Inventory
    from sqlalchemy import select

    monkeypatch.setattr(settings, "proxmox_nodes", [ProxmoxNodeConfig({"name": "pve", "vms": [201, 150, 112]})])
    err = {None: None,
           "403": aiohttp.ClientResponseError(request_info=None, history=(), status=403, message="Permission check failed"),
           "down": aiohttp.ClientResponseError(request_info=None, history=(), status=500, message="agent not running")}[agent_error]
    node = await crud.create_proxmox_node(db_session, name="pve", url="x", token_id="t", token_secret="s")
    orch = DiscoveryOrchestrator.__new__(DiscoveryOrchestrator)
    orch.db = db_session
    scanned = []

    async def fake_process(node_, vtype, target, scan_run_id, result):
        scanned.append((vtype, target.vmid, target.ip))

    monkeypatch.setattr(orch, "_process_inventory_target", fake_process)
    from vigilance.discovery.orchestrator import ScanResult
    await orch._discover_vms(FakeClient(err), node, 1, ScanResult())
    invs = {i.vmid: i for i in (await db_session.execute(select(Inventory))).scalars().all()}

    # not listed in config.yaml: recorded with name and state only, never scanned
    assert invs[300].last_scan_status == "not_configured" and invs[300].last_scan_at is None
    assert ("qemu", 300) not in [(v, i) for v, i, _ in scanned]
    assert invs[150].last_scan_status == "unsupported" and "Windows" in invs[150].last_scan_error
    # named "haos": Home Assistant OS, not scannable even when listed
    assert invs[112].last_scan_status == "unsupported" and invs[112].os_id == "haos"
    if expect_ip:
        assert scanned == [("qemu", 201, "192.0.2.201")]
    else:
        assert scanned == [] and invs[201].last_scan_status == "no_ip"
        assert ("VM.GuestAgent.Audit" in invs[201].last_scan_error) == (agent_error == "403")


@pytest.mark.asyncio
async def test_only_configured_vms_are_listed_and_targeted(any_engine, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from tests.unit.test_views import client as _client  # noqa: F401
    from vigilance.config import settings
    from vigilance.database import crud
    from vigilance.api.routes.actions import _targets
    from vigilance.api.routes.views import host_summaries

    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
        for vmid, name, typ in [(100, "ct", "lxc"), (201, "pve-vm", "qemu"), (150, "w11", "qemu")]:
            await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=vmid, name=name, type=typ, status="running",
                                        last_scan_status="ok", os_id="debian")
        await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=112, name="haos", type="qemu", status="stopped",
                                    last_scan_status="not_configured")
        await db.commit()
        monkeypatch.setattr(settings, "proxmox_nodes", [])
        hs = {h["name"]: h for h in await host_summaries(db)}
        assert set(hs) == {"ct", "haos", "pve-vm", "w11"}  # every VM is listed
        assert hs["haos"]["level"] == "stopped" and hs["haos"]["scan_configured"] is False
        assert hs["pve-vm"]["level"] == "not_scanned"  # running, not switched on: own group, not a problem
        assert [i.name for i in await _targets(db, None)] == ["ct"]
        monkeypatch.setattr(settings, "proxmox_nodes", [ProxmoxNodeConfig({"name": "pve", "vms": [201]})])
        hs = {h["name"]: h for h in await host_summaries(db)}
        assert hs["pve-vm"]["level"] != "not_scanned" and hs["w11"]["level"] == "not_scanned"
        assert [i.name for i in await _targets(db, None)] == ["ct", "pve-vm"]  # "alle": containers and listed VMs



@pytest.mark.asyncio
async def test_switch_vm_scan_in_ui(client, any_engine, monkeypatch):
    """Right-click "Für den Scan aktivieren": stored in the DB, wins over config.yaml, starts a scan."""
    import asyncio
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from tests.unit.test_views import AUTH
    from vigilance.config import configured_vm_ids, settings, vm_scan_entries
    from vigilance.core import runtime_settings as rs
    import vigilance.core.scheduler as sched
    from vigilance.database import crud

    monkeypatch.setattr(rs, "VM_SCAN_OVERRIDES", {})
    node_cfg = ProxmoxNodeConfig({"name": "pve", "vms": [{"vmid": 202, "ip": "192.0.2.202"}]})
    monkeypatch.setattr(settings, "proxmox_nodes", [node_cfg])
    scans = []

    async def fake_scan(*a, **k):
        scans.append(1)

    monkeypatch.setattr(sched, "trigger_scan_now", fake_scan)
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    node_id = client.hosts["adguard"].proxmox_node_id
    async with maker() as db:
        vm = await crud.upsert_inventory(db, proxmox_node_id=node_id, vmid=201, name="pve-vm", type="qemu", status="running")
        win = await crud.upsert_inventory(db, proxmox_node_id=node_id, vmid=150, name="w11", type="qemu",
                                          status="running", os_id="windows")
        cfg_vm = await crud.upsert_inventory(db, proxmox_node_id=node_id, vmid=202, name="vm2", type="qemu", status="running")
        await db.commit()

    r = await client.put(f"/api/hosts/{vm.id}/scan", json={"enabled": True, "ip": "192.0.2.201"})
    assert r.status_code == 401  # write access only
    r = await client.put(f"/api/hosts/{vm.id}/scan", json={"enabled": True, "ip": "192.0.2.201"}, headers=AUTH)
    assert r.status_code == 200 and r.json()["scan_started"]
    await asyncio.sleep(0)
    assert scans == [1]
    assert 201 in configured_vm_ids()
    assert {"vmid": 201, "ip": "192.0.2.201"} in vm_scan_entries(node_cfg)
    hs = {h["name"]: h for h in (await client.get("/api/hosts")).json()}
    assert hs["pve-vm"]["scan_configured"] and hs["pve-vm"]["scan_origin"] == "ui" and hs["w11"]["level"] == "not_scanned"
    assert "w11" not in {h["name"] for h in (await client.get("/api/overview")).json()["hosts"]}  # not a problem
    # switched off in the UI although listed in config.yaml
    r = await client.put(f"/api/hosts/{cfg_vm.id}/scan", json={"enabled": False}, headers=AUTH)
    assert r.status_code == 200 and 202 not in configured_vm_ids()
    assert (await client.put(f"/api/hosts/{win.id}/scan", json={"enabled": True}, headers=AUTH)).status_code == 400
    ct = client.hosts["adguard"].id
    assert (await client.put(f"/api/hosts/{ct}/scan", json={"enabled": True}, headers=AUTH)).status_code == 404
    assert (await client.put(f"/api/hosts/{vm.id}/scan", json={"enabled": True, "ip": "x"}, headers=AUTH)).status_code == 400

    rs.VM_SCAN_OVERRIDES.clear()  # loaded again from the DB, e.g. in the CLI process
    async with maker() as db:
        await rs.load_vm_overrides(db)
    assert rs.VM_SCAN_OVERRIDES[201] == {"enabled": True, "ip": "192.0.2.201"} and rs.VM_SCAN_OVERRIDES[202]["enabled"] is False
