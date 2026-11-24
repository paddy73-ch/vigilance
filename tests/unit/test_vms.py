"""VMs from config.yaml (`vms:`), scanned like the containers."""
import aiohttp
import pytest

from vigilance.config import ProxmoxNodeConfig
from vigilance.discovery.orchestrator import DiscoveryOrchestrator
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

    assert 300 not in invs  # not listed in config.yaml
    assert invs[150].last_scan_status == "unsupported" and "Windows" in invs[150].last_scan_error
    assert invs[112].last_scan_status == "stopped"
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
        await db.commit()
        monkeypatch.setattr(settings, "proxmox_nodes", [])
        assert {h["name"] for h in await host_summaries(db)} == {"ct"}
        assert [i.name for i in await _targets(db, None)] == ["ct"]
        monkeypatch.setattr(settings, "proxmox_nodes", [ProxmoxNodeConfig({"name": "pve", "vms": [201]})])
        assert {h["name"] for h in await host_summaries(db)} == {"ct", "pve-vm"}
        assert [i.name for i in await _targets(db, None)] == ["ct", "pve-vm"]  # "alle": containers and listed VMs
