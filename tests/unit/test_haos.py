"""Home Assistant OS VMs are recognised and, like Windows, cannot be switched on for a scan."""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.unit.test_views import AUTH, client  # noqa: F401  (fixture)
from vigilance.database import crud
from vigilance.discovery.orchestrator import DiscoveryOrchestrator


class VM:
    def __init__(self, name, status="running", vmid=112):
        self.name, self.status, self.vmid = name, status, vmid


class Client:
    def __init__(self, config=None, osinfo=None, error=None):
        self.config, self.osinfo, self.error = config or {"ostype": "l26"}, osinfo, error

    async def get_vm_config(self, node, vmid):
        return self.config

    async def get_vm_osinfo(self, node, vmid):
        if self.error:
            raise self.error
        return self.osinfo or {}


@pytest.mark.asyncio
@pytest.mark.parametrize("vm, cl, expected", [
    (VM("w11"), Client({"ostype": "win11"}), "windows"),
    # guest agent answers: it decides, whatever the name says
    (VM("vm1"), Client(osinfo={"id": "haos", "name": "Home Assistant OS"}), "haos"),
    (VM("haos-test"), Client(osinfo={"id": "debian", "name": "Debian GNU/Linux"}), None),
    # no agent / no right: name or description
    (VM("haos-18.1"), Client(error=RuntimeError("403")), "haos"),
    (VM("haos-18.1", "stopped"), Client(), "haos"),
    (VM("ha", "stopped"), Client({"ostype": "l26", "description": "<h2>Homeassistant OS VM</h2>"}), "haos"),
    (VM("homeassistant", "stopped"), Client(), None),  # may be Home Assistant on Debian
    (VM("chaos-lab", "stopped"), Client(), None),
    (VM("pve-vm", "stopped"), Client(), None),
])
async def test_detection(vm, cl, expected):
    orch = DiscoveryOrchestrator.__new__(DiscoveryOrchestrator)
    assert await orch._unsupported_os(cl, "pve", vm) == expected


@pytest.mark.asyncio
async def test_cannot_be_switched_on(client, any_engine):  # noqa: F811
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = await crud.get_proxmox_node_by_name(db, "pve") or \
            await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
        inv = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=112, name="haos-18.1", type="qemu",
                                          status="running")
        inv.os_id = "haos"
        await db.commit()
        hid = inv.id
    r = await client.put(f"/api/hosts/{hid}/scan", headers=AUTH, json={"enabled": True})
    assert r.status_code == 400 and "Home Assistant OS" in r.json()["detail"]
