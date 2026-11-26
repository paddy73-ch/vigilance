"""Containers / VMs deleted in Proxmox disappear from Vigilance on the next scan."""
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vigilance.database import crud
from vigilance.database.models import (AppSetting, CVEEntry, DiscoveredTool, Inventory, Suppression,
                                       VulnerabilityFinding)
from vigilance.discovery.orchestrator import DiscoveryOrchestrator


async def _setup(db):
    node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
    invs = {}
    for vmid, typ in ((100, "lxc"), (101, "lxc"), (115, "qemu"), (201, "qemu")):
        invs[vmid] = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=vmid, name=f"g{vmid}", type=typ,
                                                 status="stopped")
    cve = CVEEntry(cve_id="CVE-2026-0001", source="osv")
    db.add(cve)
    await db.flush()
    for vmid in (101, 201):
        tool = DiscoveredTool(inventory_id=invs[vmid].id, source_type="ssh_pkg", tool_name="openssl")
        db.add(tool)
        await db.flush()
        db.add(VulnerabilityFinding(discovered_tool_id=tool.id, cve_entry_id=cve.id, status="open"))
        db.add(Suppression(cve_id="CVE-2026-0001", inventory_id=invs[vmid].id, reason="x"))
    db.add(AppSetting(key="vm_scan.201", value='{"enabled": true}'))
    await db.commit()
    return node


async def _count(db, model, *where):
    return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar()


@pytest.mark.asyncio
async def test_deleted_vm_and_ct_are_removed(any_engine):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = await _setup(db)
        orch = DiscoveryOrchestrator(db)
        assert await orch._remove_deleted_guests(node, "qemu", {115}) == ["g201 (qemu 201)"]
        assert await orch._remove_deleted_guests(node, "lxc", {100}) == ["g101 (lxc 101)"]
        await db.commit()
        left = (await db.execute(select(Inventory.vmid).order_by(Inventory.vmid))).scalars().all()
        assert left == [100, 115]
        assert await _count(db, DiscoveredTool) == 0
        assert await _count(db, VulnerabilityFinding) == 0
        assert await _count(db, Suppression) == 0
        assert await _count(db, AppSetting, AppSetting.key == "vm_scan.201") == 0


@pytest.mark.asyncio
async def test_empty_list_from_proxmox_removes_nothing(any_engine):
    """A token without VM.Audit sees an empty list; that must not wipe all hosts."""
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = await _setup(db)
        orch = DiscoveryOrchestrator(db)
        assert await orch._remove_deleted_guests(node, "qemu", set()) == []
        assert await orch._remove_deleted_guests(node, "lxc", set()) == []
        assert await _count(db, Inventory) == 4
