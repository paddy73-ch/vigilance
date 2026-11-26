"""Containers through the Proxmox host (`pct exec`) instead of SSH to each container."""
import asyncio
import importlib.util
import threading
import time
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.unit.test_views import AUTH, client  # noqa: F401  (fixture)
from vigilance.config import ProxmoxNodeConfig, settings
from vigilance.database import crud
from vigilance.database.models import Base
from vigilance.discovery import access
from vigilance.discovery.orchestrator import DiscoveryOrchestrator, ScanResult
from vigilance.discovery.ssh import (PCT_SUDO_MISSING, CommandResult, PctClient, SSHClientPool, parse_pct_host,
                                     pct_host)


@pytest.fixture
def node_cfg(monkeypatch):
    cfg = ProxmoxNodeConfig({"name": "pve", "url": "x",
                             "ssh": {"host": "192.0.2.49", "key_path": "/k", "known_hosts": "/kh"}})
    monkeypatch.setattr(type(settings), "proxmox_nodes", property(lambda self: [cfg]), raising=False)
    monkeypatch.setattr(access, "OVERRIDES", {})
    return cfg


class FakeNode:
    host = "192.0.2.49"
    last_error = None

    def __init__(self, stderr="", code=0, stdout="ok"):
        self.calls, self.stderr, self.code, self.stdout = [], stderr, code, stdout

    def connect(self):
        return True

    def run_command(self, command, timeout=None):
        self.calls.append(command)
        return CommandResult(host=self.host, command=command, stdout=self.stdout, stderr=self.stderr,
                             exit_code=self.code, success=self.code == 0)


def test_pct_host_roundtrip():
    assert pct_host("pve", 124) == "pct:pve:124"
    assert parse_pct_host("pct:pve:124") == ("pve", 124)
    assert parse_pct_host("192.0.2.2") is None


def test_command_is_wrapped_and_quoted():
    node = FakeNode()
    c = PctClient("pct:pve:124", node, 124, threading.BoundedSemaphore(2))
    res = c.run_command("cat /etc/os-release 2>/dev/null || echo 'x y'")
    assert node.calls == ["sudo -n /usr/sbin/pct exec 124 -- sh -c 'cat /etc/os-release 2>/dev/null || echo '\"'\"'x y'\"'\"''"]
    assert res.success and res.host == "pct:pve:124" and res.command.startswith("cat /etc/os-release")


@pytest.mark.parametrize("stderr, expected", [
    ("sudo: a password is required", PCT_SUDO_MISSING),
    ("container '124' not running!", "Container 124 läuft nicht"),
    ("Configuration file 'nodes/pve/lxc/124.conf' does not exist", "gibt es auf dem Proxmox-Host nicht"),
])
def test_errors_are_explained(stderr, expected):
    c = PctClient("pct:pve:124", FakeNode(stderr=stderr, code=1), 124, threading.BoundedSemaphore(2))
    assert expected in c.run_command("true").stderr


def test_pool_goes_through_the_host_user(node_cfg):
    pool = SSHClientPool()
    c = pool.get_client("pct:pve:124", 22, "root", "/k", "/kh", 5)
    assert isinstance(c, PctClient) and c.vmid == 124
    assert (c._node.host, c._node.user, c._node.key_path) == ("192.0.2.49", "vigilance-scan", "/k")
    assert pool.get_client("pct:pve:100", 22, "root", "/k", "/kh", 5)._node is c._node  # one connection per node


@pytest.mark.asyncio
async def test_target_per_mode(any_engine, node_cfg):
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
        ct = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=124, name="netalertx", type="lxc",
                                         status="running", ip_address=None)
        vm = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=201, name="vm", type="qemu",
                                         status="running", ip_address="192.0.2.201")
        orch = DiscoveryOrchestrator(db)
        assert orch._get_ssh_config_for_target(node, ct)["host"] == "pct:pve:124"  # default, no IP needed
        assert orch._get_ssh_config_for_target(node, vm)["host"] == "192.0.2.201"  # VMs always SSH
        await access.set_mode(db, "pve", "ssh")
        assert orch._get_ssh_config_for_target(node, ct) is None  # SSH needs the IP
        ct.ip_address = "192.0.2.2"
        assert orch._get_ssh_config_for_target(node, ct)["host"] == "192.0.2.2"


@pytest.mark.asyncio
async def test_hosts_are_fetched_in_parallel(any_engine, node_cfg, monkeypatch):
    monkeypatch.setattr(settings, "ssh_parallel_jobs", 4, raising=False)
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
        orch = DiscoveryOrchestrator(db)
        invs = [await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=100 + i, name=f"ct{i}", type="lxc",
                                            status="running") for i in range(4)]
        orch._pending = [(inv, {"host": pct_host("pve", inv.vmid)}, "pve") for inv in invs]
        threads = set()

        async def slow_fetch(ssh_config, inv_type, vmid, node_name, autoinstall):
            threads.add(threading.get_ident())
            time.sleep(0.3)  # blocking, like paramiko
            return {"os_info": None, "error": f"x{vmid}"}
        monkeypatch.setattr(orch, "_fetch", slow_fetch)
        t0 = time.monotonic()
        await orch._run_pending(1, ScanResult())
        assert time.monotonic() - t0 < 0.9  # 4 × 0.3 s one after the other would be 1.2 s
        assert len(threads) == 4
        assert [i.last_scan_error for i in invs] == ["x100", "x101", "x102", "x103"]
        assert all(i.last_scan_at for i in invs)


@pytest.mark.asyncio
async def test_switch_in_api(client, node_cfg):  # noqa: F811
    nodes = (await client.get("/api/settings")).json()["proxmox_nodes"]
    assert nodes[0]["container_access"] == "pct" and nodes[0]["container_access_origin"] == "default"
    r = await client.put("/api/settings/container-access/pve", headers=AUTH, json={"mode": "ssh"})
    assert r.status_code == 200
    assert (await client.get("/api/settings")).json()["proxmox_nodes"][0]["container_access"] == "ssh"
    assert (await client.put("/api/settings/container-access/nope", headers=AUTH, json={"mode": "ssh"})).status_code == 404
    assert (await client.put("/api/settings/container-access/pve", headers=AUTH, json={"mode": "x"})).status_code == 422
    assert (await client.put("/api/settings/container-access/pve", json={"mode": "pct"})).status_code in (401, 403)


def test_migration_keeps_existing_installations_on_ssh():
    path = Path(__file__).parents[2] / "vigilance/database/migrations/versions/007_container_access.py"
    spec = importlib.util.spec_from_file_location("m007", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    eng = sa.create_engine("sqlite://")
    Base.metadata.create_all(eng)
    with eng.begin() as conn:
        conn.execute(sa.text("INSERT INTO proxmox_nodes (name, url, token_id, token_secret, verify_tls, created_at, "
                             "updated_at) VALUES ('pve', 'x', 't', 's', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            mod.upgrade()  # twice: no duplicate
        rows = conn.execute(sa.text("SELECT key, value FROM app_settings")).all()
    assert rows == [("container_access.pve", "ssh")]
