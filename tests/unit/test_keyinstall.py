"""Switch "Schlüssel in neue Container selbst eintragen"."""
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.unit.test_views import AUTH, client  # noqa: F401  (fixture)
from vigilance.config import ProxmoxNodeConfig, settings
from vigilance.database import crud
from vigilance.discovery import keyinstall, orchestrator
from vigilance.discovery.orchestrator import DiscoveryOrchestrator, ScanResult
from vigilance.discovery.osinfo import OSInfo
from vigilance.discovery.ssh import CommandResult

REJECTED = "SSH-Anmeldung abgelehnt: Der Schlüssel von Vigilance ist auf dem Host nicht eingetragen"


def test_install_command_only_takes_a_number():
    assert keyinstall.install_command(124) == "sudo -n /usr/local/sbin/vigilance-install-key 124"
    with pytest.raises(ValueError):
        keyinstall.install_command("124; rm -rf /")


@pytest.mark.asyncio
async def test_switch_is_stored(client):  # noqa: F811
    assert (await client.get("/api/settings")).json()["ssh_key_autoinstall"] is False
    r = await client.post("/api/settings", headers=AUTH, json={"ssh_key_autoinstall": True})
    assert r.status_code == 200
    assert (await client.get("/api/settings")).json()["ssh_key_autoinstall"] is True


async def _scan_ct(any_engine, monkeypatch, enabled, install_result, probes):
    cfg = ProxmoxNodeConfig({"name": "pve", "url": "x", "ssh": {"host": "192.0.2.49", "key_path": "/k"}})
    monkeypatch.setattr(type(settings), "proxmox_nodes", property(lambda self: [cfg]), raising=False)
    answers = list(probes)

    async def fake_probe(*a, **k):
        return answers.pop(0)
    monkeypatch.setattr(orchestrator, "probe_os", fake_probe)
    calls = []

    def fake_run(targets, command, timeout=None):
        calls.append((targets[0]["user"], targets[0]["host"], command))
        return {targets[0]["host"]: install_result}

    class Pool:
        run_parallel = staticmethod(fake_run)
    monkeypatch.setattr(keyinstall, "get_ssh_pool", lambda: Pool)
    maker = async_sessionmaker(any_engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as db:
        await keyinstall.set_autoinstall(db, enabled)
        node = await crud.create_proxmox_node(db, name="pve", url="x", token_id="t", token_secret="s")
        inv = await crud.upsert_inventory(db, proxmox_node_id=node.id, vmid=124, name="netalertx", type="lxc",
                                          status="running", ip_address="192.0.2.2")
        orch = DiscoveryOrchestrator(db)
        ssh_config = orch._get_ssh_config_for_target(node, inv)
        await orch._run_ssh_discovery(inv, ssh_config, 1, ScanResult())
        return inv, calls


def _ok(stdout="", stderr="", success=True):
    return CommandResult(host="192.0.2.49", command="x", stdout=stdout, stderr=stderr, exit_code=0 if success else 1,
                         success=success)


@pytest.mark.asyncio
async def test_key_is_put_in_and_scan_continues(any_engine, monkeypatch):
    inv, calls = await _scan_ct(any_engine, monkeypatch, True, _ok("Schluessel in CT 124 eingetragen"),
                                [(None, REJECTED), (OSInfo(id="debian", version_id="13", codename="trixie"), None)])
    assert calls == [("vigilance-scan", "192.0.2.49", "sudo -n /usr/local/sbin/vigilance-install-key 124")]
    assert inv.last_scan_status == "ok" and inv.os_version_id == "13"


@pytest.mark.asyncio
async def test_switch_off_does_nothing(any_engine, monkeypatch):
    inv, calls = await _scan_ct(any_engine, monkeypatch, False, _ok(), [(None, REJECTED)])
    assert calls == [] and inv.last_scan_status == "unreachable"


@pytest.mark.asyncio
async def test_missing_sudo_rule_is_explained(any_engine, monkeypatch):
    inv, _ = await _scan_ct(any_engine, monkeypatch, True,
                            _ok(stderr="sudo: a password is required", success=False), [(None, REJECTED)])
    assert inv.last_scan_status == "unreachable"
    assert "sudo-Regel für /usr/local/sbin/vigilance-install-key fehlt" in inv.last_scan_error


@pytest.mark.asyncio
async def test_other_errors_do_not_trigger(any_engine, monkeypatch):
    _, calls = await _scan_ct(any_engine, monkeypatch, True, _ok(), [(None, "Keine SSH-Verbindung zu 192.0.2.2 (Port 22)")])
    assert calls == []
