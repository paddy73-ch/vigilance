import pytest
from datetime import datetime

from vigilance.database import crud
from vigilance.database.models import ProxmoxNode, Inventory, DiscoveredTool, CVEEntry, VulnerabilityFinding


@pytest.mark.asyncio
async def test_create_proxmox_node(db_session):
    node = await crud.create_proxmox_node(
        db_session,
        name="test-node",
        url="https://proxmox.example.com:8006",
        token_id="vigilance@pam",
        token_secret="secret",
    )
    assert node.id is not None
    assert node.name == "test-node"
    assert node.url == "https://proxmox.example.com:8006"


@pytest.mark.asyncio
async def test_get_proxmox_node(db_session):
    node = await crud.create_proxmox_node(
        db_session,
        name="test-node-2",
        url="https://proxmox2.example.com:8006",
        token_id="vigilance@pam",
        token_secret="secret",
    )
    fetched = await crud.get_proxmox_node(db_session, node.id)
    assert fetched is not None
    assert fetched.name == "test-node-2"


@pytest.mark.asyncio
async def test_upsert_inventory(db_session):
    # First create a node
    node = await crud.create_proxmox_node(
        db_session,
        name="node-for-inv",
        url="https://proxmox.example.com:8006",
        token_id="vigilance@pam",
        token_secret="secret",
    )

    inv = await crud.upsert_inventory(
        db_session,
        proxmox_node_id=node.id,
        vmid=100,
        name="test-vm",
        type="qemu",
        status="running",
        ip_address="192.168.1.100",
    )
    assert inv.id is not None
    assert inv.vmid == 100
    assert inv.name == "test-vm"

    # Update
    inv2 = await crud.upsert_inventory(
        db_session,
        proxmox_node_id=node.id,
        vmid=100,
        name="test-vm-updated",
        type="qemu",
        status="stopped",
    )
    assert inv2.id == inv.id
    assert inv2.name == "test-vm-updated"
    assert inv2.status == "stopped"


@pytest.mark.asyncio
async def test_upsert_discovered_tool(db_session):
    node = await crud.create_proxmox_node(
        db_session, name="n", url="u", token_id="t", token_secret="s"
    )
    inv = await crud.upsert_inventory(
        db_session, proxmox_node_id=node.id, vmid=1, name="vm", type="qemu"
    )

    tool = await crud.upsert_discovered_tool(
        db_session,
        inventory_id=inv.id,
        source_type="ssh_pkg",
        tool_name="nginx",
        detected_version="1.18.0",
        package_manager="dpkg",
    )
    assert tool.id is not None
    assert tool.tool_name == "nginx"

    # Update version
    tool2 = await crud.upsert_discovered_tool(
        db_session,
        inventory_id=inv.id,
        source_type="ssh_pkg",
        tool_name="nginx",
        detected_version="1.20.0",
        package_manager="dpkg",
    )
    assert tool2.id == tool.id
    assert tool2.detected_version == "1.20.0"


@pytest.mark.asyncio
async def test_cve_entry_crud(db_session):
    cve = await crud.upsert_cve_entry(
        db_session,
        cve_id="CVE-2024-1234",
        source="osv",
        title="Test CVE",
        description="Test description",
        severity="HIGH",
        cvss_score=7.5,
        affected_ranges='[{"type": "ECOSYSTEM", "introduced": "0", "fixed": "1.2.3"}]',
        references='[{"url": "https://example.com", "type": "ADVISORY"}]',
    )
    assert cve.id is not None
    assert cve.cve_id == "CVE-2024-1234"

    fetched = await crud.get_cve_entry(db_session, "CVE-2024-1234")
    assert fetched is not None
    assert fetched.title == "Test CVE"


@pytest.mark.asyncio
async def test_vulnerability_finding_crud(db_session):
    node = await crud.create_proxmox_node(db_session, name="n", url="u", token_id="t", token_secret="s")
    inv = await crud.upsert_inventory(db_session, proxmox_node_id=node.id, vmid=1, name="vm", type="qemu")
    tool = await crud.upsert_discovered_tool(
        db_session, inventory_id=inv.id, source_type="ssh_pkg", tool_name="nginx", detected_version="1.18.0"
    )
    cve = await crud.upsert_cve_entry(
        db_session, cve_id="CVE-2024-1234", source="osv", severity="HIGH"
    )

    finding = await crud.upsert_finding(
        db_session,
        discovered_tool_id=tool.id,
        cve_entry_id=cve.id,
        status="open",
        matched_version="1.18.0",
        fixed_version="1.20.0",
    )
    assert finding.id is not None
    assert finding.status == "open"
    assert finding.matched_version == "1.18.0"

    # Update to fixed
    finding2 = await crud.upsert_finding(
        db_session,
        discovered_tool_id=tool.id,
        cve_entry_id=cve.id,
        status="fixed",
    )
    assert finding2.id == finding.id
    assert finding2.status == "fixed"


@pytest.mark.asyncio
async def test_tool_override_crud(db_session):
    override = await crud.upsert_tool_override(
        db_session,
        tool_name="docker",
        cpe_name="cpe:2.3:a:docker:docker",
        ecosystem="docker",
    )
    assert override.tool_name == "docker"
    assert override.cpe_name == "cpe:2.3:a:docker:docker"

    fetched = await crud.get_tool_override(db_session, "docker")
    assert fetched is not None
    assert fetched.ecosystem == "docker"

    # Update
    override2 = await crud.upsert_tool_override(
        db_session,
        tool_name="docker",
        package_name="docker.io",
    )
    assert override2.package_name == "docker.io"

    # Delete
    deleted = await crud.delete_tool_override(db_session, "docker")
    assert deleted is True
    fetched = await crud.get_tool_override(db_session, "docker")
    assert fetched is None


@pytest.mark.asyncio
async def test_suppression_crud(db_session):
    supp = await crud.create_suppression(
        db_session,
        cve_id="CVE-2024-1234",
        tool_name_pattern="nginx*",
        reason="Test suppression",
    )
    assert supp.id is not None

    suppressions = await crud.get_suppressions(db_session)
    assert len(suppressions) == 1
    assert suppressions[0].cve_id == "CVE-2024-1234"

    deleted = await crud.delete_suppression(db_session, supp.id)
    assert deleted is True