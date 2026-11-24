import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.config import settings
from vigilance.database import crud
from vigilance.database.models import (
    ProxmoxNode,
    Inventory,
    DiscoveredTool,
    ScanRun,
)
from vigilance.discovery.proxmox import ProxmoxClient, ProxmoxVM, ProxmoxLXC, get_all_proxmox_clients
from vigilance.discovery.docker import discover_docker_on_host, DockerContainer, DockerImage
from vigilance.discovery.packages import discover_packages_on_host, PackageInfo
from vigilance.discovery.services import discover_services_on_host, ServiceInfo
from vigilance.discovery.custom import run_all_custom_checks, CustomCheckResult
from vigilance.discovery.ssh import get_ssh_pool
from vigilance.discovery.osinfo import probe_os
from vigilance.discovery.sshkey import ensure_ssh_key
from vigilance.discovery.removal import check_removal, dumps as dump_removal, obsolete_binaries

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    nodes_scanned: int = 0
    tools_found: int = 0
    new_findings: int = 0  # filled in by the CVE match step after the sync


class DiscoveryOrchestrator:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.ssh_pool = get_ssh_pool()

    async def discover_all(self, scan_run_id: int) -> ScanResult:
        result = ScanResult()
        scan_run = await self.db.get(ScanRun, scan_run_id)

        # Make sure this instance has an SSH key (distribution to the LXCs happens via Ansible)
        ssh_pub_key = ensure_ssh_key()
        logger.info("SSH key: %s", ssh_pub_key.split()[-1] if ssh_pub_key else "missing")

        # Get or create Proxmox nodes in DB
        for node_config in settings.proxmox_nodes:
            node = await crud.get_proxmox_node_by_name(self.db, node_config.name)
            if not node:
                node = await crud.create_proxmox_node(
                    self.db,
                    name=node_config.name,
                    url=node_config.url,
                    token_id=node_config.token_id,
                    token_secret=node_config.token_secret,
                    verify_tls=node_config.verify_tls,
                )
            else:
                # config.yaml is the source of truth: pick up a rotated token or changed URL/TLS setting
                for attr in ("url", "token_id", "token_secret", "verify_tls"):
                    value = getattr(node_config, attr)
                    if value is not None and getattr(node, attr) != value:
                        setattr(node, attr, value)
                        logger.info("Proxmox node %s: %s updated from config", node.name, attr)

            # Discover via Proxmox API
            await self._discover_proxmox_node(node, scan_run_id, result)

        await self.db.commit()
        return result

    async def _discover_proxmox_node(self, node: ProxmoxNode, scan_run_id: int, result: ScanResult):
        """Discover LXC containers on a Proxmox node via API, then SSH into each."""
        async with ProxmoxClient(node) as client:
            # Get LXCs only (skip QEMU VMs)
            lxcs = await client.get_lxcs(node.name)

            all_targets = []
            for lxc in lxcs:
                try:
                    config = await client.get_lxc_config(node.name, lxc.vmid)
                    lxc.ip = self._ip_from_lxc_config(config)
                except Exception as exc:
                    logger.warning("Could not read LXC network config for %s: %s", lxc.vmid, exc)
                if not getattr(lxc, "ip", None) and lxc.status == "running":
                    # DHCP: ask Proxmox for the current address of the running container
                    try:
                        lxc.ip = self._ip_from_interfaces(await client.get_lxc_interfaces(node.name, lxc.vmid))
                    except Exception as exc:
                        logger.info("Could not read interfaces of LXC %s: %s", lxc.vmid, exc)

            # Running LXCs with a fixed IP are scanned; the others are recorded with the reason
            for lxc in lxcs:
                ip = getattr(lxc, "ip", None) or getattr(lxc, "ip_address", None)
                if lxc.status != "running":
                    await self._record_skipped(node, lxc, "stopped", None)
                elif not ip:
                    await self._record_skipped(
                        node, lxc, "no_ip", "Keine IP-Adresse gefunden (weder fest konfiguriert noch per DHCP gemeldet)")
                else:
                    all_targets.append(("lxc", lxc))

            result.nodes_scanned += len(all_targets)

            for vtype, lxc in all_targets:
                await self._process_inventory_target(node, vtype, lxc, scan_run_id, result)

    async def _record_skipped(self, node: ProxmoxNode, lxc, status: str, error: Optional[str]):
        inventory = await crud.upsert_inventory(
            self.db,
            proxmox_node_id=node.id,
            vmid=lxc.vmid,
            name=lxc.name,
            type="lxc",
            status=lxc.status,
            ip_address=getattr(lxc, "ip", None),
        )
        inventory.last_scan_at = datetime.utcnow()
        inventory.last_scan_status = status
        inventory.last_scan_error = error

    @staticmethod
    def _ip_from_lxc_config(config: dict) -> Optional[str]:
        for value in config.values():
            if not isinstance(value, str) or not value.startswith("name="):
                continue
            match = re.search(r"(?:^|,)ip=([^/,]+)", value)
            if match and match.group(1) not in {"dhcp", "manual"}:
                return match.group(1).split("/")[0]
        return None

    @staticmethod
    def _ip_from_interfaces(interfaces) -> Optional[str]:
        """First IPv4 address of a non-loopback interface from /lxc/{vmid}/interfaces."""
        for iface in interfaces or []:
            if iface.get("name") == "lo":
                continue
            inet = iface.get("inet") or ""
            if inet and not inet.startswith("127."):
                return inet.split("/")[0]
        return None

    async def _process_inventory_target(
        self,
        node: ProxmoxNode,
        vtype: str,
        target,
        scan_run_id: int,
        result: ScanResult,
    ):
        """Process a single VM or LXC: upsert inventory, run SSH discovery."""
        # Upsert inventory
        inventory = await crud.upsert_inventory(
            self.db,
            proxmox_node_id=node.id,
            vmid=target.vmid,
            name=target.name,
            type=vtype,
            status=target.status,
            ip_address=getattr(target, "ip", None) or getattr(target, "ip_address", None),
        )

        # Get SSH config for this target
        ssh_config = self._get_ssh_config_for_target(node, inventory)
        if not ssh_config:
            logger.warning(f"No SSH config for {inventory.name} ({inventory.ip_address})")
            return

        # Run all discovery modules via SSH
        await self._run_ssh_discovery(inventory, ssh_config, scan_run_id, result)

    def _get_ssh_config_for_target(self, node: ProxmoxNode, inventory: Inventory) -> Optional[dict]:
        """Get SSH connection config for a target. For now, use node's SSH config."""
        # In a real implementation, you might have per-VM/LXC SSH configs
        # For MVP, we use the Proxmox node's SSH config and target the VM/LXC IP
        if not inventory.ip_address:
            return None

        node_config = next(
            (config for config in settings.proxmox_nodes if config.name == node.name),
            None,
        )
        ssh_key_path = node_config.ssh_key_path if node_config and node_config.ssh_key_path else "/app/data/ssh/id_rsa"
        ssh_known_hosts = node_config.ssh_known_hosts if node_config and node_config.ssh_known_hosts else "/app/data/ssh/known_hosts"
        return {
            "host": inventory.ip_address,
            "port": node_config.ssh_port if node_config else 22,
            "user": node_config.ssh_user if node_config else "root",
            "key_path": ssh_key_path,
            "known_hosts": ssh_known_hosts,
        }

    async def _run_ssh_discovery(
        self,
        inventory: Inventory,
        ssh_config: dict,
        scan_run_id: int,
        result: ScanResult,
    ):
        """Run all SSH-based discovery on a target."""
        host = ssh_config["host"]
        port = ssh_config["port"]
        user = ssh_config["user"]
        key_path = ssh_config["key_path"]
        known_hosts = ssh_config["known_hosts"]

        # 0. OS release (needed for release-specific CVE lookups, e.g. OSV "Debian:13");
        #    also tells whether the host is reachable at all
        inventory.last_scan_at = datetime.utcnow()
        os_info, error = await probe_os(host, port, user, key_path, known_hosts)
        if not os_info:
            inventory.last_scan_status = "unreachable"
            inventory.last_scan_error = error
            return
        inventory.os_id = os_info.id or None
        inventory.os_version_id = os_info.version_id or None
        inventory.os_codename = os_info.codename or None
        inventory.last_scan_status = "ok"
        inventory.last_scan_error = None

        # 1. Docker Discovery
        if settings.discovery and settings.discovery.docker_enabled:
            docker_result = await discover_docker_on_host(host, port, user, key_path, known_hosts)
            await self._save_docker_discovery(inventory, docker_result, scan_run_id, result)

        # 2. Package Discovery
        if settings.discovery and settings.discovery.packages_enabled:
            managers = settings.discovery.packages_managers
            packages = await discover_packages_on_host(host, port, user, key_path, known_hosts, managers)
            await self._save_package_discovery(inventory, packages, scan_run_id, result)
            if packages:
                # What would removing the leftovers of an older release affect? (read-only)
                check = await check_removal(host, port, user, key_path, known_hosts, obsolete_binaries(packages))
                inventory.removal_check = dump_removal(check)

        # 3. Service Discovery
        if settings.discovery and settings.discovery.services_enabled:
            patterns = settings.discovery.services_include_patterns
            services = await discover_services_on_host(host, port, user, key_path, known_hosts, patterns)
            await self._save_service_discovery(inventory, services, scan_run_id, result)

        # 4. Custom Checks
        custom_results = await run_all_custom_checks(host, port, user, key_path, known_hosts)
        await self._save_custom_discovery(inventory, custom_results, scan_run_id, result)

    async def _save_docker_discovery(
        self,
        inventory: Inventory,
        docker_result: dict,
        scan_run_id: int,
        result: ScanResult,
    ):
        """Save discovered Docker containers and images as tools."""
        for container in docker_result.get("containers", []):
            name, tag = self._parse_image_name(container.image)
            tool = await crud.upsert_discovered_tool(
                self.db,
                inventory_id=inventory.id,
                source_type="ssh_docker",
                tool_name=name,
                detected_version=tag,
                cpe_name=f"cpe:2.3:a:{name}:{name}",
                package_manager="docker",
                raw_data=json.dumps({
                    "container_id": container.id,
                    "container_name": container.name,
                    "image_id": container.image_id,
                    "status": container.status,
                    "ports": container.ports,
                }),
                scan_run_id=scan_run_id,
            )
            result.tools_found += 1

        for image in docker_result.get("images", []):
            if image.repository == "<none>":
                continue
            tool = await crud.upsert_discovered_tool(
                self.db,
                inventory_id=inventory.id,
                source_type="ssh_docker",
                tool_name=image.repository,
                detected_version=image.tag,
                cpe_name=f"cpe:2.3:a:{image.repository}:{image.repository}",
                package_manager="docker",
                raw_data=json.dumps({
                    "image_id": image.image_id,
                    "created": image.created,
                    "size": image.size,
                }),
                scan_run_id=scan_run_id,
            )
            result.tools_found += 1

    async def _save_package_discovery(
        self,
        inventory: Inventory,
        packages: List[PackageInfo],
        scan_run_id: int,
        result: ScanResult,
    ):
        """Save discovered packages as tools; packages no longer installed are marked as removed."""
        seen_ids = set()
        for pkg in packages:
            cpe_name = f"cpe:2.3:a:{pkg.name}:{pkg.name}"
            tool = await crud.upsert_discovered_tool(
                self.db,
                inventory_id=inventory.id,
                source_type="ssh_pkg",
                tool_name=pkg.name,
                detected_version=pkg.version,
                cpe_name=cpe_name,
                cpe_version=pkg.version,
                package_manager=pkg.manager,
                source_name=pkg.source_name,
                source_version=pkg.source_version,
                raw_data=json.dumps({
                    "architecture": pkg.architecture,
                    "description": pkg.description,
                }),
                scan_run_id=scan_run_id,
            )
            seen_ids.add(tool.id)
            result.tools_found += 1

        # An empty list means the query failed - never mark everything as removed then
        if seen_ids:
            await crud.mark_removed_tools(self.db, inventory.id, "ssh_pkg", seen_ids)

    async def _save_service_discovery(
        self,
        inventory: Inventory,
        services: List[ServiceInfo],
        scan_run_id: int,
        result: ScanResult,
    ):
        """Save discovered services as tools."""
        for svc in services:
            cpe_name = f"cpe:2.3:a:{svc.name}:{svc.name}"

            tool = await crud.upsert_discovered_tool(
                self.db,
                inventory_id=inventory.id,
                source_type="ssh_service",
                tool_name=svc.name,
                detected_version=svc.version,
                cpe_name=cpe_name,
                cpe_version=svc.version,
                package_manager="systemd",
                raw_data=json.dumps({
                    "status": svc.status,
                    "description": svc.description,
                }),
                scan_run_id=scan_run_id,
            )
            result.tools_found += 1

    async def _save_custom_discovery(
        self,
        inventory: Inventory,
        custom_results: List[CustomCheckResult],
        scan_run_id: int,
        result: ScanResult,
    ):
        """Save custom check results as tools."""
        for check in custom_results:
            if not check.success or not check.version:
                continue

            ecosystem = "custom"
            cpe_name = f"cpe:2.3:a:{check.check_name}:{check.check_name}"

            tool = await crud.upsert_discovered_tool(
                self.db,
                inventory_id=inventory.id,
                source_type="ssh_custom",
                tool_name=check.check_name,
                detected_version=check.version,
                cpe_name=cpe_name,
                cpe_version=check.version,
                package_manager=ecosystem,
                raw_data=json.dumps({
                    "command": check.command,
                    "raw_output": check.raw_output[:1000],  # Truncate
                }),
                scan_run_id=scan_run_id,
            )
            result.tools_found += 1

    def _parse_image_name(self, image: str) -> tuple[str, str]:
        """Parse Docker image name into (name, tag)."""
        if "@" in image:
            name, digest = image.split("@", 1)
            return name, digest
        elif ":" in image and not image.startswith("sha256:"):
            parts = image.rsplit(":", 1)
            if "/" in parts[1] or "." in parts[1]:
                return image, "latest"
            return parts[0], parts[1]
        return image, "latest"
