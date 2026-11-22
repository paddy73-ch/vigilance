"""Automatic SSH key distribution to all Proxmox VMs via Guest Agent.

Reads the Proxmox API for all running VMs/LXCs, then uses the QEMU Guest Agent
to write the Vigilance SSH public key into /root/.ssh/authorized_keys on each VM.

This ensures that new VMs are automatically configured when they start,
without manual intervention.
"""

import asyncio
import json
import logging
import ssl
from typing import List, Optional
from urllib import request, error

from vigilance.config import settings

logger = logging.getLogger(__name__)

# Vigilance SSH public key (hardcoded to avoid filesystem issues in container)
VIGILANCE_SSH_PUB_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjAVtnlc+nFT5Aelji4hpGaWA+ghuOA7NDeovNWU4qu "
    "root@vigilance"
)


class ProxmoxAPI:
    """Minimal Proxmox API client using urllib (no external dependencies)."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _headers(self):
        return {"Authorization": f"PVEAPIToken={self.token}"}

    def get(self, path: str):
        req = request.Request(
            f"{self.base_url}{path}",
            headers=self._headers(),
            method="GET",
        )
        with request.urlopen(req, context=self.ctx) as resp:
            return json.loads(resp.read().decode())

    def post(self, path: str, body: dict):
        data = json.dumps(body).encode()
        req = request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={**self._headers(), "Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, context=self.ctx) as resp:
            return resp.read().decode()


async def distribute_ssh_key_to_all_vms(api: ProxmoxAPI, node_name: str = "pve") -> dict:
    """Distribute Vigilance SSH public key to all running VMs via Guest Agent.

    Returns a dict with stats: {"vms_found": int, "key_distributed": int, "failed": int}
    """
    stats = {"vms_found": 0, "key_distributed": 0, "failed": 0}

    ssh_pub_key = VIGILANCE_SSH_PUB_KEY
    if not ssh_pub_key:
        logger.error("No SSH public key available, skipping distribution")
        return stats

    # 1. Get all VMs and LXCs
    try:
        vms = api.get(f"/api2/json/nodes/{node_name}/qemu")
        lxcs = api.get(f"/api2/json/nodes/{node_name}/lxc")
    except Exception as e:
        logger.error(f"Failed to fetch VM list from Proxmox: {e}")
        return stats

    all_targets = vms.get("data", []) + lxcs.get("data", [])
    stats["vms_found"] = len(all_targets)

    # 2. For each running VM, distribute SSH key via Guest Agent
    for vm in all_targets:
        vmid = vm["vmid"]
        name = vm.get("name", f"vm{vmid}")
        status = vm.get("status", "unknown")

        if status != "running":
            logger.debug(f"Skipping {name} (vmid={vmid}) - status: {status}")
            continue

        # Try to get IP from config (optional, for logging)
        try:
            config = api.get(f"/api2/json/nodes/{node_name}/qemu/{vmid}/config")
            ip = None
            for key, value in config.get("data", {}).items():
                if isinstance(value, str) and "ip=" in value:
                    for part in value.split(","):
                        if part.startswith("ip="):
                            ip = part.split("=")[1].split("/")[0]
                            break
        except Exception:
            ip = None

        # Use Guest Agent to write SSH key
        cmd = (
            "mkdir -p /root/.ssh && "
            f"echo '{ssh_pub_key}' >> /root/.ssh/authorized_keys && "
            "chmod 600 /root/.ssh/authorized_keys"
        )

        try:
            api.post(
                f"/api2/json/nodes/{node_name}/qemu/{vmid}/agent/exec",
                {"command": ["bash", "-c", cmd]},
            )
            logger.info(f"SSH key distributed to {name} (vmid={vmid}) at {ip or 'unknown'}")
            stats["key_distributed"] += 1
        except Exception as e:
            logger.error(f"Failed to distribute SSH key to {name} (vmid={vmid}): {e}")
            stats["failed"] += 1

    return stats


async def auto_distribute_ssh_keys(api_url: str, token: str, node_name: str = "pve") -> dict:
    """Auto-distribute SSH keys to all running VMs on a Proxmox node."""
    api = ProxmoxAPI(api_url, token)
    return await distribute_ssh_key_to_all_vms(api, node_name)
