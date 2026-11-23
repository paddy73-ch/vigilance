#!/usr/bin/env python3
"""
Distribute Vigilance SSH public key to all Proxmox VMs via Guest Agent.
Uses only Python standard library (urllib) - no external dependencies.

Reads the Proxmox API for all VMs/LXCs, then uses the QEMU Guest Agent
to write the Vigilance SSH public key into /root/.ssh/authorized_keys
on each VM.

Usage:
    python3 distribute_ssh_key.py --proxmox-url https://192.0.2.49:8006 \\
        --token-id vigilance@pam!vigilance-ct123 \\
        --token-secret <secret>
"""

import argparse
import asyncio
import json
import ssl
import sys
from urllib import request, error


VIGILANCE_SSH_PUB_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEjAVtnlc+nFT5Aelji4hpGaWA+ghuOA7NDeovNWU4qu "
    "root@vigilance"
)


class ProxmoxAPI:
    def __init__(self, base_url, token_id, token_secret):
        self.base_url = base_url.rstrip("/")
        self.token = f"{token_id}={token_secret}"
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _headers(self):
        return {"Authorization": f"PVEAPIToken={self.token}"}

    def get(self, path):
        req = request.Request(
            f"{self.base_url}{path}",
            headers=self._headers(),
            method="GET",
        )
        with request.urlopen(req, context=self.ctx) as resp:
            return json.loads(resp.read().decode())

    def post(self, path, body):
        data = json.dumps(body).encode()
        req = request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={**self._headers(), "Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, context=self.ctx) as resp:
            return resp.read().decode()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxmox-url", required=True, help="Proxmox API URL")
    parser.add_argument("--token-id", required=True, help="PVE API Token ID")
    parser.add_argument("--token-secret", required=True, help="PVE API Token Secret")
    args = parser.parse_args()

    api = ProxmoxAPI(args.proxmox_url, args.token_id, args.token_secret)

    # 1. Get all nodes
    nodes = api.get("/api2/json/nodes")
    node_names = [n["node"] for n in nodes.get("data", [])]

    # 2. For each node, get all VMs and LXCs
    for node_name in node_names:
        print(f"\n=== Node: {node_name} ===")

        # Get VMs
        vms = api.get(f"/api2/json/nodes/{node_name}/qemu")
        # Get LXCs
        lxcs = api.get(f"/api2/json/nodes/{node_name}/lxc")

        all_vms = vms.get("data", []) + lxcs.get("data", [])

        for vm in all_vms:
            vmid = vm["vmid"]
            name = vm.get("name", f"vm{vmid}")
            status = vm.get("status", "unknown")

            if status != "running":
                print(f"  [SKIP] {name} (vmid={vmid}) - status: {status}")
                continue

                # Try to get IP from config
                try:
                    config = api.get(
                        f"/api2/json/nodes/{node_name}/qemu/{vmid}/config"
                    )
                except Exception:
                    config = {}

                # Extract IP from config
                ip = None
                for key, value in config.get("data", {}).items():
                    if isinstance(value, str) and "ip=" in value:
                        for part in value.split(","):
                            if part.startswith("ip="):
                                ip = part.split("=")[1].split("/")[0]
                                break

                if not ip:
                    print(f"  [SKIP] {name} (vmid={vmid}) - no IP found")
                    continue

                print(f"  [TARGET] {name} (vmid={vmid}) at {ip}")

                # Use Guest Agent to write SSH key
                cmd = (
                    "mkdir -p /root/.ssh && "
                    f"echo '{VIGILANCE_SSH_PUB_KEY}' >> /root/.ssh/authorized_keys && "
                    "chmod 600 /root/.ssh/authorized_keys"
                )

                try:
                    api.post(
                        f"/api2/json/nodes/{node_name}/qemu/{vmid}/agent/exec",
                        {"command": ["bash", "-c", cmd]},
                    )
                    print(f"     SSH key distributed to {name} (vmid={vmid})")
                except Exception as e:
                    print(f"     [FAIL] {name} (vmid={vmid}): {e}")


if __name__ == "__main__":
    asyncio.run(main())
