"""Snapshot of a container / VM right before Vigilance changes it ("Vorher Snapshot anlegen").

Through the Proxmox API with the read token's VM.Snapshot right: create, wait for the task, then delete
older snapshots that Vigilance made of the same guest (named vigilance-…), so one stays per guest. The
user's own snapshots are never touched, and Vigilance never rolls back; that is done in Proxmox.
"""
import asyncio
import logging
import re
from datetime import datetime
from typing import List, Optional, Tuple

from vigilance.database.models import Inventory, ProxmoxNode
from vigilance.discovery.proxmox import ProxmoxClient

logger = logging.getLogger(__name__)

PREFIX = "vigilance-"
_OURS = re.compile(r"^vigilance-\d{8}-\d{6}$")
TASK_TIMEOUT = 600


def snapshot_name(now: Optional[datetime] = None) -> str:
    return PREFIX + (now or datetime.now()).strftime("%Y%m%d-%H%M%S")


def _kind(inv: Inventory) -> str:
    return "lxc" if inv.type == "lxc" else "qemu"


async def _wait(client: ProxmoxClient, node: str, upid: str, timeout: int = TASK_TIMEOUT) -> Tuple[bool, str]:
    waited = 0.0
    while waited < timeout:
        status = (await client._request("GET", f"/api2/json/nodes/{node}/tasks/{upid}/status")).get("data") or {}
        if status.get("status") == "stopped":
            exit_status = status.get("exitstatus") or ""
            return exit_status == "OK", exit_status
        await asyncio.sleep(1)
        waited += 1
    return False, f"keine Antwort nach {timeout} s"


def _reason(exc: Exception) -> str:
    text = str(getattr(exc, "message", "") or exc)
    if getattr(exc, "status", None) == 403:
        return "dem Proxmox-Token fehlt das Recht VM.Snapshot"
    m = re.search(r'"(?:errors|message)"\s*:\s*\{?"?([^"}]+)', text)
    return (m.group(1) if m else text)[:300]


async def create(node: ProxmoxNode, inv: Inventory, name: str) -> Tuple[bool, Optional[str]]:
    """Create the snapshot and wait for it. (True, None) or (False, reason)."""
    path = f"/api2/json/nodes/{node.name}/{_kind(inv)}/{inv.vmid}/snapshot"
    try:
        async with ProxmoxClient(node) as client:
            res = await client._request("POST", path, data={
                "snapname": name, "description": "Von Vigilance vor einer Änderung angelegt"})
            ok, status = await _wait(client, node.name, res.get("data") or "")
            if not ok:
                return False, status or "Snapshot fehlgeschlagen"
            removed = await _prune(client, node.name, inv, keep=name)
            if removed:
                logger.info("Removed older Vigilance snapshots of %s: %s", inv.name, ", ".join(removed))
            return True, None
    except Exception as exc:
        logger.warning("Snapshot of %s failed: %s", inv.name, exc)
        return False, _reason(exc)


async def _prune(client: ProxmoxClient, node: str, inv: Inventory, keep: str) -> List[str]:
    """Delete Vigilance's older snapshots of this guest. Failures are logged, not fatal."""
    base = f"/api2/json/nodes/{node}/{_kind(inv)}/{inv.vmid}/snapshot"
    removed = []
    try:
        names = [s.get("name") for s in (await client._request("GET", base)).get("data") or []]
        for name in sorted(n for n in names if n and _OURS.match(n) and n != keep):
            res = await client._request("DELETE", f"{base}/{name}")
            ok, status = await _wait(client, node, res.get("data") or "")
            if ok:
                removed.append(name)
            else:
                logger.warning("Could not delete snapshot %s of %s: %s", name, inv.name, status)
    except Exception as exc:
        logger.warning("Could not clean up snapshots of %s: %s", inv.name, exc)
    return removed
