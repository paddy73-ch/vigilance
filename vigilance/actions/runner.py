"""Run apt on LXC containers: plan, simulate (preview), execute in the background.

Safety rules, enforced here and not only in the UI:

* Only inventories of type "lxc" are ever changed. The Proxmox host (type "node") and VMs
  are refused in ``blocked_reason`` and again right before execution.
* "suggested" only does what the UI suggests: targeted upgrades of packages whose fix the
  container's package sources offer, and purging obsolete packages whose removal check is
  "ok". Everything else is listed as skipped, with the reason.
* "full_upgrade" is ``apt-get update`` + ``apt-get full-upgrade`` with the existing config
  files kept (--force-confdef/--force-confold), non-interactive.
* One batch at a time. Every run is stored (commands, output, exit code). After a batch a
  new scan starts, so the findings reflect the result.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.database.models import ActionRun, Inventory, ProxmoxNode

logger = logging.getLogger(__name__)

KINDS = ("suggested", "full_upgrade")
DPKG_OPTS = "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
APT_ENV = ("export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 "
           "APT_LISTCHANGES_FRONTEND=none LC_ALL=C")
SIM_OPTS = "-s -o Debug::NoLocking=1 -o Dir::Log::Planner=/dev/null"
EXEC_TIMEOUT = 1800
SIM_TIMEOUT = 180
OUTPUT_LIMIT = 200_000

_lock = asyncio.Lock()
_starting = False
_tasks: set = set()


class ActionBusy(Exception):
    pass


def blocked_reason(inv: Inventory) -> Optional[str]:
    """Why Vigilance must not change this host, or None."""
    if inv.type != "lxc":
        return "Nur LXC-Container werden verändert. Der Proxmox-Host und VMs nie."
    if inv.status != "running":
        return "Container läuft nicht."
    if inv.last_scan_status != "ok":
        return "Beim letzten Scan nicht erreichbar."
    if (inv.os_id or "") not in ("debian", "ubuntu"):
        return "Nur Debian und Ubuntu (apt) werden unterstützt."
    return None


async def plan(db: AsyncSession, inv: Inventory, kind: str) -> dict:
    """Commands for one host, plus what is skipped and why."""
    if kind not in KINDS:
        raise ValueError(kind)
    result = {"host_id": inv.id, "host": inv.name, "kind": kind, "commands": [], "skipped": [],
              "blocked": blocked_reason(inv)}
    if result["blocked"]:
        return result
    if kind == "full_upgrade":
        result["commands"] = ["apt-get update", f"apt-get -y {DPKG_OPTS} full-upgrade"]
        return result

    from vigilance.api.routes.views import get_host  # late import: views imports a lot

    host = await get_host(inventory_id=inv.id, db=db, _=None)
    upgrades, removals = set(), set()
    for g in host["patchable_list"]:
        remedy = g["remedy"]
        if remedy["action"] == "upgrade":
            avail = remedy["availability"]
            ok = g["binaries"] if avail["status"] == "unknown" else avail["installable"]
            upgrades.update(ok)
            for b in g["binaries"]:
                if b not in ok:
                    result["skipped"].append({"package": b, "reason": "Fix nicht in den Paketquellen des Containers"})
        elif remedy["action"] == "remove":
            status = (remedy.get("risk") or {}).get("status")
            if status == "ok":
                removals.update(g["binaries"])
            else:
                reason = ("Risikoprüfung: vor dem Entfernen prüfen" if status == "check"
                          else "Risikoprüfung noch nicht gelaufen")
                result["skipped"] += [{"package": b, "reason": reason} for b in g["binaries"]]
    if upgrades:
        result["commands"] += ["apt-get update",
                               f"apt-get install -y {DPKG_OPTS} --only-upgrade " + " ".join(sorted(upgrades))]
    if removals:
        result["commands"].append("apt-get purge -y " + " ".join(sorted(removals)))
    return result


def script(commands: Sequence[str]) -> str:
    return "\n".join(["set -e", APT_ENV, *commands])


def simulation_script(commands: Sequence[str]) -> str:
    """Same commands as a simulation: no `apt-get update` (it changes the package lists), -s for the rest."""
    sim = [c.replace("apt-get ", f"apt-get {SIM_OPTS} ", 1) for c in commands if c != "apt-get update"]
    return "\n".join([APT_ENV, *sim])


def parse_simulation(output: str) -> dict:
    """Inst/Remv/Purg lines of apt-get -s."""
    changes = {"upgrade": [], "install": [], "remove": []}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] == "Inst":
            name = parts[1]
            if len(parts) > 2 and parts[2].startswith("["):
                new = line.split("(", 1)[1].split()[0] if "(" in line else ""
                changes["upgrade"].append(f"{name} {parts[2].strip('[]')} → {new}".strip())
            else:
                new = line.split("(", 1)[1].split()[0] if "(" in line else ""
                changes["install"].append(f"{name} {new}".strip())
        elif parts[0] in ("Remv", "Purg"):
            changes["remove"].append(parts[1])
    return changes


async def _ssh_target(db: AsyncSession, inv: Inventory) -> dict:
    from vigilance.discovery.orchestrator import DiscoveryOrchestrator

    node = await db.get(ProxmoxNode, inv.proxmox_node_id)
    target = DiscoveryOrchestrator(db)._get_ssh_config_for_target(node, inv)
    if not target:
        raise RuntimeError("Keine SSH-Verbindung konfiguriert")
    return target


async def _run(target: dict, body: str, timeout: int):
    from vigilance.discovery.ssh import get_ssh_pool

    client = get_ssh_pool().get_client(target["host"], target["port"], target["user"],
                                       target["key_path"], target["known_hosts"], timeout)
    command = f"sh -s 2>&1 <<'VIGILANCE_EOF'\n{body}\nVIGILANCE_EOF"
    # paramiko blocks: keep the event loop free while apt runs
    return await asyncio.to_thread(client.run_command, command, timeout)


async def preview(db: AsyncSession, inventories: List[Inventory], kind: str) -> List[dict]:
    """Plan + simulation for each host (read-only)."""
    plans = [await plan(db, inv, kind) for inv in inventories]
    targets: Dict[int, dict] = {}
    for p, inv in zip(plans, inventories):
        if not p["blocked"] and p["commands"]:
            targets[inv.id] = await _ssh_target(db, inv)

    async def simulate(p):
        if p["host_id"] not in targets:
            return p
        res = await _run(targets[p["host_id"]], simulation_script(p["commands"]), SIM_TIMEOUT)
        if res.exit_code != 0:
            p["simulation_error"] = (res.stdout or res.stderr or "Simulation fehlgeschlagen")[-2000:]
        else:
            p["changes"] = parse_simulation(res.stdout)
        return p

    sem = asyncio.Semaphore(4)

    async def bounded(p):
        async with sem:
            return await simulate(p)

    return list(await asyncio.gather(*(bounded(p) for p in plans)))


def is_busy() -> bool:
    return _starting or _lock.locked()


async def start_batch(db: AsyncSession, inventories: List[Inventory], kind: str, user: Optional[str]) -> str:
    """Create the runs and execute them in the background. Returns the batch id."""
    global _starting
    if is_busy():
        raise ActionBusy()
    _starting = True
    try:
        batch_id = str(uuid.uuid4())
        for inv in inventories:
            p = await plan(db, inv, kind)
            status = "queued"
            note = None
            if p["blocked"]:
                status, note = "skipped", p["blocked"]
            elif not p["commands"]:
                status, note = "skipped", "Nichts zu tun."
            db.add(ActionRun(batch_id=batch_id, inventory_id=inv.id, host_name=inv.name, kind=kind, status=status,
                             commands=json.dumps(p["commands"]), skipped=json.dumps(p["skipped"]),
                             output=note, created_by=user))
        await db.commit()
        task = asyncio.create_task(_execute(batch_id), name=f"actions-{batch_id}")
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
        return batch_id
    finally:
        _starting = False


async def _execute(batch_id: str):
    from vigilance.core.scheduler import trigger_scan_now
    from vigilance.database.base import async_session_maker

    async with _lock:
        async with async_session_maker() as db:
            runs = (await db.execute(
                select(ActionRun).where(ActionRun.batch_id == batch_id, ActionRun.status == "queued")
                .order_by(ActionRun.id)
            )).scalars().all()
            changed = False
            for run in runs:
                inv = await db.get(Inventory, run.inventory_id) if run.inventory_id else None
                reason = blocked_reason(inv) if inv else "Host nicht mehr vorhanden."
                if reason:  # checked again right before anything runs
                    run.status, run.output = "skipped", reason
                    await db.commit()
                    continue
                run.status, run.started_at = "running", datetime.utcnow()
                await db.commit()
                try:
                    res = await _run(await _ssh_target(db, inv), script(json.loads(run.commands)), EXEC_TIMEOUT)
                    out = res.stdout or res.stderr or ""
                    run.output = out[-OUTPUT_LIMIT:]
                    run.exit_code = res.exit_code
                    run.status = "ok" if res.exit_code == 0 else "failed"
                    changed = True
                except Exception as exc:  # keep going with the next host
                    logger.exception("Action on %s failed", run.host_name)
                    run.status, run.output = "failed", f"{type(exc).__name__}: {exc}"
                run.finished_at = datetime.utcnow()
                await db.commit()
    if changed:
        try:
            await trigger_scan_now()
        except Exception:
            logger.exception("Scan after actions could not be started")


async def mark_interrupted(db: AsyncSession) -> int:
    """At startup: runs that were queued or running when the app stopped."""
    runs = (await db.execute(select(ActionRun).where(ActionRun.status.in_(["queued", "running"])))).scalars().all()
    for run in runs:
        run.status = "interrupted"
        run.finished_at = run.finished_at or datetime.utcnow()
        run.output = (run.output or "") + "\nAbgebrochen: Vigilance wurde während der Ausführung neu gestartet."
    return len(runs)
