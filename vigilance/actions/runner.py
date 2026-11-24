"""Run apt on LXC containers and, one at a time, on the Proxmox host: plan, simulate, execute.

Safety rules, enforced here and not only in the UI:

* LXC containers are changed as root over SSH. The Proxmox host (type "node") only when it is
  the sole target of a request with ``confirm_host`` (checked in the API), only for
  "suggested"/"full_upgrade", and only through ``sudo -n apt-get`` as the unprivileged scan user;
  without a sudo rule the preview says so and nothing runs. On the host the commands run
  detached (nohup) and are polled, so a dropped SSH connection does not leave apt half done -
  Vigilance itself runs in a container on that host. VMs are never changed.
* "suggested" only does what the UI suggests: targeted upgrades of packages whose fix the
  container's package sources offer, and purging obsolete packages whose removal check is
  "ok". Everything else is listed as skipped, with the reason.
* "full_upgrade" is ``apt-get update`` + ``apt-get full-upgrade`` with the existing config
  files kept (--force-confdef/--force-confold), non-interactive.
* "kernel_cleanup" removes kernel packages from a container (they are never loaded there) with
  ``purge --autoremove``. "suggested" includes it only if the scan's simulation removes nothing
  but kernel-related packages.
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

from vigilance.database.models import ActionRun, DiscoveredTool, Inventory, ProxmoxNode

logger = logging.getLogger(__name__)

KINDS = ("suggested", "full_upgrade", "kernel_cleanup")
NODE_KINDS = ("suggested", "full_upgrade")
DPKG_OPTS = "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
APT_ENV = ("export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 "
           "APT_LISTCHANGES_FRONTEND=none LC_ALL=C")
SIM_OPTS = "-s -o Debug::NoLocking=1 -o Dir::Log::Planner=/dev/null"
EXEC_TIMEOUT = 1800
POLL_INTERVAL = 5
SIM_TIMEOUT = 180
OUTPUT_LIMIT = 200_000

_lock = asyncio.Lock()
PARALLEL = 4  # containers changed at the same time in one batch
_starting = False
_tasks: set = set()


class ActionBusy(Exception):
    pass


def node_config_for(inv: Inventory):
    from vigilance.config import settings

    return next((c for c in settings.proxmox_nodes if c.scan_host), None) if inv.type == "node" else None


def blocked_reason(inv: Inventory, kind: str = "suggested") -> Optional[str]:
    """Why Vigilance must not change this host with this kind of action, or None."""
    if inv.type == "node":
        if kind not in NODE_KINDS:
            return "Auf dem Proxmox-Host nicht verfügbar."
        if not node_config_for(inv):
            return "Der Proxmox-Host wird nicht gescannt (scan_host)."
    elif inv.type == "qemu":
        from vigilance.config import configured_vm_ids
        if inv.vmid not in configured_vm_ids():
            return "VM ist nicht für den Scan eingetragen (config.yaml, vms)."
        if kind == "kernel_cleanup":
            return "Eine VM nutzt ihren eigenen Kernel."
    elif inv.type != "lxc":
        return "Nicht unterstützt."
    if inv.status != "running":
        return "Host läuft nicht."
    if inv.last_scan_status != "ok":
        return "Beim letzten Scan nicht erreichbar."
    if (inv.os_id or "") not in ("debian", "ubuntu"):
        return "Nur Debian und Ubuntu (apt) werden unterstützt."
    return None


def kernel_info(inv: Inventory) -> Optional[dict]:
    try:
        return (json.loads(inv.removal_check or "{}") or {}).get("kernel")
    except ValueError:
        return None


def kernel_command(info: dict) -> str:
    names = [p["name"] for p in info["packages"]]
    return "apt-get purge -y --autoremove " + " ".join(names)


async def plan(db: AsyncSession, inv: Inventory, kind: str) -> dict:
    """Commands for one host, plus what is skipped and why."""
    if kind not in KINDS:
        raise ValueError(kind)
    node = inv.type == "node"
    result = {"host_id": inv.id, "host": inv.name, "type": inv.type, "kind": kind, "commands": [], "skipped": [],
              "blocked": blocked_reason(inv, kind)}
    if result["blocked"]:
        return result
    sudo = "sudo -n " if node else ""

    if kind == "full_upgrade":
        # Proxmox documents dist-upgrade (same as full-upgrade) for the host
        result["commands"] = [f"{sudo}apt-get update",
                              f"{sudo}apt-get -y {DPKG_OPTS} {'dist-upgrade' if node else 'full-upgrade'}"]
        return result

    if kind == "kernel_cleanup":
        info = kernel_info(inv)
        if not info:
            result["blocked"] = "Keine Kernel-Pakete im Container (laut letztem Scan)."
        else:
            result["commands"] = [kernel_command(info)]
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
                    reason = ("Paketquelle bietet nur eine Version unter dem Fix" if b in avail.get("older", [])
                              else "Fix nicht in den Paketquellen")
                    result["skipped"].append({"package": b, "reason": reason})
        elif remedy["action"] == "remove":
            risk = remedy.get("risk") or {}
            if risk.get("status") == "ok":
                removals.update(g["binaries"])
            else:
                reason = ("Risikoprüfung: vor dem Entfernen prüfen" if risk.get("status") == "check"
                          else "Risikoprüfung noch nicht gelaufen")
                result["skipped"] += [{"package": b, "reason": reason} for b in g["binaries"]]
    if upgrades:
        result["commands"] += [f"{sudo}apt-get update",
                               f"{sudo}apt-get install -y {DPKG_OPTS} --only-upgrade " + " ".join(sorted(upgrades))]
    if removals:
        result["commands"].append(f"{sudo}apt-get purge -y " + " ".join(sorted(removals)))
    if not node:
        info = kernel_info(inv)
        if info:
            if info.get("extra") or info.get("error"):
                why = ("würde zusätzlich entfernen: " + ", ".join(info["extra"])) if info.get("extra") else info["error"]
                result["skipped"].append({"package": "Kernel im Container",
                                          "reason": f"{why}. Mit „Kernel aufräumen“ einzeln ausführen."})
            else:
                result["commands"].append(kernel_command(info))
    return result


async def hosts_with_suggestions(db: AsyncSession, inventories: List[Inventory]) -> List[int]:
    """Hosts where "Vorschläge umsetzen" would run something (same rules as plan()).
    Hosts without fixable packages or kernel packages are skipped without planning."""
    from vigilance.api.routes.views import host_summaries

    counts = {h["id"]: h for h in await host_summaries(db)}
    out = []
    for inv in inventories:
        h = counts.get(inv.id) or {}
        if not (h.get("upgrade_packages") or h.get("remove_packages") or kernel_info(inv)):
            continue
        p = await plan(db, inv, "suggested")
        if not p["blocked"] and p["commands"]:
            out.append(inv.id)
    return out


def script(commands: Sequence[str]) -> str:
    return "\n".join(["set -e", APT_ENV, *commands])


def simulation_script(commands: Sequence[str]) -> str:
    """Same commands as a simulation: no `apt-get update` (it changes the package lists), -s for the
    rest, and without sudo (a simulation needs no root)."""
    plain = [c.removeprefix("sudo -n ") for c in commands]
    sim = [c.replace("apt-get ", f"apt-get {SIM_OPTS} ", 1) for c in plain if c != "apt-get update"]
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
    cfg = node_config_for(inv)
    if inv.type == "node":
        if not cfg:
            raise RuntimeError("Proxmox-Host nicht konfiguriert")
        target = {**target, "host": cfg.ssh_host, "user": cfg.host_user}
    return target


SUDO_CHECK = "sudo -n -l /usr/bin/apt-get >/dev/null 2>&1 && echo VIGILANCE_SUDO_OK"
SUDO_MISSING = ("sudo-Regel für apt-get fehlt: Der Scan-Benutzer darf apt-get nicht als root ausführen. "
                "Die Regel steht unter Verwaltung, Grenzen, Abschnitt Aktionen.")


async def _run_detached(target: dict, body: str, timeout: int):
    """Start the script with nohup on the host and poll for its exit code.

    The SSH connection only starts and polls; apt keeps running if it drops (for example
    when an upgrade restarts something Vigilance's own container depends on).
    """
    start = (
        'd="$HOME/.vigilance-action"; mkdir -p "$d"; rm -f "$d/rc" "$d/log"\n'
        "cat > \"$d/run.sh\" <<'VIGILANCE_SCRIPT'\n" + body + "\nVIGILANCE_SCRIPT\n"
        'S=""; command -v setsid >/dev/null && S=setsid\n'
        '$S nohup sh -c \'sh "$1" > "$2" 2>&1; echo $? > "$3"\' _ "$d/run.sh" "$d/log" "$d/rc" '
        '> /dev/null 2>&1 < /dev/null &\n'
        "echo VIGILANCE_STARTED"
    )
    res = await _run(target, start, 60)
    if "VIGILANCE_STARTED" not in (res.stdout or ""):
        return res
    waited = 0
    while waited < timeout:
        await asyncio.sleep(POLL_INTERVAL)
        waited += POLL_INTERVAL
        try:
            poll = await _run(target, 'cat "$HOME/.vigilance-action/rc" 2>/dev/null', 30)
        except Exception:  # connection may drop while the host upgrades; keep polling
            continue
        code = (poll.stdout or "").strip()
        if code.isdigit():
            log = await _run(target, f'tail -c {OUTPUT_LIMIT} "$HOME/.vigilance-action/log"', 60)
            log.exit_code = int(code)
            return log
    raise TimeoutError(f"Kein Ergebnis nach {timeout} s; apt läuft auf dem Host eventuell noch.")


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
        if p.get("type") == "node":
            check = await _run(targets[p["host_id"]], SUDO_CHECK, 30)
            if "VIGILANCE_SUDO_OK" not in (check.stdout or ""):
                p["blocked"] = SUDO_MISSING
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
    """Run a batch: hosts with apt-cacher-ng first and alone (the others may download through it),
    then the rest in parallel, at most PARALLEL at a time. Each run has its own DB session."""
    from vigilance.core.scheduler import trigger_scan_now
    from vigilance.database.base import async_session_maker

    async with _lock:
        async with async_session_maker() as db:
            runs = (await db.execute(
                select(ActionRun.id, ActionRun.inventory_id).where(
                    ActionRun.batch_id == batch_id, ActionRun.status == "queued").order_by(ActionRun.id)
            )).all()
            inv_ids = [r.inventory_id for r in runs if r.inventory_id]
            proxies = set((await db.execute(
                select(DiscoveredTool.inventory_id).where(
                    DiscoveredTool.inventory_id.in_(inv_ids), DiscoveredTool.tool_name == "apt-cacher-ng")
            )).scalars().all()) if inv_ids else set()
        first = [r.id for r in runs if r.inventory_id in proxies]
        rest = [r.id for r in runs if r.inventory_id not in proxies]

        changed = False
        for run_id in first:
            changed |= await _execute_run(run_id)
        sem = asyncio.Semaphore(max(1, PARALLEL))

        async def bounded(run_id):
            async with sem:
                return await _execute_run(run_id)

        changed |= any(await asyncio.gather(*(bounded(r) for r in rest)))
    if changed:
        try:
            await trigger_scan_now()
        except Exception:
            logger.exception("Scan after actions could not be started")


async def _execute_run(run_id: int) -> bool:
    """Execute one queued run. Returns True if commands ran (successful or not)."""
    from vigilance.database.base import async_session_maker

    async with async_session_maker() as db:
        run = await db.get(ActionRun, run_id)
        inv = await db.get(Inventory, run.inventory_id) if run.inventory_id else None
        reason = blocked_reason(inv, run.kind) if inv else "Host nicht mehr vorhanden."
        if reason:  # checked again right before anything runs
            run.status, run.output = "skipped", reason
            await db.commit()
            return False
        run.status, run.started_at = "running", datetime.utcnow()
        await db.commit()
        changed = False
        try:
            target = await _ssh_target(db, inv)
            body = script(json.loads(run.commands))
            if inv.type == "node":
                res = await _run_detached(target, body, EXEC_TIMEOUT)
            else:
                res = await _run(target, body, EXEC_TIMEOUT)
            out = res.stdout or res.stderr or ""
            run.output = out[-OUTPUT_LIMIT:]
            run.exit_code = res.exit_code
            run.status = "ok" if res.exit_code == 0 else "failed"
            changed = True
        except Exception as exc:  # the other hosts carry on
            logger.exception("Action on %s failed", run.host_name)
            run.status, run.output = "failed", f"{type(exc).__name__}: {exc}"
        run.finished_at = datetime.utcnow()
        await db.commit()
        return changed


async def mark_interrupted(db: AsyncSession) -> int:
    """At startup: runs that were queued or running when the app stopped."""
    runs = (await db.execute(select(ActionRun).where(ActionRun.status.in_(["queued", "running"])))).scalars().all()
    for run in runs:
        run.status = "interrupted"
        run.finished_at = run.finished_at or datetime.utcnow()
        run.output = (run.output or "") + "\nAbgebrochen: Vigilance wurde während der Ausführung neu gestartet."
    return len(runs)
