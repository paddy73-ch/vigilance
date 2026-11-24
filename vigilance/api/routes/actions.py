"""Remediation actions: preview (simulation) and execution of apt on LXC containers."""

import json
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.actions import runner
from vigilance.api.deps import get_current_user_optional, get_db, require_write_access
from vigilance.core.security import User
from vigilance.database.models import ActionRun, Inventory

router = APIRouter()


class ActionRequest(BaseModel):
    kind: Literal["suggested", "full_upgrade", "kernel_cleanup"]
    host_ids: Optional[List[int]] = Field(None, description="Leer = alle laufenden LXC-Container")
    # Required to change the Proxmox host; the host is only accepted as the sole target
    confirm_host: bool = False


async def _targets(db: AsyncSession, host_ids: Optional[List[int]]) -> List[Inventory]:
    stmt = select(Inventory).order_by(Inventory.vmid)
    if host_ids:
        stmt = stmt.where(Inventory.id.in_(host_ids))
    else:
        # "all": running containers and the VMs from config.yaml; never the Proxmox host
        from vigilance.config import configured_vm_ids
        vms = configured_vm_ids()
        stmt = stmt.where(Inventory.status == "running", or_(
            Inventory.type == "lxc", and_(Inventory.type == "qemu", Inventory.vmid.in_(vms or {-1}))))
    invs = list((await db.execute(stmt)).scalars().all())
    if host_ids and len(invs) != len(set(host_ids)):
        raise HTTPException(status_code=404, detail="Host nicht gefunden")
    if any(i.type == "node" for i in invs) and len(invs) > 1:
        raise HTTPException(status_code=400, detail="Der Proxmox-Host kann nur einzeln ausgewählt werden.")
    return invs


@router.get("/actions/available")
async def available(host_id: Optional[int] = Query(None), db: AsyncSession = Depends(get_db),
                    _: Optional[User] = Depends(get_current_user_optional)):
    """Which hosts have suggestions to apply, so the UI can disable the buttons. Read-only."""
    invs = await _targets(db, [host_id] if host_id else None)
    return {"suggested": await runner.hosts_with_suggestions(db, invs)}


def _run_dict(r: ActionRun, with_output: bool = True) -> dict:
    iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
    out = {
        "id": r.id, "batch_id": r.batch_id, "host_id": r.inventory_id, "host": r.host_name, "kind": r.kind,
        "status": r.status, "commands": json.loads(r.commands or "[]"), "skipped": json.loads(r.skipped or "[]"),
        "exit_code": r.exit_code, "created_by": r.created_by, "created_at": iso(r.created_at),
        "started_at": iso(r.started_at), "finished_at": iso(r.finished_at),
    }
    if with_output:
        out["output"] = r.output
    return out


@router.post("/actions/preview")
async def preview(body: ActionRequest, db: AsyncSession = Depends(get_db), _: User = Depends(require_write_access)):
    """What would run, what is skipped, and what apt would change (simulation, changes nothing)."""
    return {"kind": body.kind, "busy": runner.is_busy(), "parallel": runner.PARALLEL,
            "hosts": await runner.preview(db, await _targets(db, body.host_ids), body.kind)}


@router.post("/actions")
async def execute(body: ActionRequest, db: AsyncSession = Depends(get_db), user: User = Depends(require_write_access)):
    targets = await _targets(db, body.host_ids)
    if any(i.type == "node" for i in targets) and not body.confirm_host:
        raise HTTPException(status_code=400, detail="Für den Proxmox-Host ist eine ausdrückliche Bestätigung nötig.")
    try:
        batch_id = await runner.start_batch(db, targets, body.kind, user.username)
    except runner.ActionBusy:
        raise HTTPException(status_code=409, detail="Es läuft bereits eine Aktion. Bitte warten, bis sie fertig ist.")
    return {"batch_id": batch_id}


@router.get("/actions")
async def list_runs(batch_id: Optional[str] = Query(None), limit: int = Query(50, ge=1, le=500),
                    db: AsyncSession = Depends(get_db), _: Optional[User] = Depends(get_current_user_optional)):
    stmt = select(ActionRun).order_by(ActionRun.id.desc()).limit(limit)
    if batch_id:
        stmt = select(ActionRun).where(ActionRun.batch_id == batch_id).order_by(ActionRun.id)
    runs = (await db.execute(stmt)).scalars().all()
    return {"busy": runner.is_busy(), "runs": [_run_dict(r, with_output=bool(batch_id)) for r in runs]}


@router.get("/actions/{run_id}")
async def get_run(run_id: int, db: AsyncSession = Depends(get_db),
                  _: Optional[User] = Depends(get_current_user_optional)):
    run = await db.get(ActionRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Aktion nicht gefunden")
    return _run_dict(run)
