"""Remediation actions: preview (simulation) and execution of apt on LXC containers."""

import json
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.actions import runner
from vigilance.api.deps import get_current_user_optional, get_db, require_write_access
from vigilance.core.security import User
from vigilance.database.models import ActionRun, Inventory

router = APIRouter()


class ActionRequest(BaseModel):
    kind: Literal["suggested", "full_upgrade"]
    host_ids: Optional[List[int]] = Field(None, description="Leer = alle laufenden LXC-Container")


async def _targets(db: AsyncSession, host_ids: Optional[List[int]]) -> List[Inventory]:
    stmt = select(Inventory).order_by(Inventory.vmid)
    if host_ids:
        stmt = stmt.where(Inventory.id.in_(host_ids))
    else:
        # "all": running containers only; the Proxmox host and VMs are never targets
        stmt = stmt.where(Inventory.type == "lxc", Inventory.status == "running")
    invs = list((await db.execute(stmt)).scalars().all())
    if host_ids and len(invs) != len(set(host_ids)):
        raise HTTPException(status_code=404, detail="Host nicht gefunden")
    return invs


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
    return {"kind": body.kind, "busy": runner.is_busy(),
            "hosts": await runner.preview(db, await _targets(db, body.host_ids), body.kind)}


@router.post("/actions")
async def execute(body: ActionRequest, db: AsyncSession = Depends(get_db), user: User = Depends(require_write_access)):
    try:
        batch_id = await runner.start_batch(db, await _targets(db, body.host_ids), body.kind, user.username)
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
