from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_db, get_current_user_optional, require_write_access
from vigilance.api.schemas import (
    ToolOverrideResponse,
    ToolOverrideCreate,
    ToolOverrideUpdate,
)
from vigilance.database import crud
from vigilance.core.security import User

router = APIRouter()


@router.get("/overrides", response_model=List[ToolOverrideResponse])
async def list_overrides(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """List all tool overrides."""
    return await crud.get_tool_overrides(db)


@router.post("/overrides", response_model=ToolOverrideResponse)
async def create_override(
    override: ToolOverrideCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Create a new tool override."""
    return await crud.upsert_tool_override(db, **override.model_dump())


@router.patch("/overrides/{tool_name}", response_model=ToolOverrideResponse)
async def update_override(
    tool_name: str,
    override: ToolOverrideUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Update a tool override."""
    existing = await crud.get_tool_override(db, tool_name)
    if not existing:
        raise HTTPException(status_code=404, detail="Override not found")

    return await crud.upsert_tool_override(db, tool_name=tool_name, **override.model_dump(exclude_unset=True))


@router.delete("/overrides/{tool_name}")
async def delete_override(
    tool_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Delete a tool override."""
    success = await crud.delete_tool_override(db, tool_name)
    if not success:
        raise HTTPException(status_code=404, detail="Override not found")
    return {"message": "Override deleted"}