from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from vigilance.api.deps import get_db, get_current_user_optional, require_write_access
from vigilance.api.schemas import (
    ProxmoxNodeResponse,
    ProxmoxNodeCreate,
    ProxmoxNodeUpdate,
    InventoryResponse,
)
from vigilance.database import crud
from vigilance.database.models import ProxmoxNode, Inventory
from vigilance.core.security import User

router = APIRouter()


@router.get("/nodes", response_model=List[ProxmoxNodeResponse])
async def list_nodes(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """List all Proxmox nodes."""
    nodes = await crud.get_proxmox_nodes(db)
    return nodes


@router.post("/nodes", response_model=ProxmoxNodeResponse)
async def create_node(
    node_data: ProxmoxNodeCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Create a new Proxmox node configuration."""
    # Check if name already exists
    existing = await crud.get_proxmox_node_by_name(db, node_data.name)
    if existing:
        raise HTTPException(status_code=400, detail="Node with this name already exists")

    node = await crud.create_proxmox_node(db, **node_data.model_dump())
    return node


@router.get("/nodes/{node_id}", response_model=ProxmoxNodeResponse)
async def get_node(
    node_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get a specific Proxmox node."""
    node = await crud.get_proxmox_node(db, node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


@router.patch("/nodes/{node_id}", response_model=ProxmoxNodeResponse)
async def update_node(
    node_id: int,
    node_data: ProxmoxNodeUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Update a Proxmox node."""
    node = await crud.update_proxmox_node(db, node_id, **node_data.model_dump(exclude_unset=True))
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


@router.delete("/nodes/{node_id}")
async def delete_node(
    node_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Delete a Proxmox node."""
    success = await crud.delete_proxmox_node(db, node_id)
    if not success:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"message": "Node deleted"}


@router.get("/nodes/{node_id}/inventories", response_model=List[InventoryResponse])
async def list_node_inventories(
    node_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """List all VMs/LXCs for a Proxmox node."""
    inventories = await crud.get_inventories(db, node_id=node_id)
    return inventories


@router.get("/inventories/{inventory_id}", response_model=InventoryResponse)
async def get_inventory(
    inventory_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get a specific inventory (VM/LXC)."""
    inventory = await crud.get_inventory(db, inventory_id)
    if not inventory:
        raise HTTPException(status_code=404, detail="Inventory not found")
    return inventory


@router.get("/inventories/{inventory_id}/tools")
async def get_inventory_tools(
    inventory_id: int,
    source_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_optional),
):
    """Get discovered tools for an inventory."""
    tools = await crud.get_discovered_tools(db, inventory_id=inventory_id, source_type=source_type)
    return tools