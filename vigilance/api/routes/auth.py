from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from vigilance.api.deps import get_current_user
from vigilance.core.security import User

router = APIRouter()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.get("/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info."""
    return {
        "username": current_user.username,
        "is_admin": current_user.is_admin,
        "can_write": current_user.can_write,
        "auth_method": current_user.auth_method,
    }


@router.post("/auth/token", response_model=TokenResponse)
async def create_token():
    """Create an API token (placeholder for built-in auth)."""
    raise HTTPException(status_code=501, detail="Built-in token creation not implemented in MVP")