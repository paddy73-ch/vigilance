from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_current_user, get_db, require_write_access
from vigilance.core import auth_token
from vigilance.core.security import User

router = APIRouter()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    message: str = "Store this token now - it is shown only once. The previous token is no longer valid."


@router.get("/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Who am I (401 without a valid token)."""
    return {
        "username": current_user.username,
        "is_admin": current_user.is_admin,
        "can_write": current_user.can_write,
        "auth_method": current_user.auth_method,
    }


@router.post("/auth/token", response_model=TokenResponse)
async def rotate_api_token(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_write_access),
):
    """Generate a new API token. Replaces the current one immediately."""
    return TokenResponse(access_token=await auth_token.rotate_token(db))
