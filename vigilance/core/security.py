from typing import Optional
from dataclasses import dataclass
from fastapi import Depends, Header, HTTPException, Request, status
from vigilance.config import settings


@dataclass
class User:
    username: str
    is_admin: bool = False
    can_write: bool = False
    auth_method: str = "unknown"  # proxy, token, builtin


async def get_current_user(
    request: Request,
    remote_user: Optional[str] = Header(None, alias="Remote-User"),
    authorization: Optional[str] = Header(None),
) -> User:
    auth_mode = settings.auth_mode.lower()

    # Check API Token for write access
    has_token = False
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        if token == settings.api_token and settings.api_token:
            has_token = True

    # Proxy authentication (Reverse Proxy / SSO)
    if auth_mode in ("proxy", "both") and remote_user:
        return User(
            username=remote_user,
            is_admin=has_token,
            can_write=True,
            auth_method="proxy",
        )

    # API token authentication (works regardless of auth_mode)
    if has_token:
        return User(
            username="api-user",
            is_admin=True,
            can_write=True,
            auth_method="token",
        )

    # Built-in authentication (if enabled)
    if auth_mode in ("builtin", "both"):
        # For MVP, we just check token; full built-in auth would need session/JWT
        # (token check above already covers this case)
        pass

    # No valid authentication
    if auth_mode == "proxy":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (Reverse Proxy)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user_optional(
    request: Request,
    remote_user: Optional[str] = Header(None, alias="Remote-User"),
    authorization: Optional[str] = Header(None),
) -> Optional[User]:
    try:
        return await get_current_user(request, remote_user, authorization)
    except HTTPException:
        return None


def require_write_access(user: User = Depends(get_current_user)) -> User:
    if not user.can_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write access requires API token",
        )
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user