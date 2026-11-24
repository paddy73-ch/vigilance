"""Authentication.

* Reading needs no login (access is limited by the network: LAN/VPN firewall).
* Writing needs the API token (``Authorization: Bearer <token>``).
* A reverse-proxy user header (``Remote-User``) is only trusted when the request
  comes from one of ``VIGILANCE_TRUSTED_PROXIES`` (IPs/CIDRs, comma separated).
  Without trusted proxies the header is ignored, so it cannot be spoofed by a
  client that talks to port 8000 directly.
"""

import ipaddress
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional, Union

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.config import settings
from vigilance.core import auth_token
from vigilance.database.base import get_db

logger = logging.getLogger(__name__)

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass
class User:
    username: str
    is_admin: bool = False
    can_write: bool = False
    auth_method: str = "unknown"  # proxy, token


@lru_cache(maxsize=8)
def _parse_networks(raw: str) -> List[Network]:
    networks = []
    for part in (raw or "").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            logger.error("Ignoring invalid entry in VIGILANCE_TRUSTED_PROXIES: %r", part)
    return networks


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def is_trusted_proxy(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _parse_networks(settings.trusted_proxies))


def _bearer(request: Request) -> Optional[str]:
    header = request.headers.get("authorization") or ""
    if header[:7].lower() == "bearer ":
        return header[7:].strip() or None
    return None


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    ip = client_ip(request)
    token = _bearer(request)

    if token:
        if auth_token.is_rate_limited(ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Try again in 15 minutes.",
            )
        stored_hash = await auth_token.get_stored_hash(db)
        if auth_token.verify_token(token, stored_hash):
            return User(username="api-token", is_admin=True, can_write=True, auth_method="token")
        auth_token.record_failure(ip)
        logger.warning("Invalid API token from %s", ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    remote_user = request.headers.get(settings.remote_user_header or "Remote-User")
    if remote_user and settings.auth_mode in ("proxy", "both") and is_trusted_proxy(ip):
        return User(username=remote_user, is_admin=True, can_write=True, auth_method="proxy")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API token required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_optional(request: Request, db: AsyncSession = Depends(get_db)) -> Optional[User]:
    """For read endpoints: never fails because of missing credentials."""
    try:
        return await get_current_user(request, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            raise
        return None


def require_write_access(user: User = Depends(get_current_user)) -> User:
    if not user.can_write:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Write access required")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user
