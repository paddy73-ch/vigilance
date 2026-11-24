"""API token for write access.

* Vigilance generates the token itself; only its SHA-256 hash is stored
  (app_settings ``api_token_sha256``). The token is shown once.
* Generating a new token replaces the old one immediately.
* ``VIGILANCE_API_TOKEN`` from the environment is only used as long as no
  generated token exists.
* Failed attempts are rate limited per client IP.

The hash is read from the database whenever a token is presented, so a token
rotated with the CLI (separate process) takes effect immediately.
"""

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, Optional, Tuple

from vigilance.config import settings

TOKEN_HASH_KEY = "api_token_sha256"
TOKEN_CREATED_KEY = "api_token_created_at"
TOKEN_PREFIX = "vig_"

MAX_FAILURES = 10
FAILURE_WINDOW_SECONDS = 15 * 60

_failures: Dict[str, Deque[float]] = defaultdict(deque)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_token() -> Tuple[str, str]:
    """Return (token, sha256 hash)."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, _sha256(token)


def verify_token(token: Optional[str], stored_hash: Optional[str]) -> bool:
    """Generated token (hash) wins; the env token only counts while none was generated."""
    if not token:
        return False
    if stored_hash:
        return hmac.compare_digest(_sha256(token), stored_hash)
    if settings.api_token:
        return hmac.compare_digest(token.encode("utf-8"), settings.api_token.encode("utf-8"))
    return False


def _prune(client: str, now: float) -> Deque[float]:
    attempts = _failures[client]
    while attempts and now - attempts[0] > FAILURE_WINDOW_SECONDS:
        attempts.popleft()
    return attempts


def is_rate_limited(client: str) -> bool:
    return len(_prune(client, time.monotonic())) >= MAX_FAILURES


def record_failure(client: str) -> None:
    now = time.monotonic()
    _prune(client, now).append(now)


def reset_failures() -> None:
    _failures.clear()


async def get_token_info(db) -> dict:
    from vigilance.database import crud
    stored = await crud.get_setting(db, TOKEN_HASH_KEY)
    if stored:
        return {"configured": True, "source": "generated", "created_at": await crud.get_setting(db, TOKEN_CREATED_KEY)}
    if settings.api_token:
        return {"configured": True, "source": "env", "created_at": None}
    return {"configured": False, "source": None, "created_at": None}


async def get_stored_hash(db) -> Optional[str]:
    from vigilance.database import crud
    return await crud.get_setting(db, TOKEN_HASH_KEY)


async def rotate_token(db) -> str:
    """Create a new token, store its hash and return the token (shown once)."""
    from vigilance.database import crud
    token, token_hash = generate_token()
    created = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    await crud.set_setting(db, TOKEN_HASH_KEY, token_hash, "SHA-256 of the API token for write access")
    await crud.set_setting(db, TOKEN_CREATED_KEY, created, "When the API token was generated")
    await db.commit()
    return token
