from typing import AsyncGenerator
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.database.base import get_db
from vigilance.core.security import get_current_user, get_current_user_optional, require_write_access, require_admin, User


# Re-export for convenience
get_db = get_db
get_current_user = get_current_user
get_current_user_optional = get_current_user_optional
require_write_access = require_write_access
require_admin = require_admin
User = User