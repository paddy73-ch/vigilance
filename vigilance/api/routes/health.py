from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from vigilance.api.deps import get_db
from vigilance.api.schemas import HealthResponse
from vigilance.config import settings
from vigilance.database.base import engine
from datetime import datetime

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint for Docker healthcheck and monitoring."""
    # Check database connectivity
    db_status = "ok"
    try:
        await db.execute("SELECT 1")
    except Exception:
        db_status = "error"

    return HealthResponse(
        status="healthy" if db_status == "ok" else "degraded",
        timestamp=datetime.utcnow(),
        database=db_status,
    )