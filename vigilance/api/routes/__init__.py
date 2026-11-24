from fastapi import APIRouter

from vigilance.api.routes import (
    health,
    dashboard,
    nodes,
    findings,
    cves,
    scans,
    settings,
    auth,
    views,
)

api_router = APIRouter()

api_router.include_router(health.router, prefix="/api", tags=["health"])
api_router.include_router(dashboard.router, prefix="/api", tags=["dashboard"])
api_router.include_router(nodes.router, prefix="/api", tags=["nodes"])
api_router.include_router(findings.router, prefix="/api", tags=["findings"])
api_router.include_router(cves.router, prefix="/api", tags=["cves"])
api_router.include_router(scans.router, prefix="/api", tags=["scans"])
api_router.include_router(settings.router, prefix="/api", tags=["settings"])
api_router.include_router(auth.router, prefix="/api", tags=["auth"])
api_router.include_router(views.router, prefix="/api", tags=["views"])
