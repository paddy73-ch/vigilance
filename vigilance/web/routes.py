from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from vigilance.api.deps import get_current_user_optional
from vigilance.core.security import User

router = APIRouter()

# Templates
template_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@router.get("/nodes", response_class=HTMLResponse)
async def nodes_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse("nodes.html", {"request": request})


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse("findings.html", {"request": request})


@router.get("/cves", response_class=HTMLResponse)
async def cves_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse("cves.html", {"request": request})


@router.get("/suppressions", response_class=HTMLResponse)
async def suppressions_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse("suppressions.html", {"request": request})


@router.get("/overrides", response_class=HTMLResponse)
async def overrides_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse("overrides.html", {"request": request})


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse("settings.html", {"request": request})