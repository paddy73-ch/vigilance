from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from vigilance.api.deps import get_current_user_optional
from vigilance.core.security import User

router = APIRouter()

# Templates
template_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"request": request})


@router.get("/nodes", response_class=HTMLResponse)
async def nodes_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse(request=request, name="nodes.html", context={"request": request})


@router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse(request=request, name="findings.html", context={"request": request})


@router.get("/cves", response_class=HTMLResponse)
async def cves_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse(request=request, name="cves.html", context={"request": request})


@router.get("/suppressions", response_class=HTMLResponse)
async def suppressions_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse(request=request, name="suppressions.html", context={"request": request})


@router.get("/overrides", response_class=HTMLResponse)
async def overrides_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse(request=request, name="overrides.html", context={"request": request})


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse(request=request, name="settings.html", context={"request": request})