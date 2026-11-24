from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from vigilance import __version__ as _app_version
from vigilance.api.deps import get_current_user_optional
from vigilance.core.security import User

router = APIRouter()

template_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))
# Cache busting for /static: changes with every release
templates.env.globals["asset_version"] = _app_version


def _page(name: str):
    async def handler(request: Request, current_user: User = Depends(get_current_user_optional)):
        return templates.TemplateResponse(request=request, name=name, context={"request": request})
    return handler


router.add_api_route("/", _page("overview.html"), response_class=HTMLResponse, include_in_schema=False)
router.add_api_route("/hosts", _page("hosts.html"), response_class=HTMLResponse, include_in_schema=False)
router.add_api_route("/vulnerabilities", _page("vulnerabilities.html"), response_class=HTMLResponse, include_in_schema=False)
router.add_api_route("/admin/sources", _page("admin_sources.html"), response_class=HTMLResponse, include_in_schema=False)
router.add_api_route("/admin/exceptions", _page("admin_exceptions.html"), response_class=HTMLResponse, include_in_schema=False)
router.add_api_route("/admin/settings", _page("admin_settings.html"), response_class=HTMLResponse, include_in_schema=False)
router.add_api_route("/admin/actions", _page("admin_actions.html"), response_class=HTMLResponse, include_in_schema=False)


@router.get("/hosts/{inventory_id}", response_class=HTMLResponse, include_in_schema=False)
async def host_page(request: Request, inventory_id: int, current_user: User = Depends(get_current_user_optional)):
    return templates.TemplateResponse(request=request, name="host.html",
                                      context={"request": request, "inventory_id": inventory_id})


# Old addresses (bookmarks) -> new pages
_REDIRECTS = {
    "/findings": "/vulnerabilities",
    "/containers": "/hosts",
    "/cves": "/vulnerabilities?view=cve",
    "/nodes": "/admin/settings",
    "/suppressions": "/admin/exceptions",
    "/overrides": "/admin/settings",
    "/settings": "/admin/settings",
    "/admin": "/admin/sources",
}


def _redirect(target: str):
    async def handler(request: Request):
        query = request.url.query
        if query and "?" not in target:
            return RedirectResponse(f"{target}?{query}", status_code=301)
        return RedirectResponse(target, status_code=301)
    return handler


for _old, _new in _REDIRECTS.items():
    router.add_api_route(_old, _redirect(_new), include_in_schema=False)
