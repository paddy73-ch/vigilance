from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from vigilance.api.routes import api_router
from vigilance.core.scheduler import lifespan
from vigilance.web.routes import router as web_router

app = FastAPI(title="Vigilance", lifespan=lifespan)

# Everything is served from this origin; nothing is loaded from elsewhere.
# 'unsafe-eval' is required by Alpine.js (it compiles x-* expressions at runtime).
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-eval'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if request.url.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "public, max-age=86400")
    return response


app.include_router(api_router)
app.include_router(web_router)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web/static"), name="static")
