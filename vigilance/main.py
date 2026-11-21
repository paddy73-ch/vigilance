from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from vigilance.api.routes import api_router
from vigilance.core.scheduler import lifespan
from vigilance.web.routes import router as web_router

app = FastAPI(title="Vigilance", lifespan=lifespan)
app.include_router(api_router)
app.include_router(web_router)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web/static"), name="static")
