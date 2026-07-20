"""FastAPI application factory for the ShadowSensor dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

TEMPLATES = Jinja2Templates(directory=Path(__file__).parent / "templates")
STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    """Create and configure the ShadowSensor FastAPI application."""
    app = FastAPI(title="ShadowSensor", version="0.3.0", docs_url="/api/docs")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    from dashboard.routers.api import router as api_router
    from dashboard.routers.killchain import router as killchain_router
    from dashboard.routers.pages import router as pages_router

    app.include_router(pages_router)
    app.include_router(killchain_router)
    app.include_router(api_router, prefix="/api/v1", tags=["api"])

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard/home", status_code=302)

    return app


app = create_app()
