"""FastAPI Application Entrypoint (dashboard/app.py).

Configures:
- FastAPI web service bound to 127.0.0.1:8000
- Mounting of static assets (/static)
- Registration of all 11 HTML page routes and REST API endpoints
- Safe startup recovery via JobManager (zero auto-running D1/D2/D3 on boot)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from dashboard.routes.api import router as api_router
from dashboard.routes.pages import router as pages_router
from dashboard.services.job_manager import get_job_manager

logger = logging.getLogger("dashboard.app")

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs startup verification and crash recovery without auto-running D1/D2/D3."""
    logger.info("Initializing Forensic Dashboard service...")
    jm = get_job_manager()
    logger.info("JobManager ready. Anti-overlap and filelock mutex active. Is busy: %s", jm.is_busy())
    yield


def create_app() -> FastAPI:
    """Factory creating and configuring the forensic FastAPI application."""
    app = FastAPI(
        title="Blockchain Ai Aigital Forensics",
        description="FastAPI Web Dashboard for Blockchain Ai Aigital Forensics",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    # Mount static assets directory
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Include routers
    app.include_router(pages_router)
    app.include_router(api_router)

    @app.exception_handler(404)
    async def custom_404_handler(request: Request, exc: Any) -> Any:
        if request.url.path.startswith("/api"):
            return JSONResponse(status_code=404, content={"detail": "API endpoint không tồn tại."})
        return HTMLResponse(
            """<!DOCTYPE html>
            <html lang="vi" class="bg-slate-950 text-slate-100 p-8 font-sans">
              <head><meta charset="utf-8"><title>404 - Không tìm thấy trang</title></head>
              <body class="max-w-md mx-auto text-center space-y-4 pt-20">
                <h1 class="text-3xl font-bold text-cyan-400">404</h1>
                <p class="text-sm text-slate-400">Trang bạn yêu cầu không tồn tại trong Blockchain Ai Aigital Forensics.</p>
                <a href="/" class="inline-block px-4 py-2 bg-cyan-600 rounded text-sm text-white font-bold">Về Trang Tổng quan</a>
              </body>
            </html>""",
            status_code=404,
        )

    return app


app = create_app()
