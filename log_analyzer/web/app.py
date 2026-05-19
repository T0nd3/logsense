"""FastAPI application factory for the LogSense web dashboard."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from log_analyzer.config import Config

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_app(config: Config) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="LogSense",
        description="Log analysis dashboard",
        docs_url=None,
        redoc_url=None,
    )
    app.state.config = config
    app.state.templates = Jinja2Templates(directory=_TEMPLATES_DIR)

    from .routes import api as api_module
    from .routes import ui as ui_module

    app.include_router(ui_module.router)
    app.include_router(api_module.router, prefix="/api")

    return app


def create_reload_app() -> FastAPI:
    """Factory for uvicorn --reload mode. Reads config path from LOGSENSE_CONFIG env var."""
    config_str = os.environ.get("LOGSENSE_CONFIG", "")
    config_path = Path(config_str) if config_str else None
    cfg = Config.load(config_path)
    return create_app(cfg)
