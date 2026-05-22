"""FastAPI application factory for the Logatory web dashboard."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

from logatory import __version__
from logatory.config import Config

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_BUILTIN_RULES_DIR = Path(__file__).parent.parent / "rules" / "builtin"


@asynccontextmanager
async def _lifespan(app: FastAPI):  # type: ignore[type-arg]
    """Load rule engine (built-in + plugins) once at startup; nothing to teardown."""
    from logatory.plugins.loader import load_plugins
    from logatory.rules.engine import RuleEngine
    from logatory.rules.loader import load_rules_dir

    cfg: Config = app.state.config
    rules = list(load_rules_dir(_BUILTIN_RULES_DIR))

    plugin_registry = load_plugins(cfg.plugins_dir)
    for pdir in plugin_registry.rule_dirs:
        rules.extend(load_rules_dir(pdir))
    rules.extend(plugin_registry.rules)

    app.state.rule_engine = RuleEngine(rules)
    yield


def create_app(config: Config) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Logatory",
        description=(
            "Local log analysis dashboard with REST API.\n\n"
            "Authenticate via `Authorization: Bearer <token>` on `/api/v1/*` endpoints "
            "when `api_token` is set in config."
        ),
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=_lifespan,
    )
    app.state.config = config
    app.state.templates = Jinja2Templates(directory=_TEMPLATES_DIR)

    # ── HTML dashboard routes ──────────────────────────────────────────────
    # Dashboard pages and HTMX partials are kept out of the OpenAPI schema, so
    # /api/docs documents only the public REST API (/api/v1/*).
    from .routes import ui as ui_module

    app.include_router(ui_module.router, include_in_schema=False)

    # ── HTMX / JSON dashboard API ──────────────────────────────────────────
    from .routes import api as api_module

    app.include_router(api_module.router, prefix="/api", include_in_schema=False)

    # ── REST API v1 ────────────────────────────────────────────────────────
    from .routes.v1 import health_router
    from .routes.v1 import router as v1_router

    app.include_router(health_router, prefix="/api/v1")
    app.include_router(v1_router, prefix="/api/v1")

    return app


def create_reload_app() -> FastAPI:
    """Factory for uvicorn --reload mode. Reads config path from LOGATORY_CONFIG env var."""
    config_str = os.environ.get("LOGATORY_CONFIG", "")
    config_path = Path(config_str) if config_str else None
    cfg = Config.load(config_path)
    return create_app(cfg)
