"""CLI command: logatory serve — starts the Logatory web dashboard."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer


def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to."),
    port: int = typer.Option(8080, "--port", "-p", help="Port to listen on."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path."),
    reload: bool = typer.Option(
        False, "--reload", help="Auto-reload on source changes (dev mode)."
    ),
) -> None:
    """Start the Logatory web dashboard.

    Install web dependencies first:

        pip install 'logatory[web]'
    """
    try:
        import uvicorn
    except ImportError:
        typer.echo(
            "Error: uvicorn is not installed.\n"
            "Install web dependencies with:\n\n"
            "  pip install 'logatory[web]'\n",
            err=True,
        )
        raise typer.Exit(1)

    from logatory.config import Config
    from logatory.web.app import create_app

    url = f"http://{host}:{port}"
    typer.echo(f"\n  Logatory dashboard -> {url}\n  Press Ctrl+C to stop.\n")

    if reload:
        # Pass config path via env var so the factory can pick it up after reload
        if config:
            os.environ["LOGATORY_CONFIG"] = str(config)
        import uvicorn

        uvicorn.run(
            "logatory.web.app:create_reload_app",
            host=host,
            port=port,
            reload=True,
            factory=True,
        )
    else:
        cfg = Config.load(config)
        web_app = create_app(cfg)
        import uvicorn

        uvicorn.run(web_app, host=host, port=port, log_level="info")
