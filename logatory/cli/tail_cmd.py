"""Realtime log tailing — `logatory tail <file>`.

Watches a log file for new lines, applies PII redaction and the rule
engine on each incoming event, and prints findings immediately with
colour-coded severity.  Optionally persists errors/findings and fires
webhook alerts.  Runs until the user presses Ctrl+C.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.tail import TailAdapter
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._types import REDACT_MAP, RedactModeArg
from logatory.cli.colors import SEVERITY_COLOR
from logatory.config import Config
from logatory.models import Finding
from logatory.pii.redactor import PIIRedactor
from logatory.plugins.loader import compile_plugin_pii_patterns, load_plugins
from logatory.rules.loader import build_engine

# ---------------------------------------------------------------------------
# Public entry point (registered on the main Typer app by main.py)
# ---------------------------------------------------------------------------


def tail_watch(
    path: Annotated[Path, typer.Argument(help="Log file to watch.")],
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    from_start: Annotated[
        bool, typer.Option("--from-start", help="Read from beginning instead of end.")
    ] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip rule engine.")] = False,
    rules_dir: Annotated[
        Optional[Path], typer.Option("--rules-dir", help="Extra rules directory.")
    ] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite.")
    ] = False,
    track_findings: Annotated[
        bool,
        typer.Option("--track-findings", help="Persist HIGH/CRITICAL findings to SQLite."),
    ] = False,
    alert_webhook: Annotated[
        Optional[str],
        typer.Option("--alert-webhook", help="POST findings as JSON to this URL."),
    ] = None,
    alert_min_severity: Annotated[
        str,
        typer.Option(
            "--alert-min-severity",
            help="Minimum severity to fire webhook: low|medium|high|critical.",
        ),
    ] = "high",
    poll_interval: Annotated[
        float,
        typer.Option("--poll-interval", help="File poll interval in seconds."),
    ] = 0.2,
) -> None:
    """Watch a log file for new events in real time. Press Ctrl+C to stop."""
    if not path.exists():
        typer.echo(f"Error: file not found: {path}", err=True)
        raise typer.Exit(1)

    cfg = Config.load(config)

    # Load plugins first (PII patterns + rules)
    plugin_registry = load_plugins(cfg.plugins_dir)
    plugin_pii = compile_plugin_pii_patterns(plugin_registry)
    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt,
        rules_path=cfg.pii_rules_path,
        mode=REDACT_MAP[redact],
        additional=plugin_pii or None,
    )

    engine = build_engine(no_rules, rules_dir, plugin_registry)

    adapter = TailAdapter(path, from_start=from_start, poll_interval=poll_interval)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Tailing  : {path}")
    typer.echo(f"  Rules    : {'off' if no_rules else 'on'}")
    typer.echo(f"  PII      : {redact.value}")
    if track_errors:
        typer.echo(f"  Errors   : tracking -> {cfg.db_path}")
    if track_findings:
        typer.echo(f"  Findings : tracking (>= {cfg.findings_min_severity})")
    if alert_webhook:
        typer.echo(f"  Webhook  : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts: dict[str, int] = {
        "events": 0,
        "findings": 0,
        "pii": 0,
        "errors": 0,
        "webhooks": 0,
    }

    async def _run() -> None:
        await run_tail_pipeline(
            event_stream=adapter.events(),
            redactor=redactor,
            engine=engine,
            counts=counts,
            cfg=cfg,
            print_finding=_print_finding,
            track_errors=track_errors,
            track_findings=track_findings,
            alert_webhook=alert_webhook,
            alert_min_severity=alert_min_severity,
        )

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass

    # Summary
    typer.echo(f"\n{sep}")
    typer.echo("  Stopped.")
    typer.echo(f"  Events   : {counts['events']:,}")
    typer.echo(f"  PII hits : {counts['pii']:,}")
    typer.echo(f"  Findings : {counts['findings']:,}")
    if track_errors:
        typer.echo(f"  Errors   : {counts['errors']:,} tracked")
    if alert_webhook:
        typer.echo(f"  Webhooks : {counts['webhooks']:,} sent")
    typer.echo(sep)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _print_finding(finding: Finding) -> None:
    ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    sev = finding.severity.value
    color = SEVERITY_COLOR.get(sev, typer.colors.WHITE)
    line = f"  [{sev.upper()}] {ts}  {finding.rule_id}  {finding.message}"
    typer.echo(typer.style(line, fg=color))
