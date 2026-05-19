"""Realtime log tailing — `analyzer tail <file>`.

Watches a log file for new lines, applies PII redaction and the rule
engine on each incoming event, and prints findings immediately with
colour-coded severity.  Optionally persists errors/findings and fires
webhook alerts.  Runs until the user presses Ctrl+C.
"""
from __future__ import annotations

import asyncio
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

from log_analyzer.adapters.tail import TailAdapter
from log_analyzer.config import Config
from log_analyzer.errors.tracker import ErrorTracker
from log_analyzer.models import Finding
from log_analyzer.pii.redactor import PIIRedactor, RedactMode
from log_analyzer.rules.engine import RuleEngine
from log_analyzer.rules.loader import load_rules_dir
from log_analyzer.storage.errors_repo import ErrorsRepository
from log_analyzer.storage.findings_repo import FindingsRepository, meets_min_severity
from log_analyzer.tail_helpers import meets_alert_severity, post_webhook

_BUILTIN_RULES_DIR = Path(__file__).parent.parent / "log_analyzer" / "rules" / "builtin"

_SEVERITY_COLOR = {
    "low": typer.colors.CYAN,
    "medium": typer.colors.YELLOW,
    "high": typer.colors.RED,
    "critical": typer.colors.BRIGHT_RED,
}


class _RedactModeArg(str, Enum):
    redact = "redact"
    mask = "mask"
    dry_run = "dry-run"


_REDACT_MAP = {
    _RedactModeArg.redact: RedactMode.REDACT,
    _RedactModeArg.mask: RedactMode.MASK,
    _RedactModeArg.dry_run: RedactMode.DRY_RUN,
}


# ---------------------------------------------------------------------------
# Public entry point (registered on the main Typer app by main.py)
# ---------------------------------------------------------------------------

def tail_watch(
    path: Annotated[Path, typer.Argument(help="Log file to watch.")],
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[_RedactModeArg, typer.Option("--redact")] = _RedactModeArg.redact,
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
    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt,
        rules_path=cfg.pii_rules_path,
        mode=_REDACT_MAP[redact],
    )

    engine: RuleEngine | None = None
    if not no_rules:
        all_rules = list(load_rules_dir(_BUILTIN_RULES_DIR))
        if rules_dir and rules_dir.is_dir():
            all_rules.extend(load_rules_dir(rules_dir))
        engine = RuleEngine(all_rules)

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
        e_repo: ErrorsRepository | None = None
        tracker: ErrorTracker | None = None
        f_repo: FindingsRepository | None = None

        if track_errors:
            e_repo = ErrorsRepository(cfg.db_path)
            e_repo.open()
            tracker = ErrorTracker(e_repo)
        if track_findings:
            f_repo = FindingsRepository(cfg.db_path)
            f_repo.open()

        try:
            async for event in adapter.events():
                # PII redaction
                result = redactor.redact(event.message)
                event.message = result.text
                event.raw = redactor.redact(event.raw).text
                counts["pii"] += len(result.hits)
                counts["events"] += 1

                # Rule engine
                if engine:
                    for finding in engine.process(event):
                        _print_finding(finding)
                        counts["findings"] += 1

                        if alert_webhook and meets_alert_severity(
                            finding, alert_min_severity
                        ):
                            post_webhook(alert_webhook, finding)
                            counts["webhooks"] += 1

                        if f_repo and meets_min_severity(
                            finding, cfg.findings_min_severity
                        ):
                            f_repo.add_findings([finding])

                # Error tracking
                if tracker and tracker.process(event) is not None:
                    counts["errors"] += 1

        finally:
            if e_repo:
                e_repo.close()
            if f_repo:
                f_repo.close()

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
    color = _SEVERITY_COLOR.get(sev, typer.colors.WHITE)
    line = f"  [{sev.upper()}] {ts}  {finding.rule_id}  {finding.message}"
    typer.echo(typer.style(line, fg=color))
