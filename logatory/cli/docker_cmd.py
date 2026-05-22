"""CLI command group: logatory docker — analyze logs from local containers."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.docker import DockerAdapter
from logatory.cli._types import REDACT_MAP, RedactModeArg
from logatory.config import Config
from logatory.errors.tracker import ErrorTracker
from logatory.models import Event, Finding
from logatory.pii.patterns import PIIPattern
from logatory.pii.redactor import PIIRedactor
from logatory.plugins.loader import load_plugins
from logatory.rules.engine import RuleEngine
from logatory.rules.loader import load_rules_dir
from logatory.storage.errors_repo import ErrorsRepository

_BUILTIN_RULES_DIR = Path(__file__).parent.parent / "rules" / "builtin"

app = typer.Typer(help="Analyze logs from local Docker containers — no log stack needed.")

_SEVERITY_COLOR = {
    "low": typer.colors.CYAN,
    "medium": typer.colors.YELLOW,
    "high": typer.colors.RED,
    "critical": typer.colors.BRIGHT_RED,
}


@app.command("scan")
def docker_scan(
    name: Annotated[
        Optional[str], typer.Option("--name", "-n", help="Filter containers by name (substring).")
    ] = None,
    label: Annotated[
        Optional[str], typer.Option("--label", "-l", help="Filter by label: 'key' or 'key=value'.")
    ] = None,
    include_stopped: Annotated[
        bool, typer.Option("--all", "-a", help="Include stopped containers.")
    ] = False,
    tail: Annotated[int, typer.Option("--tail", help="Log lines to fetch per container.")] = 200,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    limit: Annotated[int, typer.Option("--limit", help="Max events to display.")] = 50,
    show_all: Annotated[bool, typer.Option("--show-all", help="Display every event.")] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip the rule engine.")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite.")
    ] = False,
) -> None:
    """Fetch logs from local Docker containers, redact PII, run detection rules.

    No log-aggregation stack required — the logs come straight from the
    Docker daemon. Each event is tagged with its container name.
    """
    cfg = Config.load(config)

    plugin_registry = load_plugins(cfg.plugins_dir)
    plugin_pii = [
        PIIPattern(name=p["name"], pattern=re.compile(p["pattern"]), prefix=p["prefix"])
        for p in plugin_registry.pii_patterns
    ]
    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt,
        rules_path=cfg.pii_rules_path,
        mode=REDACT_MAP[redact],
        additional=plugin_pii or None,
    )

    engine: RuleEngine | None = None
    if not no_rules:
        all_rules = list(load_rules_dir(_BUILTIN_RULES_DIR))
        if rules_dir and rules_dir.is_dir():
            all_rules.extend(load_rules_dir(rules_dir))
        for pdir in plugin_registry.rule_dirs:
            all_rules.extend(load_rules_dir(pdir))
        all_rules.extend(plugin_registry.rules)
        engine = RuleEngine(all_rules)

    events: list[Event] = []
    findings: list[Finding] = []
    pii_hits = 0

    async def _run() -> None:
        nonlocal pii_hits
        adapter = DockerAdapter(name=name, label=label, include_stopped=include_stopped, tail=tail)
        async for event in adapter.events():
            result = redactor.redact(event.message)
            event.message = result.text
            event.raw = redactor.redact(event.raw).text
            pii_hits += len(result.hits)
            events.append(event)
            if engine:
                findings.extend(engine.process(event))

    try:
        asyncio.run(_run())
    except ImportError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Error talking to Docker: {e}", err=True)
        raise typer.Exit(1)

    containers = sorted({e.source for e in events})
    sep = "-" * 60
    typer.echo(
        f"\n{sep}\n"
        f"  Source     : Docker ({len(containers)} container(s))\n"
        f"  Events     : {len(events):,}\n"
        f"  PII hits   : {pii_hits:,} (mode: {redact.value})\n"
        f"  Findings   : {len(findings):,}\n"
        f"{sep}"
    )
    if containers:
        typer.echo(f"  Containers : {', '.join(containers)}")

    sample = events if show_all else events[:limit]
    if sample:
        typer.echo(f"\n  Events ({len(sample)} of {len(events):,}):\n")
        for i, ev in enumerate(sample, 1):
            ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "no timestamp"
            sev = ev.severity.value.upper().ljust(8)
            typer.echo(f"  [{i:>5}] {ts}  {sev}  {ev.source}  {ev.message[:100]}")
        if not show_all and len(events) > limit:
            typer.echo(f"\n  ... {len(events) - limit:,} more. Use --show-all or --limit N.")

    if findings:
        typer.echo(f"\n  Findings ({len(findings)}):\n")
        for finding in findings:
            color = _SEVERITY_COLOR.get(finding.severity.value, typer.colors.WHITE)
            ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            line = (
                f"  [{finding.severity.value.upper()}] {ts}  {finding.rule_id}  {finding.message}"
            )
            typer.echo(typer.style(line, fg=color))
    elif not no_rules:
        typer.echo("\n  No findings.")

    if track_errors and events:
        with ErrorsRepository(cfg.db_path) as e_repo:
            tracker = ErrorTracker(e_repo)
            tracked = sum(1 for ev in events if tracker.process(ev) is not None)
        typer.echo(f"\n  Errors tracked: {tracked:,} -> {cfg.db_path}")
