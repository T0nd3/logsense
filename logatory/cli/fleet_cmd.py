"""CLI command group: logatory fleet — analyze logs from multiple targets at once."""

from __future__ import annotations

import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.cli._types import REDACT_MAP, RedactModeArg
from logatory.config import Config
from logatory.errors.tracker import ErrorTracker
from logatory.fleet import (
    Target,
    TargetConfigError,
    build_adapter,
    load_targets,
    select_targets,
)
from logatory.models import Event, Finding
from logatory.pii.patterns import PIIPattern
from logatory.pii.redactor import PIIRedactor
from logatory.plugins.loader import load_plugins
from logatory.rules.engine import RuleEngine
from logatory.rules.loader import load_rules_dir
from logatory.storage.errors_repo import ErrorsRepository

_BUILTIN_RULES_DIR = Path(__file__).parent.parent / "rules" / "builtin"

app = typer.Typer(help="Analyze logs from multiple configured targets — a fleet.")

_SEVERITY_COLOR = {
    "low": typer.colors.CYAN,
    "medium": typer.colors.YELLOW,
    "high": typer.colors.RED,
    "critical": typer.colors.BRIGHT_RED,
}


@app.callback()
def fleet() -> None:
    """Analyze logs from multiple configured targets — a fleet."""
    # Keeps `fleet` a command group (so `fleet scan` needs the subcommand name)
    # even while it has only one command.


def _build_engine(no_rules: bool, rules_dir: Optional[Path], plugin_registry) -> RuleEngine | None:
    if no_rules:
        return None
    all_rules = list(load_rules_dir(_BUILTIN_RULES_DIR))
    if rules_dir and rules_dir.is_dir():
        all_rules.extend(load_rules_dir(rules_dir))
    for pdir in plugin_registry.rule_dirs:
        all_rules.extend(load_rules_dir(pdir))
    all_rules.extend(plugin_registry.rules)
    return RuleEngine(all_rules)


@dataclass
class _FetchResult:
    """Raw events pulled from one target, plus any failure."""

    target: Target
    events: list[Event]
    error: str | None


def _fetch_target(target: Target) -> _FetchResult:
    """Drain one target's adapter. Runs in a worker thread; never raises."""
    events: list[Event] = []
    try:
        adapter = build_adapter(target)

        async def _drain() -> None:
            async for event in adapter.events():
                event.parsed_fields["target"] = target.name
                events.append(event)

        asyncio.run(_drain())
        return _FetchResult(target, events, None)
    except Exception as e:
        # failure isolation — one dead target must not abort the fleet scan
        return _FetchResult(target, events, str(e))


def _print_summary(
    summaries: list[tuple[str, str, int, int, str]],
    total_events: int,
    pii_hits: int,
    total_findings: int,
    redact: RedactModeArg,
) -> None:
    name_w = max([len("TARGET")] + [len(s[0]) for s in summaries])
    sep = "  " + "-" * 66
    typer.echo(sep)
    header = f"  {'TARGET'.ljust(name_w)}  {'STATUS'.ljust(8)}  {'EVENTS':>9}  {'FINDINGS':>9}"
    typer.echo(header)
    typer.echo(sep)

    ok = failed = 0
    for name, status, ev_count, f_count, detail in summaries:
        if status == "ok":
            ok += 1
            status_str = typer.style("ok".ljust(8), fg=typer.colors.GREEN)
        else:
            failed += 1
            status_str = typer.style("failed".ljust(8), fg=typer.colors.RED)
        typer.echo(f"  {name.ljust(name_w)}  {status_str}  {ev_count:>9,}  {f_count:>9,}")
        if detail:
            typer.echo(f"  {' ' * name_w}  └─ {detail[:60]}")

    typer.echo(sep)
    typer.echo(
        f"  {ok} ok · {failed} failed   ·   events {total_events:,}   ·   "
        f"PII {pii_hits:,} ({redact.value})   ·   findings {total_findings:,}"
    )
    typer.echo(sep)


def _print_events(events: list[Event], limit: int, show_all: bool) -> None:
    sample = events if show_all else events[:limit]
    if not sample:
        return
    typer.echo(f"\n  Events ({len(sample)} of {len(events):,}):\n")
    for i, ev in enumerate(sample, 1):
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "no timestamp"
        sev = ev.severity.value.upper().ljust(8)
        tgt = str(ev.parsed_fields.get("target", "?"))
        typer.echo(f"  [{i:>5}] {ts}  {sev}  {tgt}  {ev.message[:90]}")
    if not show_all and len(events) > limit:
        typer.echo(f"\n  ... {len(events) - limit:,} more. Use --show-all or --limit N.")


def _print_findings(findings: list[tuple[str, Finding]], no_rules: bool) -> None:
    if findings:
        typer.echo(f"\n  Findings ({len(findings)}):\n")
        for target_name, finding in findings:
            color = _SEVERITY_COLOR.get(finding.severity.value, typer.colors.WHITE)
            ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            line = (
                f"  [{finding.severity.value.upper()}] {ts}  {target_name}  "
                f"{finding.rule_id}  {finding.message}"
            )
            typer.echo(typer.style(line, fg=color))
    elif not no_rules:
        typer.echo("\n  No findings.")


@app.command("scan")
def fleet_scan(
    targets_file: Annotated[Path, typer.Option("--targets", help="Targets file to load.")] = Path(
        "targets.yaml"
    ),
    target: Annotated[
        Optional[list[str]],
        typer.Option("--target", help="Select a target by name (repeatable)."),
    ] = None,
    group: Annotated[
        Optional[list[str]],
        typer.Option("--group", help="Select targets by group (repeatable)."),
    ] = None,
    workers: Annotated[
        int, typer.Option("--workers", help="Max targets fetched concurrently.")
    ] = 16,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    limit: Annotated[int, typer.Option("--limit", help="Max events to display.")] = 50,
    show_all: Annotated[bool, typer.Option("--show-all", help="Display every event.")] = False,
    findings_only: Annotated[
        bool, typer.Option("--findings-only", help="Skip the events list.")
    ] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip the rule engine.")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite.")
    ] = False,
) -> None:
    """Scan every configured target once, concurrently — redact PII, run rules.

    Reads a targets file (default: targets.yaml). Targets are fetched in
    parallel; a target that fails is reported but does not abort the run.
    """
    try:
        selected = select_targets(load_targets(targets_file), target, group)
    except TargetConfigError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

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
    engine = _build_engine(no_rules, rules_dir, plugin_registry)

    typer.echo(f"\n  Fleet scan — {len(selected)} target(s), fetching concurrently...")

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(selected)))) as pool:
        results = list(pool.map(_fetch_target, selected))

    # Pipeline runs serially on the main thread — the rule engine and error
    # tracker keep mutable state and are not safe to share across threads.
    events: list[Event] = []
    findings: list[tuple[str, Finding]] = []
    summaries: list[tuple[str, str, int, int, str]] = []
    pii_hits = 0
    errors_tracked = 0

    e_repo: ErrorsRepository | None = None
    tracker: ErrorTracker | None = None
    if track_errors:
        e_repo = ErrorsRepository(cfg.db_path)
        e_repo.open()
        tracker = ErrorTracker(e_repo)

    try:
        for r in results:
            t_events = 0
            t_findings = 0
            for ev in r.events:
                result = redactor.redact(ev.message)
                ev.message = result.text
                ev.raw = redactor.redact(ev.raw).text
                pii_hits += len(result.hits)
                events.append(ev)
                t_events += 1
                if engine:
                    for finding in engine.process(ev):
                        findings.append((r.target.name, finding))
                        t_findings += 1
                if tracker and tracker.process(ev) is not None:
                    errors_tracked += 1
            status = "ok" if r.error is None else "failed"
            summaries.append((r.target.name, status, t_events, t_findings, r.error or ""))
    finally:
        if e_repo:
            e_repo.close()

    typer.echo("")
    _print_summary(summaries, len(events), pii_hits, len(findings), redact)

    if not findings_only:
        _print_events(events, limit, show_all)
    _print_findings(findings, no_rules)

    if track_errors:
        typer.echo(f"\n  Errors tracked: {errors_tracked:,} -> {cfg.db_path}")
