"""CLI command group: logatory ssh — analyze logs from a remote host over SSH."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.ssh import SSHAdapter
from logatory.cli._types import REDACT_MAP, RedactModeArg
from logatory.cli.colors import SEVERITY_COLOR
from logatory.config import Config
from logatory.errors.tracker import ErrorTracker
from logatory.models import Event, Finding
from logatory.pii.patterns import PIIPattern
from logatory.pii.redactor import PIIRedactor
from logatory.plugins.loader import load_plugins
from logatory.rules.engine import RuleEngine
from logatory.rules.loader import load_rules_dir
from logatory.storage.dismiss_repo import DismissRepository
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository, meets_min_severity
from logatory.tail_helpers import meets_alert_severity, post_webhook

_BUILTIN_RULES_DIR = Path(__file__).parent.parent / "rules" / "builtin"

app = typer.Typer(help="Analyze logs from a remote host over SSH.")


def _print_finding(finding: Finding) -> None:
    color = SEVERITY_COLOR.get(finding.severity.value, typer.colors.WHITE)
    ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    line = f"  [{finding.severity.value.upper()}] {ts}  {finding.rule_id}  {finding.message}"
    typer.echo(typer.style(line, fg=color))


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


def _resolve_mode(path: Optional[str], unit: Optional[str], journald: bool) -> bool:
    """Return True for journald mode; reject an invalid path/journald combination."""
    use_journald = journald or unit is not None
    if use_journald and path:
        raise typer.BadParameter("--path cannot be combined with --journald/--unit.")
    if not use_journald and not path:
        raise typer.BadParameter(
            "specify a remote source: --path <file>, or --journald (optionally with --unit)."
        )
    return use_journald


@app.command("scan")
def ssh_scan(
    host: Annotated[
        str, typer.Argument(help="Remote host: 'user@host', 'host', or an ssh-config alias.")
    ],
    path: Annotated[Optional[str], typer.Option("--path", help="Remote log file to read.")] = None,
    unit: Annotated[
        Optional[str], typer.Option("--unit", "-u", help="Read journald, filtered to this unit.")
    ] = None,
    journald: Annotated[
        bool, typer.Option("--journald", "-j", help="Read the remote systemd journal.")
    ] = False,
    since: Annotated[
        Optional[str], typer.Option("--since", help="journald --since value, e.g. '-1h'.")
    ] = None,
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Max remote lines/entries to fetch.")
    ] = 1000,
    port: Annotated[Optional[int], typer.Option("--port", "-p", help="SSH port.")] = None,
    identity: Annotated[
        Optional[str], typer.Option("--identity", "-i", help="SSH private key file.")
    ] = None,
    ssh_opt: Annotated[
        Optional[list[str]],
        typer.Option("--ssh-opt", help="Extra 'ssh -o' option (repeatable)."),
    ] = None,
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
    """Read logs from a remote host over SSH, redact PII, run detection rules.

    Pulls logs straight over an existing SSH connection — no agent on the
    remote box. The source is a file (--path) or the systemd journal
    (--journald / --unit). Needs an `ssh` client locally.
    """
    use_journald = _resolve_mode(path, unit, journald)
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

    events: list[Event] = []
    findings: list[Finding] = []
    pii_hits = 0

    async def _run() -> None:
        nonlocal pii_hits
        adapter = SSHAdapter(
            host=host,
            path=path,
            unit=unit,
            use_journald=use_journald,
            since=since,
            lines=lines,
            port=port,
            identity=identity,
            ssh_opts=ssh_opt,
        )
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
    except Exception as e:
        typer.echo(f"Error reading remote logs: {e}", err=True)
        raise typer.Exit(1)

    src_desc = f"{host} ({'journald' if use_journald else path})"
    sep = "-" * 60
    typer.echo(
        f"\n{sep}\n"
        f"  Source     : {src_desc}\n"
        f"  Events     : {len(events):,}\n"
        f"  PII hits   : {pii_hits:,} (mode: {redact.value})\n"
        f"  Findings   : {len(findings):,}\n"
        f"{sep}"
    )

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
            _print_finding(finding)
    elif not no_rules:
        typer.echo("\n  No findings.")

    if track_errors and events:
        with ErrorsRepository(cfg.db_path) as e_repo:
            tracker = ErrorTracker(e_repo)
            tracked = sum(1 for ev in events if tracker.process(ev) is not None)
        typer.echo(f"\n  Errors tracked: {tracked:,} -> {cfg.db_path}")


@app.command("tail")
def ssh_tail(
    host: Annotated[
        str, typer.Argument(help="Remote host: 'user@host', 'host', or an ssh-config alias.")
    ],
    path: Annotated[
        Optional[str], typer.Option("--path", help="Remote log file to follow.")
    ] = None,
    unit: Annotated[
        Optional[str], typer.Option("--unit", "-u", help="Follow journald, filtered to this unit.")
    ] = None,
    journald: Annotated[
        bool, typer.Option("--journald", "-j", help="Follow the remote systemd journal.")
    ] = False,
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Entries to backfill before following.")
    ] = 20,
    reconnect_delay: Annotated[
        float, typer.Option("--reconnect-delay", help="Seconds to wait before reconnecting.")
    ] = 3.0,
    port: Annotated[Optional[int], typer.Option("--port", "-p", help="SSH port.")] = None,
    identity: Annotated[
        Optional[str], typer.Option("--identity", "-i", help="SSH private key file.")
    ] = None,
    ssh_opt: Annotated[
        Optional[list[str]],
        typer.Option("--ssh-opt", help="Extra 'ssh -o' option (repeatable)."),
    ] = None,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip the rule engine.")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite.")
    ] = False,
    track_findings: Annotated[
        bool, typer.Option("--track-findings", help="Persist HIGH/CRITICAL findings to SQLite.")
    ] = False,
    alert_webhook: Annotated[
        Optional[str], typer.Option("--alert-webhook", help="POST findings as JSON to this URL.")
    ] = None,
    alert_min_severity: Annotated[
        str, typer.Option("--alert-min-severity", help="Minimum severity to fire the webhook.")
    ] = "high",
) -> None:
    """Follow logs from a remote host in real time — redact PII, run rules, alert.

    Streams over a long-lived SSH connection (`journalctl -f` / `tail -F`).
    A dropped connection reconnects automatically; journald mode resumes
    gap-free via the journal cursor. Runs until Ctrl+C. Needs an `ssh` client.
    """
    use_journald = _resolve_mode(path, unit, journald)
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

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Following : {host} — {'journald' if use_journald else path}")
    typer.echo(f"  Reconnect : every {reconnect_delay}s on drop")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        e_repo: ErrorsRepository | None = None
        tracker: ErrorTracker | None = None
        f_repo: FindingsRepository | None = None
        d_repo: DismissRepository | None = None

        if track_errors:
            e_repo = ErrorsRepository(cfg.db_path)
            e_repo.open()
            tracker = ErrorTracker(e_repo)
        if track_findings:
            f_repo = FindingsRepository(cfg.db_path)
            f_repo.open()
        if engine:
            d_repo = DismissRepository(cfg.db_path)
            d_repo.open()

        adapter = SSHAdapter(
            host=host,
            path=path,
            unit=unit,
            use_journald=use_journald,
            lines=lines,
            port=port,
            identity=identity,
            ssh_opts=ssh_opt,
        )
        try:
            async for event in adapter.poll(reconnect_delay):
                result = redactor.redact(event.message)
                event.message = result.text
                event.raw = redactor.redact(event.raw).text
                counts["pii"] += len(result.hits)
                counts["events"] += 1

                if engine:
                    for finding in engine.process(event):
                        if d_repo and d_repo.is_dismissed(finding.rule_id, finding.source):
                            continue
                        _print_finding(finding)
                        counts["findings"] += 1
                        if alert_webhook and meets_alert_severity(finding, alert_min_severity):
                            post_webhook(alert_webhook, finding)
                            counts["webhooks"] += 1
                        if f_repo and meets_min_severity(finding, cfg.findings_min_severity):
                            f_repo.add_findings([finding])

                if tracker and tracker.process(event) is not None:
                    counts["errors"] += 1
        finally:
            if e_repo:
                e_repo.close()
            if f_repo:
                f_repo.close()
            if d_repo:
                d_repo.close()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        typer.echo(f"\nError reading remote logs: {e}", err=True)
        raise typer.Exit(1)

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
