from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Optional

import typer

from cli.colors import SEVERITY_COLOR as _SEV_COLOR
from logsense.config import Config
from logsense.storage.dismiss_repo import DismissRepository
from logsense.storage.findings_repo import FindingsRepository

app = typer.Typer(help="Browse persisted HIGH/CRITICAL findings.")

_UNIT_HOURS = {"s": 1 / 3600, "m": 1 / 60, "h": 1, "d": 24}


def _parse_hours(s: str) -> int:
    m = re.match(r"^(\d+)([smhd])$", s.strip())
    if not m:
        typer.echo(f"Invalid time spec '{s}'. Use e.g. 24h, 7d, 30m.", err=True)
        raise typer.Exit(1)
    return max(1, int(int(m.group(1)) * _UNIT_HOURS[m.group(2)]))


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "?"
    return ts[:19].replace("T", " ")


def _open_repo(config_path: Path | None) -> FindingsRepository:
    cfg = Config.load(config_path)
    repo = FindingsRepository(cfg.db_path)
    repo.open()
    return repo


def _open_dismiss_repo(config_path: Path | None) -> DismissRepository:
    cfg = Config.load(config_path)
    repo = DismissRepository(cfg.db_path)
    repo.open()
    return repo


# ---------------------------------------------------------------------------
# findings list
# ---------------------------------------------------------------------------


@app.command("list")
def findings_list(
    severity: Annotated[
        Optional[str], typer.Option("--severity", "-s", help="Filter: low|medium|high|critical.")
    ] = None,
    source: Annotated[
        Optional[str], typer.Option("--source", help="Filter by source file/key.")
    ] = None,
    since: Annotated[
        Optional[str],
        typer.Option("--since", help="Only findings from last N hours/days, e.g. 24h, 7d."),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """List persisted findings, newest first."""
    with _open_repo(config) as repo:
        if since:
            hours = _parse_hours(since)
            rows = repo.recent_findings(since_hours=hours, severity=severity)
            rows = rows[:limit]
        else:
            rows = repo.list_findings(severity=severity, source=source, limit=limit)
        summary = repo.summary()

    if not rows:
        typer.echo("No findings stored yet. Run 'logsense scan --track-errors' first.")
        return

    total = summary["total"]
    typer.echo(f"\n  {total} finding(s) total — showing {len(rows)}\n")
    typer.echo(f"  {'SEV':<10} {'RULE':<28} {'SOURCE':<20} {'WHEN':<20} MESSAGE")
    typer.echo(f"  {'-' * 10} {'-' * 28} {'-' * 20} {'-' * 20} {'-' * 35}")

    for row in rows:
        color = _SEV_COLOR.get(row["severity"], typer.colors.WHITE)
        sev = typer.style(row["severity"].upper().ljust(10), fg=color)
        rule = row["rule_id"][:28]
        src = (row["source"] or "")[:20]
        ts = _fmt_ts(row["event_timestamp"])
        msg = (row["message"] or "")[:50]
        typer.echo(f"  {sev} {rule:<28} {src:<20} {ts:<20} {msg}")


# ---------------------------------------------------------------------------
# findings show
# ---------------------------------------------------------------------------


@app.command("show")
def findings_show(
    rule_id: Annotated[str, typer.Argument(help="Rule ID from 'findings list'.")],
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max occurrences to show.")] = 20,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Show all stored occurrences for a specific rule ID."""
    with _open_repo(config) as repo:
        rows = repo.get_by_rule(rule_id, limit=limit)

    if not rows:
        typer.echo(f"No findings stored for rule '{rule_id}'.", err=True)
        raise typer.Exit(1)

    first = rows[-1]  # oldest (list is newest-first)
    last = rows[0]
    color = _SEV_COLOR.get(last["severity"], typer.colors.WHITE)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Rule       : {rule_id}")
    typer.echo(f"  Severity   : {typer.style(last['severity'].upper(), fg=color)}")
    typer.echo(f"  Occurrences: {len(rows)} (showing up to {limit})")
    typer.echo(f"  First seen : {_fmt_ts(first['event_timestamp'])}")
    typer.echo(f"  Last seen  : {_fmt_ts(last['event_timestamp'])}")
    typer.echo(f"\n  Message (latest):\n    {last['message']}")
    typer.echo(sep)

    typer.echo(f"\n  Occurrences ({len(rows)}):\n")
    for row in rows:
        src = row["source"] or ""
        ts = _fmt_ts(row["event_timestamp"])
        raw = (row["raw_event"] or "")[:80]
        typer.echo(f"  {ts}  {src}")
        if raw:
            typer.echo(f"    {raw}")


# ---------------------------------------------------------------------------
# findings summary
# ---------------------------------------------------------------------------


@app.command("summary")
def findings_summary(
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Show finding counts broken down by severity and top rules."""
    with _open_repo(config) as repo:
        s = repo.summary()
        top_rules = repo.count_by_rule(limit=10)

    if s["total"] == 0:
        typer.echo("No findings stored yet. Run 'logsense scan --track-errors' first.")
        return

    sep = "-" * 50
    typer.echo(f"\n{sep}")
    typer.echo(f"  Total findings : {s['total']}")
    typer.echo("\n  By severity:")
    for sev in ("critical", "high", "medium", "low"):
        count = s["by_severity"].get(sev, 0)
        if count:
            color = _SEV_COLOR.get(sev, typer.colors.WHITE)
            label = typer.style(sev.upper().ljust(10), fg=color)
            typer.echo(f"    {label} {count:>5}")

    if top_rules:
        typer.echo("\n  Top rules by occurrence:")
        typer.echo(f"  {'RULE':<30} {'SEV':<10} COUNT")
        typer.echo(f"  {'-' * 30} {'-' * 10} {'-' * 5}")
        for row in top_rules:
            color = _SEV_COLOR.get(row["severity"], typer.colors.WHITE)
            sev = typer.style(row["severity"].upper().ljust(10), fg=color)
            typer.echo(f"  {row['rule_id']:<30} {sev} {row['count']:>5}")

    typer.echo(sep)


# ---------------------------------------------------------------------------
# findings dismiss / undismiss / dismissed
# ---------------------------------------------------------------------------


@app.command("dismiss")
def findings_dismiss(
    rule_id: Annotated[str, typer.Argument(help="Rule ID to suppress (e.g. SSH_BRUTE_FORCE).")],
    source: Annotated[
        Optional[str],
        typer.Option(
            "--source", help="Limit to this source file only. Omit to suppress globally."
        ),
    ] = None,
    reason: Annotated[
        Optional[str], typer.Option("--reason", "-r", help="Optional reason for the dismissal.")
    ] = None,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Suppress a rule — future findings from this rule will be filtered out.

    Use --source to limit suppression to one log file; omit it to suppress
    the rule across all sources (global false-positive).

    Examples::

        logsense findings dismiss SSH_BRUTE_FORCE
        logsense findings dismiss NGINX_404_SCAN --source nginx.log --reason "internal scanner"
    """
    with _open_dismiss_repo(config) as repo:
        added = repo.dismiss(rule_id, source=source, reason=reason)

    scope = f"source '{source}'" if source else "all sources"
    if added:
        typer.echo(typer.style(f"  Dismissed: {rule_id} ({scope})", fg=typer.colors.YELLOW))
    else:
        typer.echo(f"  Already dismissed: {rule_id} ({scope})")


@app.command("undismiss")
def findings_undismiss(
    rule_id: Annotated[str, typer.Argument(help="Rule ID to re-enable.")],
    source: Annotated[
        Optional[str],
        typer.Option("--source", help="Remove only the source-specific suppression."),
    ] = None,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Re-enable a previously dismissed rule."""
    with _open_dismiss_repo(config) as repo:
        removed = repo.undismiss(rule_id, source=source)

    scope = f"source '{source}'" if source else "all sources"
    if removed:
        typer.echo(typer.style(f"  Re-enabled: {rule_id} ({scope})", fg=typer.colors.GREEN))
    else:
        typer.echo(f"  Not found: {rule_id} ({scope}) — nothing to remove.")


@app.command("dismissed")
def findings_dismissed(
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """List all currently dismissed rules."""
    with _open_dismiss_repo(config) as repo:
        rows = repo.list_dismissed()

    if not rows:
        typer.echo("No rules are currently dismissed.")
        return

    sep = "-" * 65
    typer.echo(f"\n  {len(rows)} dismissed rule(s)\n")
    typer.echo(f"  {'RULE ID':<30} {'SCOPE':<22} REASON")
    typer.echo(f"  {sep}")
    for r in rows:
        scope = r["source"] if r["source"] else "(all sources)"
        reason = r["reason"] or ""
        typer.echo(f"  {r['rule_id']:<30} {scope:<22} {reason}")
    typer.echo("")
