from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from log_analyzer.config import Config
from log_analyzer.storage.errors_repo import ErrorsRepository

app = typer.Typer(help="Browse and query tracked errors.")

_SEV_COLOR = {
    "debug": typer.colors.WHITE,
    "info": typer.colors.WHITE,
    "warning": typer.colors.YELLOW,
    "error": typer.colors.RED,
    "critical": typer.colors.BRIGHT_RED,
}


def _open_repo(config_path: Path | None) -> ErrorsRepository:
    cfg = Config.load(config_path)
    repo = ErrorsRepository(cfg.db_path)
    repo.open()
    return repo


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "?"
    return ts[:19].replace("T", " ")


# ---------------------------------------------------------------------------
# errors list
# ---------------------------------------------------------------------------


@app.command("list")
def errors_list(
    sort: Annotated[
        str, typer.Option("--sort", "-s", help="Sort by: count, last_seen, first_seen.")
    ] = "count",
    severity: Annotated[Optional[str], typer.Option("--severity")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 30,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """List all tracked error types sorted by frequency or recency."""
    with _open_repo(config) as repo:
        rows = repo.list_errors(sort=sort, severity=severity, limit=limit)
        summary = repo.summary()

    if not rows:
        typer.echo("No errors tracked yet. Run 'analyzer scan' first.")
        return

    typer.echo(
        f"\n  {summary['total_error_types']} error types  "
        f"({summary['total_occurrences']:,} total occurrences)\n"
    )
    typer.echo(f"  {'FINGERPRINT':<14} {'SEV':<10} {'COUNT':>6}  {'LAST SEEN':<20} TYPE")
    typer.echo(f"  {'-' * 14} {'-' * 10} {'-' * 6}  {'-' * 20} {'-' * 30}")

    for row in rows:
        color = _SEV_COLOR.get(row["severity"], typer.colors.WHITE)
        sev = typer.style(row["severity"].upper().ljust(10), fg=color)
        typer.echo(
            f"  {row['fingerprint']:<14} {sev} {row['count']:>6}  "
            f"{_fmt_ts(row['last_seen']):<20} {row['error_type']}"
        )


# ---------------------------------------------------------------------------
# errors show
# ---------------------------------------------------------------------------


@app.command("show")
def errors_show(
    fingerprint: Annotated[str, typer.Argument(help="Fingerprint from 'errors list'.")],
    occurrences: Annotated[int, typer.Option("--occurrences", "-n")] = 10,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Show details and recent occurrences for a specific error fingerprint."""
    with _open_repo(config) as repo:
        row = repo.get_error(fingerprint)
        if not row:
            typer.echo(f"Error '{fingerprint}' not found.", err=True)
            raise typer.Exit(1)
        occs = repo.get_occurrences(fingerprint, limit=occurrences)

    sources = json.loads(row["sources"])
    color = _SEV_COLOR.get(row["severity"], typer.colors.WHITE)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Fingerprint : {row['fingerprint']}")
    typer.echo(f"  Type        : {row['error_type']}")
    typer.echo(f"  Severity    : {typer.style(row['severity'].upper(), fg=color)}")
    typer.echo(f"  Count       : {row['count']:,}")
    typer.echo(f"  First seen  : {_fmt_ts(row['first_seen'])}")
    typer.echo(f"  Last seen   : {_fmt_ts(row['last_seen'])}")
    typer.echo(f"  Sources     : {', '.join(sources)}")
    typer.echo(f"\n  Normalized:\n    {row['normalized_msg']}")
    typer.echo(f"{sep}")

    if occs:
        typer.echo(f"\n  Last {len(occs)} occurrence(s):\n")
        for occ in occs:
            lang = f" [{occ['stack_lang']}]" if occ["stack_lang"] else ""
            typer.echo(f"  {_fmt_ts(occ['timestamp'])}  {occ['source']}{lang}")
            typer.echo(f"    {occ['sample'][:100]}")
    else:
        typer.echo("\n  No occurrences recorded.")


# ---------------------------------------------------------------------------
# errors new
# ---------------------------------------------------------------------------


@app.command("new")
def errors_new(
    since: Annotated[str, typer.Option("--since", help="Time window: '7d', '24h', '1h'.")] = "7d",
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Show errors first seen within the given time window."""
    hours = _parse_hours(since)
    with _open_repo(config) as repo:
        rows = repo.new_errors(since_hours=hours)

    if not rows:
        typer.echo(f"No new errors in the last {since}.")
        return

    typer.echo(f"\n  {len(rows)} new error type(s) in the last {since}:\n")
    for row in rows:
        color = _SEV_COLOR.get(row["severity"], typer.colors.WHITE)
        sev = typer.style(row["severity"].upper().ljust(9), fg=color)
        typer.echo(
            f"  {row['fingerprint']}  {sev}  {row['error_type']}  (first: {_fmt_ts(row['first_seen'])})"
        )


# ---------------------------------------------------------------------------
# errors regression
# ---------------------------------------------------------------------------


@app.command("regression")
def errors_regression(
    gap: Annotated[
        str, typer.Option("--gap", help="Minimum silence gap to qualify as regression.")
    ] = "24h",
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Show errors that reappeared after a silence period (regressions)."""
    hours = _parse_hours(gap)
    with _open_repo(config) as repo:
        rows = repo.regression_errors(gap_hours=hours)

    if not rows:
        typer.echo(f"No regressions detected (gap >= {gap}).")
        return

    typer.echo(f"\n  {len(rows)} potential regression(s) (gap >= {gap}):\n")
    for row in rows:
        color = _SEV_COLOR.get(row["severity"], typer.colors.WHITE)
        sev = typer.style(row["severity"].upper().ljust(9), fg=color)
        typer.echo(
            f"  {row['fingerprint']}  {sev}  {row['error_type']}\n"
            f"    first: {_fmt_ts(row['first_seen'])}   last: {_fmt_ts(row['last_seen'])}   count: {row['count']}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UNIT_HOURS = {"s": 1 / 3600, "m": 1 / 60, "h": 1, "d": 24}


def _parse_hours(s: str) -> int:
    import re

    m = re.match(r"^(\d+)([smhd])$", s.strip())
    if not m:
        typer.echo(f"Invalid time spec '{s}'. Use e.g. 24h, 7d, 30m.", err=True)
        raise typer.Exit(1)
    return max(1, int(int(m.group(1)) * _UNIT_HOURS[m.group(2)]))
