from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from log_analyzer.anomaly.baseline import compute_stats
from log_analyzer.anomaly.features import FeatureExtractor
from log_analyzer.config import Config
from log_analyzer.pii.redactor import PIIRedactor, RedactMode
from log_analyzer.storage.baseline_repo import BaselineRepository

app = typer.Typer(help="Manage the statistical anomaly detection baseline.")

_MIN_TRAINED = 5


def _open_repo(config_path: Path | None) -> BaselineRepository:
    cfg = Config.load(config_path)
    repo = BaselineRepository(cfg.db_path)
    repo.open()
    return repo


# ---------------------------------------------------------------------------
# anomaly learn
# ---------------------------------------------------------------------------


@app.command("learn")
def anomaly_learn(
    path: Annotated[Path, typer.Argument(help="Log file to feed into the baseline.")],
    source_key: Annotated[
        Optional[str], typer.Option("--source", "-s", help="Source key (default: file stem).")
    ] = None,
    bucket_seconds: Annotated[
        int, typer.Option("--bucket", "-b", help="Time-bucket width in seconds.")
    ] = 60,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Feed a log file into the baseline (observe mode).

    Run this several times on representative logs before enabling
    --detect-anomalies in 'analyzer scan'.  At least 5 buckets are needed
    before the baseline is considered trained.
    """
    if not path.exists():
        typer.echo(f"Error: file not found: {path}", err=True)
        raise typer.Exit(1)

    key = source_key or path.stem
    cfg = Config.load(config)
    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt, rules_path=cfg.pii_rules_path, mode=RedactMode.REDACT
    )

    # --- Parse log file -------------------------------------------------------
    async def _collect():
        from log_analyzer.adapters.file import FileAdapter

        adapter = FileAdapter(path)
        evts = []
        async for ev in adapter.events():
            ev.message = redactor.redact(ev.message).text
            evts.append(ev)
        return evts

    typer.echo(f"  Parsing {path.name} ...", err=True)
    events = asyncio.run(_collect())
    if not events:
        typer.echo("  No events found – nothing added to baseline.")
        return

    # --- Feature extraction ---------------------------------------------------
    extractor = FeatureExtractor(bucket_seconds=bucket_seconds)
    buckets = extractor.extract(events)
    if not buckets:
        typer.echo("  No timestamped events – cannot extract buckets.")
        return

    feature_dicts = [b.to_feature_dict() for b in buckets]
    bucket_timestamps = [b.ts for b in buckets]

    # --- Persist and recompute stats -----------------------------------------
    with BaselineRepository(cfg.db_path) as repo:
        inserted = repo.add_observations(key, feature_dicts, bucket_timestamps)
        all_fds = repo.get_all_feature_dicts(key)
        stats = compute_stats(all_fds, key)
        repo.update_stats(stats)
        n_total = stats.n_buckets

    # --- Report ---------------------------------------------------------------
    trained = n_total >= _MIN_TRAINED
    status_text = (
        typer.style("TRAINED", fg=typer.colors.GREEN)
        if trained
        else typer.style(f"OBSERVE ({n_total}/{_MIN_TRAINED} buckets)", fg=typer.colors.YELLOW)
    )
    sep = "-" * 55
    typer.echo(
        f"\n{sep}\n"
        f"  Source key   : {key}\n"
        f"  Events       : {len(events):,}\n"
        f"  New buckets  : {inserted}\n"
        f"  Total buckets: {n_total}\n"
        f"  Status       : {status_text}\n"
        f"{sep}"
    )


# ---------------------------------------------------------------------------
# anomaly status
# ---------------------------------------------------------------------------


@app.command("status")
def anomaly_status(
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Show baseline status for all known source keys."""
    with _open_repo(config) as repo:
        sources = repo.list_sources()

    if not sources:
        typer.echo("No baseline data. Run 'analyzer anomaly learn <log>' first.")
        return

    typer.echo(f"\n  {'SOURCE KEY':<30} {'BUCKETS':>8}  STATUS")
    typer.echo(f"  {'-' * 30} {'-' * 8}  {'-' * 20}")
    for s in sources:
        n = s.get("n_buckets", 0)
        if n >= _MIN_TRAINED:
            status = typer.style("TRAINED", fg=typer.colors.GREEN)
        else:
            status = typer.style(f"OBSERVE ({n}/{_MIN_TRAINED})", fg=typer.colors.YELLOW)
        typer.echo(f"  {s['source_key']:<30} {n:>8}  {status}")
    typer.echo()


# ---------------------------------------------------------------------------
# anomaly reset
# ---------------------------------------------------------------------------


@app.command("reset")
def anomaly_reset(
    source_key: Annotated[
        Optional[str],
        typer.Option("--source", "-s", help="Source key to reset (omit to reset all)."),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Delete baseline data for one source key, or for all sources."""
    with _open_repo(config) as repo:
        sources = repo.list_sources()

        if source_key:
            targets = [s for s in sources if s["source_key"] == source_key]
            if not targets:
                typer.echo(f"Source key '{source_key}' not found.", err=True)
                raise typer.Exit(1)
        else:
            targets = sources

        if not targets:
            typer.echo("Nothing to reset.")
            return

        if not yes:
            names = ", ".join(t["source_key"] for t in targets[:5])
            if len(targets) > 5:
                names += f" (+{len(targets) - 5} more)"
            confirmed = typer.confirm(f"Reset baseline for: {names}?")
            if not confirmed:
                raise typer.Exit(0)

        for t in targets:
            repo.delete_source(t["source_key"])
        typer.echo(f"  Cleared {len(targets)} baseline source(s).")
