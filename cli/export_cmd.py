"""CLI command group: analyzer export."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(help="Export findings and errors to various formats.")


def _open_file(path: Path) -> None:
    """Open a file with the OS default application."""
    try:
        if sys.platform == "win32":
            import os
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except Exception:
        pass


@app.command("report")
def export_report(
    output: Path = typer.Option(Path("report.md"), "--output", "-o", help="Output file path."),
    since: str = typer.Option("168h", "--since", help="Look-back window (e.g. 24h, 7d, 30d)."),
    severity: Optional[str] = typer.Option(
        None, "--severity", help="Minimum severity filter (low/medium/high/critical)."
    ),
    title: str = typer.Option("LogSense Security Report", "--title", help="Report title."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path."),
    open_file: bool = typer.Option(False, "--open", help="Open report after writing."),
) -> None:
    """Generate a Markdown security report from findings and errors in the database.

    Examples::

        analyzer export report
        analyzer export report --since 24h --severity high --output daily.md
        analyzer export report --open
    """
    from log_analyzer.config import Config
    from log_analyzer.export.markdown import generate_report

    cfg = Config.load(config)

    # Parse --since (e.g. "24h", "7d", "168h")
    since_hours = _parse_hours(since)

    typer.echo(f"  Generating report (last {since_hours}h)...")
    content = generate_report(
        db_path=cfg.db_path,
        since_hours=since_hours,
        min_severity=severity,
        title=title,
    )

    output.write_text(content, encoding="utf-8")
    size_kb = output.stat().st_size / 1024
    typer.echo(typer.style(f"  Report written: {output}  ({size_kb:.1f} KB)", fg=typer.colors.GREEN))

    if open_file:
        _open_file(output)


def _parse_hours(s: str) -> int:
    _UNITS = {"s": 1 / 3600, "m": 1 / 60, "h": 1, "d": 24}
    s = s.strip().lower()
    if s[-1] in _UNITS:
        try:
            return max(1, int(float(s[:-1]) * _UNITS[s[-1]]))
        except ValueError:
            pass
    try:
        return int(s)
    except ValueError:
        typer.echo(f"Error: invalid time format '{s}'. Use e.g. 24h, 7d, 168h.", err=True)
        raise typer.Exit(1)
