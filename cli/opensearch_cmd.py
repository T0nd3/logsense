from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from log_analyzer.adapters.opensearch import OpenSearchAdapter
from log_analyzer.adapters.opensearch_config import (
    FieldMapping,
    OpenSearchAuth,
    OpenSearchQuery,
    TimeRange,
)
from log_analyzer.config import Config
from log_analyzer.models import Event, Finding
from log_analyzer.pii.redactor import PIIRedactor, RedactMode
from log_analyzer.rules.engine import RuleEngine
from log_analyzer.rules.loader import load_rules_dir

_BUILTIN_RULES_DIR = Path(__file__).parent.parent / "log_analyzer" / "rules" / "builtin"

app = typer.Typer(help="Query logs from an OpenSearch / Elasticsearch cluster.")

_SEVERITY_COLOR = {
    "low": typer.colors.CYAN,
    "medium": typer.colors.YELLOW,
    "high": typer.colors.RED,
    "critical": typer.colors.BRIGHT_RED,
}


@app.command("scan")
def opensearch_scan(
    # Connection
    host: Annotated[str, typer.Option("--host", "-H", help="OpenSearch host.")] = "localhost",
    port: Annotated[int, typer.Option("--port", "-p")] = 9200,
    use_ssl: Annotated[bool, typer.Option("--ssl/--no-ssl")] = False,
    no_verify: Annotated[bool, typer.Option("--no-verify-certs", help="Skip TLS cert verification.")] = False,
    # Auth (all optional; env vars preferred over CLI flags)
    username: Annotated[Optional[str], typer.Option("--user", "-u", envvar="OPENSEARCH_USERNAME")] = None,
    password: Annotated[Optional[str], typer.Option("--password", envvar="OPENSEARCH_PASSWORD")] = None,
    api_key: Annotated[Optional[str], typer.Option("--api-key", envvar="OPENSEARCH_API_KEY")] = None,
    # Query
    index: Annotated[str, typer.Option("--index", "-i", help="Index pattern.")] = "logstash-*",
    since: Annotated[Optional[str], typer.Option("--since", help="Start time: '24h', '7d', or ISO datetime.")] = None,
    until: Annotated[Optional[str], typer.Option("--until", help="End time: 'now' or ISO datetime.")] = None,
    filter_: Annotated[Optional[list[str]], typer.Option("--filter", "-f", help="field=value filter. Repeatable.")] = None,
    max_events: Annotated[Optional[int], typer.Option("--max", help="Max events to fetch.")] = None,
    page_size: Annotated[int, typer.Option("--page-size")] = 1000,
    # Field mapping overrides
    ts_field: Annotated[str, typer.Option("--ts-field")] = "@timestamp",
    msg_field: Annotated[str, typer.Option("--msg-field")] = "message",
    sev_field: Annotated[Optional[str], typer.Option("--sev-field")] = "level",
    src_field: Annotated[Optional[str], typer.Option("--src-field")] = "host.name",
    # Output
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
    show_all: Annotated[bool, typer.Option("--all")] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
) -> None:
    """Fetch events from OpenSearch, redact PII, and run detection rules."""
    cfg = Config.load(config)

    # Merge CLI host/port with config-file defaults (CLI wins)
    os_cfg = cfg.opensearch
    effective_host = host if host != "localhost" else os_cfg.host
    effective_port = port if port != 9200 else os_cfg.port

    auth = OpenSearchAuth(
        username=username or os_cfg.username,
        password=password or os_cfg.password,
        api_key=api_key or os_cfg.api_key,
    )
    has_auth = any([auth.username, auth.api_key])

    # Parse --filter key=value pairs
    filters: list[dict[str, str]] = []
    for f in (filter_ or []):
        if "=" not in f:
            typer.echo(f"Warning: ignoring malformed filter '{f}' (expected field=value)", err=True)
            continue
        k, _, v = f.partition("=")
        filters.append({"field": k.strip(), "value": v.strip()})

    query = OpenSearchQuery(
        index=index,
        time_range=TimeRange(since=since, until=until),
        filters=filters,
        field_mapping=FieldMapping(
            timestamp=ts_field,
            message=msg_field,
            severity=sev_field or None,
            source_name=src_field or None,
        ),
        page_size=page_size,
        max_events=max_events,
    )

    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt,
        rules_path=cfg.pii_rules_path,
        mode=RedactMode.REDACT,
    )

    engine: RuleEngine | None = None
    if not no_rules:
        all_rules = list(load_rules_dir(_BUILTIN_RULES_DIR))
        if rules_dir and rules_dir.is_dir():
            all_rules.extend(load_rules_dir(rules_dir))
        engine = RuleEngine(all_rules)

    async def _run() -> None:
        adapter = OpenSearchAdapter(
            host=effective_host,
            port=effective_port,
            query=query,
            auth=auth if has_auth else None,
            use_ssl=use_ssl,
            verify_certs=not no_verify,
        )

        events: list[Event] = []
        findings: list[Finding] = []
        pii_hits_total = 0

        try:
            async for event in adapter.events():
                result = redactor.redact(event.message)
                event.message = result.text
                event.raw = redactor.redact(event.raw).text
                pii_hits_total += len(result.hits)
                events.append(event)
                if engine:
                    findings.extend(engine.process(event))
        except Exception as e:
            typer.echo(f"Error connecting to OpenSearch: {e}", err=True)
            raise typer.Exit(1)

        sep = "-" * 60
        typer.echo(
            f"\n{sep}\n"
            f"  Source   : {effective_host}:{effective_port}/{index}\n"
            f"  Events   : {len(events):,}\n"
            f"  PII hits : {pii_hits_total:,}\n"
            f"  Findings : {len(findings):,}\n"
            f"{sep}"
        )

        sample = events if show_all else events[:limit]
        if sample:
            typer.echo(f"\n  Events ({len(sample)} of {len(events):,}):\n")
            for i, ev in enumerate(sample, 1):
                ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "no timestamp"
                sev = ev.severity.value.upper().ljust(8)
                typer.echo(f"  [{i:>5}] {ts}  {sev}  {ev.message[:120]}")
            if not show_all and len(events) > limit:
                typer.echo(f"\n  ... {len(events) - limit:,} more. Use --all or --limit N.")

        if findings:
            typer.echo(f"\n  Findings ({len(findings)}):\n")
            for finding in findings:
                color = _SEVERITY_COLOR.get(finding.severity.value, typer.colors.WHITE)
                ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                line = f"  [{finding.severity.value.upper()}] {ts}  {finding.rule_id}  {finding.message}"
                typer.echo(typer.style(line, fg=color))
        elif not no_rules:
            typer.echo("\n  No findings.")

    asyncio.run(_run())


@app.command("info")
def opensearch_info(
    host: Annotated[str, typer.Option("--host", "-H")] = "localhost",
    port: Annotated[int, typer.Option("--port", "-p")] = 9200,
    use_ssl: Annotated[bool, typer.Option("--ssl/--no-ssl")] = False,
    no_verify: Annotated[bool, typer.Option("--no-verify-certs")] = False,
    username: Annotated[Optional[str], typer.Option("--user", envvar="OPENSEARCH_USERNAME")] = None,
    password: Annotated[Optional[str], typer.Option("--password", envvar="OPENSEARCH_PASSWORD")] = None,
    api_key: Annotated[Optional[str], typer.Option("--api-key", envvar="OPENSEARCH_API_KEY")] = None,
) -> None:
    """Check cluster connectivity and print basic cluster info."""
    try:
        from log_analyzer.adapters.opensearch import _make_client
        from log_analyzer.adapters.opensearch_config import OpenSearchAuth
    except ImportError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)

    auth = OpenSearchAuth(username=username, password=password, api_key=api_key)
    has_auth = any([auth.username, auth.api_key])

    try:
        client = _make_client(host, port, use_ssl, not no_verify, auth if has_auth else None)
        info = client.info()
        name = info.get("cluster_name", "?")
        version = info.get("version", {}).get("number", "?")
        typer.echo(typer.style(f"Connected  cluster={name}  version={version}", fg=typer.colors.GREEN))
    except Exception as e:
        typer.echo(typer.style(f"Connection failed: {e}", fg=typer.colors.RED), err=True)
        raise typer.Exit(1)
