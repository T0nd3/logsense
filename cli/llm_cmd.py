from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from log_analyzer.config import Config
from log_analyzer.llm.base import AbstractLLMClient
from log_analyzer.llm.factory import make_embed_client, make_llm_client
from log_analyzer.llm.prompts import (
    ask_prompt,
    explain_error_prompt,
    summarize_prompt,
)
from log_analyzer.llm.retrieval import build_chroma_index, retrieve_context
from log_analyzer.storage.errors_repo import ErrorsRepository

app = typer.Typer(
    help="LLM-powered log analysis. Supports Ollama, Claude, and OpenAI-compatible APIs."
)

_CLOUD_WARNING = "  [!] Cloud provider — log data (PII-redacted) will be sent to an external API."


def _make_client(cfg: Config) -> AbstractLLMClient:
    return make_llm_client(cfg.llm)


def _warn_if_cloud(client: AbstractLLMClient) -> None:
    if client.is_cloud:
        typer.echo(typer.style(_CLOUD_WARNING, fg=typer.colors.YELLOW), err=True)


def _stream(client: AbstractLLMClient, prompt: str) -> None:
    """Stream LLM output token-by-token to stdout."""
    try:
        for token in client.generate(prompt, stream=True):
            print(token, end="", flush=True)
        print()  # newline at end
    except Exception as e:
        typer.echo(f"\nError: {e}", err=True)
        raise typer.Exit(1)


def _chroma_path(cfg: Config) -> Path:
    return cfg.db_path.parent / "chroma_index"


# ---------------------------------------------------------------------------
# llm info
# ---------------------------------------------------------------------------


@app.command("info")
def llm_info(
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Show LLM provider status and available models."""
    cfg = Config.load(config)
    client = _make_client(cfg)

    sep = "-" * 55
    typer.echo(f"\n{sep}")
    typer.echo(f"  Provider : {cfg.llm.provider}")
    typer.echo(f"  Model    : {cfg.llm.model}")
    typer.echo(
        f"  Embed    : {cfg.llm.embed_model} (via {cfg.llm.embed_provider or cfg.llm.provider})"
    )

    if client.is_cloud:
        typer.echo(
            f"  Cloud    : {typer.style('YES — data leaves this machine (PII-redacted)', fg=typer.colors.YELLOW)}"
        )
    else:
        typer.echo(f"  Cloud    : {typer.style('No — fully local', fg=typer.colors.GREEN)}")

    if client.is_available():
        status = typer.style("ONLINE", fg=typer.colors.GREEN)
        models = client.list_models()
    else:
        status = typer.style("OFFLINE / unreachable", fg=typer.colors.RED)
        models = []

    typer.echo(f"  Status   : {status}")

    if models:
        label = "Available models" if client.is_cloud else "Locally available models"
        typer.echo(f"\n  {label} ({len(models)}):")
        for m in models:
            marker = "  *" if cfg.llm.model in m else "   "
            typer.echo(f"{marker} {m}")
    elif client.is_available() and cfg.llm.provider == "ollama":
        typer.echo("\n  No models pulled yet. Run: ollama pull gemma3:4b")

    typer.echo(sep)


# ---------------------------------------------------------------------------
# llm explain <fingerprint>
# ---------------------------------------------------------------------------


@app.command("explain")
def llm_explain(
    fingerprint: Annotated[
        str, typer.Argument(help="Error fingerprint from 'analyzer errors list'.")
    ],
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Ask the LLM to explain a tracked error in plain language."""
    cfg = Config.load(config)
    client = _make_client(cfg)

    _warn_if_cloud(client)
    if not client.is_available():
        typer.echo(
            f"LLM provider '{cfg.llm.provider}' is not reachable.\n"
            "Check your endpoint and API key (or run: ollama serve).",
            err=True,
        )
        raise typer.Exit(1)

    with ErrorsRepository(cfg.db_path) as repo:
        row = repo.get_error(fingerprint)
        if not row:
            typer.echo(f"Error '{fingerprint}' not found.", err=True)
            raise typer.Exit(1)
        occs = repo.get_occurrences(fingerprint, limit=4)

    occ_dicts = [dict(o) for o in occs]
    prompt = explain_error_prompt(dict(row), occ_dicts)

    typer.echo(f"\n  Explaining [{fingerprint}] {row['error_type']} ...\n")
    typer.echo(f"  Provider: {cfg.llm.provider}  Model: {cfg.llm.model}\n")
    typer.echo("-" * 55)
    _stream(client, prompt)
    typer.echo("-" * 55)


# ---------------------------------------------------------------------------
# llm summarize
# ---------------------------------------------------------------------------


@app.command("summarize")
def llm_summarize(
    since: Annotated[
        str, typer.Option("--since", "-s", help="Time window: '7d', '24h', '1h'.")
    ] = "24h",
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max errors to include.")] = 10,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Generate a natural-language summary of recent errors."""
    cfg = Config.load(config)
    client = _make_client(cfg)

    _warn_if_cloud(client)
    if not client.is_available():
        typer.echo(f"LLM provider '{cfg.llm.provider}' is not reachable.", err=True)
        raise typer.Exit(1)

    hours = _parse_hours(since)
    with ErrorsRepository(cfg.db_path) as repo:
        rows = repo.new_errors(since_hours=hours)
        if not rows:
            rows = repo.list_errors(sort="count", limit=limit)
        rows = rows[:limit]

    if not rows:
        typer.echo("No errors found. Run 'analyzer scan --track-errors' first.")
        return

    row_dicts = [dict(r) for r in rows]
    prompt = summarize_prompt(row_dicts, since)

    typer.echo(f"\n  Summarizing last {since} ({len(rows)} error types)...\n")
    typer.echo(f"  Provider: {cfg.llm.provider}  Model: {cfg.llm.model}\n")
    typer.echo("-" * 55)
    _stream(client, prompt)
    typer.echo("-" * 55)


# ---------------------------------------------------------------------------
# llm ask
# ---------------------------------------------------------------------------


@app.command("ask")
def llm_ask(
    question: Annotated[str, typer.Argument(help="Natural language question about your logs.")],
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    no_vector: Annotated[
        bool, typer.Option("--no-vector", help="Skip ChromaDB vector search.")
    ] = False,
) -> None:
    """Ask a question about your findings and errors (RAG over local SQLite)."""
    cfg = Config.load(config)
    client = _make_client(cfg)

    _warn_if_cloud(client)
    if not client.is_available():
        typer.echo(f"LLM provider '{cfg.llm.provider}' is not reachable.", err=True)
        raise typer.Exit(1)

    chroma_dir = None if no_vector else _chroma_path(cfg)
    if chroma_dir and not chroma_dir.exists():
        chroma_dir = None  # no index built yet; fall back to keyword search

    # Use the embed client for vector queries (may differ from text client)
    embed_client = make_embed_client(cfg.llm) if chroma_dir else None

    chunks = retrieve_context(
        question=question,
        db_path=cfg.db_path,
        chroma_path=chroma_dir,
        ollama_client=embed_client,
    )

    prompt = ask_prompt(question, chunks)

    method = "keyword + vector" if chroma_dir else "keyword"
    typer.echo(f"\n  Q: {question}")
    typer.echo(f"  Provider: {cfg.llm.provider}  Context: {len(chunks)} chunk(s) ({method})\n")
    typer.echo("-" * 55)
    _stream(client, prompt)
    typer.echo("-" * 55)


# ---------------------------------------------------------------------------
# llm index  (build ChromaDB vector index)
# ---------------------------------------------------------------------------


@app.command("index")
def llm_index(
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
) -> None:
    """Build (or rebuild) the ChromaDB embedding index for 'analyzer llm ask'.

    Requires: pip install chromadb
    Requires: Ollama running with the embed model available.
    """
    cfg = Config.load(config)
    client = _make_client(cfg)

    if not client.is_available():
        typer.echo(f"Ollama is not running at {cfg.llm.endpoint}.", err=True)
        raise typer.Exit(1)

    chroma_dir = _chroma_path(cfg)
    chroma_dir.mkdir(parents=True, exist_ok=True)

    typer.echo(f"\n  Building ChromaDB index at {chroma_dir} ...")
    typer.echo(f"  Embed model: {cfg.llm.embed_model}\n")

    try:
        n = build_chroma_index(cfg.db_path, chroma_dir, client)
        typer.echo(typer.style(f"  Indexed {n} error(s).", fg=typer.colors.GREEN))
    except RuntimeError as e:
        typer.echo(typer.style(f"  {e}", fg=typer.colors.RED), err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(typer.style(f"  LLM error: {e}", fg=typer.colors.RED), err=True)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UNIT_HOURS = {"s": 1 / 3600, "m": 1 / 60, "h": 1, "d": 24}


def _parse_hours(s: str) -> int:
    import re

    m = re.match(r"^(\d+)([smhd])$", s.strip())
    if not m:
        typer.echo(f"Invalid time spec '{s}'. Use e.g. 24h, 7d.", err=True)
        raise typer.Exit(1)
    return max(1, int(int(m.group(1)) * _UNIT_HOURS[m.group(2)]))
