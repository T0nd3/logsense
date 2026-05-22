"""JSON and HTMX partial routes used by the dashboard."""

from __future__ import annotations

import gzip
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from logsense.config import Config
from logsense.storage.errors_repo import ErrorsRepository
from logsense.storage.findings_repo import FindingsRepository

from ..deps import errors_repo, findings_repo, get_config, get_templates

router = APIRouter()


# ---------------------------------------------------------------------------
# HTMX partials
# ---------------------------------------------------------------------------


@router.get("/findings", response_class=HTMLResponse)
def api_findings(
    request: Request,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    since_hours: Optional[int] = None,
    limit: int = 200,
    templates: Jinja2Templates = Depends(get_templates),
    f_repo: FindingsRepository = Depends(findings_repo),
) -> HTMLResponse:
    sev = severity or None
    src = source.strip() or None if source else None

    if since_hours:
        rows_raw = f_repo.recent_findings(since_hours=since_hours, severity=sev)
        if src:
            rows_raw = [r for r in rows_raw if dict(r)["source"] == src]
        rows = [dict(r) for r in rows_raw]
    else:
        rows = [dict(r) for r in f_repo.list_findings(severity=sev, source=src, limit=limit)]

    return templates.TemplateResponse(request, "partials/findings_rows.html", {"rows": rows})


@router.get("/errors", response_class=HTMLResponse)
def api_errors(
    request: Request,
    severity: Optional[str] = None,
    sort: str = "last_seen",
    templates: Jinja2Templates = Depends(get_templates),
    e_repo: ErrorsRepository = Depends(errors_repo),
) -> HTMLResponse:
    rows = [dict(r) for r in e_repo.list_errors(sort=sort, severity=severity or None, limit=200)]
    return templates.TemplateResponse(request, "partials/errors_rows.html", {"rows": rows})


@router.get("/top-rules", response_class=HTMLResponse)
def api_top_rules(
    request: Request,
    sort: str = "count",
    templates: Jinja2Templates = Depends(get_templates),
    f_repo: FindingsRepository = Depends(findings_repo),
) -> HTMLResponse:
    """Top findings rules as an HTMX table partial, sortable by count or severity."""
    sort_key = sort if sort in ("count", "severity") else "count"
    rows = [dict(r) for r in f_repo.count_by_rule(limit=10, sort=sort_key)]
    return templates.TemplateResponse(
        request,
        "partials/top_rules.html",
        {"top_rules": rows, "sort": sort_key},
    )


# ---------------------------------------------------------------------------
# JSON data endpoints
# ---------------------------------------------------------------------------


@router.get("/stats")
def api_stats(
    f_repo: FindingsRepository = Depends(findings_repo),
    e_repo: ErrorsRepository = Depends(errors_repo),
) -> dict:
    f_sum = f_repo.summary()
    e_sum = e_repo.summary()
    return {
        "findings_total": f_sum["total"],
        "findings_critical": f_sum["by_severity"].get("critical", 0),
        "error_types": e_sum["total_error_types"],
        "error_occurrences": e_sum["total_occurrences"],
    }


@router.get("/trend")
def api_trend(
    days: int = 14,
    f_repo: FindingsRepository = Depends(findings_repo),
    e_repo: ErrorsRepository = Depends(errors_repo),
) -> dict:
    return {
        "findings": f_repo.daily_counts(days=days),
        "errors": e_repo.daily_occurrences(days=days),
    }


# ---------------------------------------------------------------------------
# LLM explain
# ---------------------------------------------------------------------------


def _explain_prompt(rule_id: str, severity: str, message: str, source: str) -> str:
    return "\n".join(
        [
            "You are a log analysis expert. Explain the following security finding concisely.",
            "",
            "FINDING:",
            f"  Rule     : {rule_id}",
            f"  Severity : {severity.upper()}",
            f"  Source   : {source}",
            f"  Message  : {message}",
            "",
            "Answer these three questions in 3-5 sentences total:",
            "1. What happened?",
            "2. What is the likely cause?",
            "3. What should be done next?",
            "",
            "Be specific and actionable.",
        ]
    )


# ---------------------------------------------------------------------------
# Log file upload & instant scan
# ---------------------------------------------------------------------------

_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@router.post("/upload", response_class=HTMLResponse)
async def api_upload(
    request: Request,
    file: UploadFile = File(...),
    redact: str = Form("redact"),
    templates: Jinja2Templates = Depends(get_templates),
    cfg: Config = Depends(get_config),
) -> HTMLResponse:
    """Accept a log file, run PII redaction + rule engine, return an HTMX partial.

    Nothing is written to the database — results are shown in-page only.
    """
    from logsense.adapters.file import FileAdapter
    from logsense.parsers.detector import FormatDetector
    from logsense.pii.redactor import PIIRedactor, RedactMode

    filename = file.filename or "upload.log"

    # ── read with size guard ───────────────────────────────────────────────
    content = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(content) > _MAX_UPLOAD_BYTES:
        return templates.TemplateResponse(
            request,
            "partials/upload_results.html",
            {"error": "File too large — maximum upload size is 10 MB.", "filename": filename},
        )
    if not content.strip():
        return templates.TemplateResponse(
            request,
            "partials/upload_results.html",
            {"error": "The uploaded file is empty.", "filename": filename},
        )

    # ── write to temp file (preserve extension for format detection) ───────
    suffix = Path(filename).suffix or ".log"
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        # ── format detection ───────────────────────────────────────────────
        try:
            open_fn = gzip.open if suffix == ".gz" else open
            with open_fn(tmp_path, "rt", encoding="utf-8", errors="replace") as fh:
                sample_lines = [next(fh) for _ in range(10) if True]
            format_name = FormatDetector().detect(sample_lines, tmp_path).value
        except Exception:
            format_name = "auto"

        # ── redactor ──────────────────────────────────────────────────────
        try:
            mode = RedactMode(redact)
        except ValueError:
            mode = RedactMode.REDACT

        redactor = PIIRedactor.from_config(
            salt=cfg.pii_salt,
            rules_path=cfg.pii_rules_path,
            mode=mode,
        )

        # ── scan ──────────────────────────────────────────────────────────
        rule_engine = getattr(request.app.state, "rule_engine", None)
        events_out: list[dict] = []
        findings_out: list[dict] = []
        pii_hits = 0

        adapter = FileAdapter(tmp_path)
        async for event in adapter.events():
            result = redactor.redact(event.message)
            event.message = result.text
            pii_hits += len(result.hits)

            events_out.append(
                {
                    "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    if event.timestamp
                    else "—",
                    "severity": event.severity.value,
                    "message": event.message[:200],
                }
            )

            if rule_engine:
                for f in rule_engine.process(event):
                    findings_out.append(
                        {
                            "rule_id": f.rule_id,
                            "severity": f.severity.value,
                            "message": f.message,
                            "source": f.source,
                            "timestamp": f.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    )

        # Sort findings: critical → high → medium → low
        findings_out.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))

        return templates.TemplateResponse(
            request,
            "partials/upload_results.html",
            {
                "filename": filename,
                "format_name": format_name,
                "event_count": len(events_out),
                "pii_hits": pii_hits,
                "redact_mode": mode.value,
                "findings": findings_out,
                "sample_events": events_out[:20],
                "error": None,
            },
        )

    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "partials/upload_results.html",
            {"error": str(exc), "filename": filename},
        )
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


@router.post("/explain", response_class=HTMLResponse)
def api_explain(
    request: Request,
    rule_id: str = Form(""),
    severity: str = Form(""),
    message: str = Form(""),
    source: str = Form(""),
    templates: Jinja2Templates = Depends(get_templates),
    cfg: Config = Depends(get_config),
) -> HTMLResponse:
    explanation = ""
    error = ""
    try:
        from logsense.llm.factory import make_llm_client

        client = make_llm_client(cfg.llm)
        if not client.is_available():
            error = f"LLM provider '{cfg.llm.provider}' is not reachable."
        else:
            prompt = _explain_prompt(rule_id, severity, message, source)
            explanation = client.generate(prompt, stream=False)
    except Exception as exc:
        error = str(exc)

    return templates.TemplateResponse(
        request,
        "partials/llm_explain.html",
        {"explanation": explanation, "error": error},
    )
