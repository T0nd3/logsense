"""JSON and HTMX partial routes used by the dashboard."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from log_analyzer.config import Config
from log_analyzer.storage.errors_repo import ErrorsRepository
from log_analyzer.storage.findings_repo import FindingsRepository

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
    return "\n".join([
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
    ])


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
        from log_analyzer.llm.factory import make_llm_client

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
