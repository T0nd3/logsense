"""HTML page routes — full-page responses rendered via Jinja2."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from logsense.storage.errors_repo import ErrorsRepository
from logsense.storage.findings_repo import FindingsRepository

from ..deps import errors_repo, findings_repo, get_templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    templates: Jinja2Templates = Depends(get_templates),
    f_repo: FindingsRepository = Depends(findings_repo),
    e_repo: ErrorsRepository = Depends(errors_repo),
) -> HTMLResponse:
    f_summary = f_repo.summary()
    e_summary = e_repo.summary()
    top_rules = [dict(r) for r in f_repo.count_by_rule(limit=10)]
    recent = [dict(r) for r in f_repo.recent_findings(since_hours=24)[:10]]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "active_page": "dashboard",
            "f_summary": f_summary,
            "e_summary": e_summary,
            "top_rules": top_rules,
            "recent": recent,
        },
    )


@router.get("/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    templates: Jinja2Templates = Depends(get_templates),
    f_repo: FindingsRepository = Depends(findings_repo),
) -> HTMLResponse:
    rows = [dict(r) for r in f_repo.list_findings(limit=200)]
    return templates.TemplateResponse(
        request,
        "findings.html",
        {"active_page": "findings", "rows": rows, "total": len(rows)},
    )


@router.get("/upload", response_class=HTMLResponse)
def upload_page(
    request: Request,
    templates: Jinja2Templates = Depends(get_templates),
) -> HTMLResponse:
    return templates.TemplateResponse(request, "upload.html", {"active_page": "upload"})


@router.get("/errors", response_class=HTMLResponse)
def errors_page(
    request: Request,
    templates: Jinja2Templates = Depends(get_templates),
    e_repo: ErrorsRepository = Depends(errors_repo),
) -> HTMLResponse:
    rows = [dict(r) for r in e_repo.list_errors(sort="last_seen", limit=200)]
    return templates.TemplateResponse(
        request,
        "errors.html",
        {"active_page": "errors", "rows": rows, "total": len(rows)},
    )
