"""FastAPI dependency helpers for the web dashboard."""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Request
from fastapi.templating import Jinja2Templates

from logatory.config import Config
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository


def get_config(request: Request) -> Config:
    return request.app.state.config  # type: ignore[no-any-return]


def get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates  # type: ignore[no-any-return]


def findings_repo(request: Request) -> Generator[FindingsRepository, None, None]:
    repo = FindingsRepository(get_config(request).db_path)
    repo.open()
    try:
        yield repo
    finally:
        repo.close()


def errors_repo(request: Request) -> Generator[ErrorsRepository, None, None]:
    repo = ErrorsRepository(get_config(request).db_path)
    repo.open()
    try:
        yield repo
    finally:
        repo.close()
