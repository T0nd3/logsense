"""Bearer token authentication for the REST API.

If `config.api_token` is None (or empty), authentication is disabled —
all requests are accepted.  Set a non-empty token to enforce auth.

Token priority: LOGSENSE_API_TOKEN env var > config.yaml `api_token`.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from logsense.config import Config

from .deps import get_config

_bearer = HTTPBearer(auto_error=False)


def require_token(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    cfg: Config = Depends(get_config),
) -> None:
    """FastAPI dependency: validate Bearer token when api_token is configured."""
    if not cfg.api_token:
        return  # auth disabled — local / dev mode
    if credentials is None or credentials.credentials != cfg.api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
