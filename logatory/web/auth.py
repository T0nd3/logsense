"""Authentication for the REST API.

Two dependencies:

* ``current_principal`` — resolves the request's :class:`Principal` and never
  raises.  Returns ``Principal(kind="anonymous")`` when auth is disabled or
  when the supplied Bearer token does not match.
* ``require_token`` — enforces auth: raises 401 when ``cfg.api_token`` is set
  and the request did not supply a matching Bearer token.  Returns the
  resolved :class:`Principal` on success.

If ``cfg.api_token`` is ``None`` (or empty), authentication is disabled —
all requests are accepted as ``Principal(kind="anonymous")``.

Token priority: ``LOGATORY_API_TOKEN`` env var > ``config.yaml`` ``api_token``.

The :class:`Principal` dataclass is intentionally forward-compatible: future
kinds such as ``"user"`` (with ``user_id`` / ``tenant_id``) can be added by
the commercial multi-user server without changing the return contract of
``require_token`` or any OSS route.  See ``Log-Analyzer.md`` →
"Enterprise-Vorbereitung - Code-Survey" for the design rationale.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from logatory.config import Config

from .deps import get_config

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    """The authenticated principal making a request.

    Today, ``kind`` is one of:

    * ``"anonymous"`` — no auth required (``api_token`` unset) or invalid
      token presented to a non-enforcing dependency.
    * ``"api_token"`` — request authenticated by a valid Bearer token.

    ``user_id`` and ``tenant_id`` are reserved for the future multi-user
    server and are always ``None`` in the open-source build.
    """

    kind: str
    user_id: int | None = None
    tenant_id: int | None = None

    @property
    def is_authenticated(self) -> bool:
        """True for any non-anonymous principal."""
        return self.kind != "anonymous"


def current_principal(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    cfg: Config = Depends(get_config),
) -> Principal:
    """FastAPI dependency: resolve the request's principal without raising.

    * ``api_token`` unset → ``Principal("anonymous")``
    * ``api_token`` set + matching Bearer → ``Principal("api_token")``
    * ``api_token`` set + missing/wrong Bearer → ``Principal("anonymous")``

    Use this when a handler wants to *know* who the caller is but does not
    want to enforce authentication itself (e.g. handlers that show extra
    fields to authenticated callers).  Use :func:`require_token` to enforce.
    """
    if not cfg.api_token:
        return Principal(kind="anonymous")
    if credentials is None or credentials.credentials != cfg.api_token:
        return Principal(kind="anonymous")
    return Principal(kind="api_token")


def require_token(
    principal: Principal = Depends(current_principal),
    cfg: Config = Depends(get_config),
) -> Principal:
    """FastAPI dependency: enforce auth when ``api_token`` is configured.

    * ``api_token`` unset → returns ``Principal("anonymous")`` (auth disabled).
    * ``api_token`` set + authenticated → returns ``Principal("api_token")``.
    * ``api_token`` set + not authenticated → raises 401.
    """
    if cfg.api_token and not principal.is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal
