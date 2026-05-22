"""Minimal HTTP GET helper for the Loki and Graylog adapters.

Standard library only — no `requests` / `httpx` dependency. Both adapters
just need authenticated JSON GETs, which `urllib` handles fine.
"""

from __future__ import annotations

import base64
import urllib.error
import urllib.request


def basic_auth_header(username: str, password: str) -> str:
    """Build an HTTP Basic ``Authorization`` header value."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def http_get(url: str, headers: dict[str, str], timeout: float = 30.0) -> str:
    """GET a URL and return the response body as text.

    Raises RuntimeError with a readable message on any HTTP or network
    error, so callers can surface a clean failure.
    """
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace").strip()[:200]
        raise RuntimeError(f"HTTP {e.code} {e.reason}: {detail or url}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"could not reach {url}: {e.reason}")
