"""Detection seam for the optional commercial ``logatory-enterprise`` add-on.

The open-source core never imports or depends on ``logatory_enterprise``.
This module is the single place where the core may discover whether the
enterprise add-on is installed — any future premium feature gate goes
through here.

When the add-on is absent (the standard case) every function degrades to a
safe default: the core runs with its full open-source feature set and
nothing is restricted. Installing the add-on may only ever *add*
capabilities, never change or remove core behaviour.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def enterprise_available() -> bool:
    """Return True if the commercial ``logatory-enterprise`` package is installed.

    This is a pure capability probe — the core works fully without it.
    """
    try:
        import logatory_enterprise  # noqa: F401
    except ImportError:
        return False
    return True


def enterprise_version() -> str | None:
    """Return the installed ``logatory-enterprise`` version, or None if absent."""
    if not enterprise_available():
        return None
    try:
        return version("logatory-enterprise")
    except PackageNotFoundError:
        return None
