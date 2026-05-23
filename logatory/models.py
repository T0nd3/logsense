from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

# Canonical priority maps — higher value means more severe.  Single source
# of truth for all severity comparison and sorting across the codebase.
# Negate `.level` when you need descending order (most-critical first).
_EVENT_LEVELS: dict[str, int] = {
    "debug": 0,
    "info": 1,
    "warning": 2,
    "error": 3,
    "critical": 4,
}

_FINDING_LEVELS: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class Severity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        """Numeric priority — higher is more severe."""
        return _EVENT_LEVELS[self.value]


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        """Numeric priority — higher is more severe."""
        return _FINDING_LEVELS[self.value]


def finding_severity_level(value: str, default: int = 0) -> int:
    """Return the level for a FindingSeverity value string, or *default*.

    Use when you have a raw string (e.g. from SQLite or an HTTP query
    parameter) and need a comparable integer without raising on unknown
    input.  Pass a sentinel default to sort unknowns to one end.
    """
    try:
        return FindingSeverity(value.lower()).level
    except (ValueError, AttributeError):
        return default


def event_severity_level(value: str, default: int = 0) -> int:
    """Return the level for an event Severity value string, or *default*."""
    try:
        return Severity(value.lower()).level
    except (ValueError, AttributeError):
        return default


@dataclass
class Event:
    raw: str
    source: str
    message: str
    timestamp: datetime | None = None
    severity: Severity = Severity.INFO
    parsed_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    severity: FindingSeverity
    message: str
    source: str
    timestamp: datetime
    events: list[Event] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
