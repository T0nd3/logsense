from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


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
