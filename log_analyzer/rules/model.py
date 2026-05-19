from __future__ import annotations

from dataclasses import dataclass, field

from ..models import FindingSeverity


@dataclass(frozen=True)
class MatchCondition:
    """A single field condition. All conditions in a rule are ANDed."""
    field: str   # dotted path: "message", "parsed_fields.remote_addr", "severity"
    op: str      # eq, ne, contains, startswith, endswith, re, gt, lt, gte, lte
    value: str


@dataclass(frozen=True)
class AggregateCondition:
    """Triggers a finding when event count crosses a threshold within a time window."""
    count_op: str          # >=, >, ==, <=, <
    count_val: int
    timeframe_seconds: int
    group_by: str | None = None         # dotted field path; group counts per distinct value
    group_by_regex: str | None = None   # regex on message; group(1) used as key


@dataclass
class Rule:
    id: str
    title: str
    level: FindingSeverity
    match: list[MatchCondition]
    aggregate: AggregateCondition | None = None
    description: str = ""
    logsource_formats: list[str] | None = None  # None = any format
    tags: list[str] = field(default_factory=list)
    source_file: str = ""
