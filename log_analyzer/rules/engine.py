from __future__ import annotations

import re
from collections import deque
from datetime import UTC, datetime
from typing import Any

from ..models import Event, Finding
from .model import AggregateCondition, MatchCondition, Rule


def _get_field(event: Event, path: str) -> Any:
    """Resolve a dotted field path against an Event."""
    if path == "message":
        return event.message
    if path == "raw":
        return event.raw
    if path == "source":
        return event.source
    if path == "severity":
        return event.severity.value
    if path.startswith("parsed_fields."):
        key = path[len("parsed_fields."):]
        return event.parsed_fields.get(key)
    return None


def _match_condition(cond: MatchCondition, event: Event) -> bool:
    val = _get_field(event, cond.field)
    if val is None:
        return False
    raw_val = str(val)
    target = cond.value

    match cond.op:
        case "eq":
            return raw_val == target
        case "ne":
            return raw_val != target
        case "contains":
            return target.lower() in raw_val.lower()
        case "startswith":
            return raw_val.lower().startswith(target.lower())
        case "endswith":
            return raw_val.lower().endswith(target.lower())
        case "re":
            return bool(re.search(target, raw_val))
        case "gt":
            return float(raw_val) > float(target)
        case "lt":
            return float(raw_val) < float(target)
        case "gte":
            return float(raw_val) >= float(target)
        case "lte":
            return float(raw_val) <= float(target)
        case _:
            return False


def _eval_count(op: str, actual: int, threshold: int) -> bool:
    match op:
        case ">=":
            return actual >= threshold
        case ">":
            return actual > threshold
        case "==":
            return actual == threshold
        case "<=":
            return actual <= threshold
        case "<":
            return actual < threshold
        case _:
            return False


def _extract_group_key(agg: AggregateCondition, event: Event) -> str:
    if agg.group_by:
        val = _get_field(event, agg.group_by)
        return str(val) if val is not None else "__none__"
    if agg.group_by_regex:
        m = re.search(agg.group_by_regex, event.message)
        if m:
            return m.group(1)
    return "__global__"


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules
        # rule_id → group_key → deque of event timestamps
        self._buffers: dict[str, dict[str, deque[datetime]]] = {}
        # rule_id → group_key → timestamp of last emitted finding (cooldown)
        self._cooldown: dict[str, dict[str, datetime]] = {}

    def process(self, event: Event) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            if not self._logsource_matches(rule, event):
                continue
            if not all(_match_condition(c, event) for c in rule.match):
                continue
            if rule.aggregate:
                finding = self._process_aggregate(rule, event)
            else:
                finding = _make_finding(rule, event)
            if finding:
                findings.append(finding)
        return findings

    def _logsource_matches(self, rule: Rule, event: Event) -> bool:
        if not rule.logsource_formats:
            return True
        # Source contains the file path; format tag added by parsers via source field
        # We match against the format names stored in rule.logsource_formats
        # For now, always True if no logsource restriction (parsers don't embed format)
        return True

    def _process_aggregate(self, rule: Rule, event: Event) -> Finding | None:
        agg = rule.aggregate
        assert agg is not None

        group_key = _extract_group_key(agg, event)
        ts = event.timestamp or datetime.now(tz=UTC)

        buf = self._buffers.setdefault(rule.id, {}).setdefault(group_key, deque())
        buf.append(ts)

        # Expire entries outside the time window
        cutoff = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts
        from datetime import timedelta
        cutoff = cutoff - timedelta(seconds=agg.timeframe_seconds)
        while buf and _ts_utc(buf[0]) < cutoff:
            buf.popleft()

        count = len(buf)
        if not _eval_count(agg.count_op, count, agg.count_val):
            return None

        # Cooldown: don't re-fire within the same timeframe
        last = self._cooldown.setdefault(rule.id, {}).get(group_key)
        if last and (_ts_utc(ts) - _ts_utc(last)).total_seconds() < agg.timeframe_seconds:
            return None
        self._cooldown[rule.id][group_key] = ts

        detail_group = f" from '{group_key}'" if group_key != "__global__" else ""
        message = (
            f"{rule.title}: {count} events{detail_group} "
            f"within {agg.timeframe_seconds}s "
            f"(threshold: {agg.count_op} {agg.count_val})"
        )
        return Finding(
            rule_id=rule.id,
            severity=rule.level,
            message=message,
            source=event.source,
            timestamp=ts if ts.tzinfo else ts.replace(tzinfo=UTC),
            events=[event],
            details={"group_key": group_key, "count": count, "tags": rule.tags},
        )

    def reset(self) -> None:
        """Clear all buffered state (use between independent scans)."""
        self._buffers.clear()
        self._cooldown.clear()


def _make_finding(rule: Rule, event: Event) -> Finding:
    ts = event.timestamp or datetime.now(tz=UTC)
    return Finding(
        rule_id=rule.id,
        severity=rule.level,
        message=f"{rule.title}: {event.message[:200]}",
        source=event.source,
        timestamp=ts if ts.tzinfo else ts.replace(tzinfo=UTC),
        events=[event],
        details={"tags": rule.tags},
    )


def _ts_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts
