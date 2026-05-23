"""Tests for the severity-level API on FindingSeverity / Severity.

This locks the single-source-of-truth contract: any code that needs to
compare or sort severities goes through `.level` (or the helper
functions for raw strings).  See `Log-Analyzer.md` notes for context.
"""

from __future__ import annotations

import pytest

from logatory.models import (
    FindingSeverity,
    Severity,
    event_severity_level,
    finding_severity_level,
)


class TestFindingSeverityLevel:
    def test_levels_are_strictly_ascending(self) -> None:
        assert FindingSeverity.LOW.level < FindingSeverity.MEDIUM.level
        assert FindingSeverity.MEDIUM.level < FindingSeverity.HIGH.level
        assert FindingSeverity.HIGH.level < FindingSeverity.CRITICAL.level

    def test_level_via_string_constructor(self) -> None:
        assert FindingSeverity("low").level == 0
        assert FindingSeverity("critical").level == 3

    @pytest.mark.parametrize(
        "value,expected",
        [("low", 0), ("medium", 1), ("high", 2), ("critical", 3)],
    )
    def test_helper_maps_each_value(self, value: str, expected: int) -> None:
        assert finding_severity_level(value) == expected

    def test_helper_is_case_insensitive(self) -> None:
        assert finding_severity_level("HIGH") == finding_severity_level("high")

    def test_helper_returns_default_for_unknown(self) -> None:
        assert finding_severity_level("nonsense") == 0
        assert finding_severity_level("nonsense", default=2) == 2

    def test_helper_returns_default_for_none(self) -> None:
        # Defensive: callers sometimes pass None coming from optional config.
        assert finding_severity_level(None, default=-1) == -1  # type: ignore[arg-type]


class TestEventSeverityLevel:
    def test_levels_are_strictly_ascending(self) -> None:
        ladder = [
            Severity.DEBUG,
            Severity.INFO,
            Severity.WARNING,
            Severity.ERROR,
            Severity.CRITICAL,
        ]
        levels = [s.level for s in ladder]
        assert levels == sorted(levels)
        assert len(set(levels)) == len(levels)  # all distinct

    def test_helper_returns_default_for_unknown(self) -> None:
        assert event_severity_level("not-a-real-level", default=99) == 99

    def test_helper_round_trips_known_values(self) -> None:
        for s in Severity:
            assert event_severity_level(s.value) == s.level


class TestDescendingSortPattern:
    """The web API sorts critical→low by negating .level — lock the pattern."""

    def test_negated_level_sorts_descending(self) -> None:
        severities = ["low", "critical", "medium", "high"]
        sorted_desc = sorted(severities, key=lambda s: -finding_severity_level(s))
        assert sorted_desc == ["critical", "high", "medium", "low"]

    def test_unknown_value_falls_to_end_with_negative_default(self) -> None:
        severities = ["low", "critical", "weird", "high"]
        sorted_desc = sorted(severities, key=lambda s: -finding_severity_level(s, default=-9))
        assert sorted_desc[-1] == "weird"
