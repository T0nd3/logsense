from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from log_analyzer.models import Event, FindingSeverity, Severity
from log_analyzer.rules.engine import (
    RuleEngine,
    _eval_count,
    _extract_group_key,
    _get_field,
    _ts_utc,
)
from log_analyzer.rules.loader import load_rules_dir, validate_rule_file
from log_analyzer.rules.model import Rule
from log_analyzer.rules.sigma import load_sigma_file

_BUILTIN = Path(__file__).parent.parent / "log_analyzer" / "rules" / "builtin"
_DATA = Path(__file__).parent / "data"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(message: str, ts: datetime | None = None, **parsed) -> Event:
    return Event(
        raw=message,
        source="test",
        message=message,
        timestamp=ts or datetime.now(tz=UTC),
        severity=Severity.INFO,
        parsed_fields=parsed,
    )


def _make_rule(match: list[dict], agg: dict | None = None, level: str = "high") -> Rule:
    from log_analyzer.rules.loader import _load_one

    data = {
        "id": "test_rule",
        "title": "Test Rule",
        "level": level,
        "detection": {"match": match},
    }
    if agg:
        data["detection"]["aggregate"] = agg
    return _load_one(data, "<test>")


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------


class TestGetField:
    def test_message(self):
        ev = _event("hello")
        assert _get_field(ev, "message") == "hello"

    def test_parsed_field(self):
        ev = _event("x", status=404)
        assert _get_field(ev, "parsed_fields.status") == 404

    def test_missing_returns_none(self):
        ev = _event("x")
        assert _get_field(ev, "parsed_fields.nonexistent") is None


# ---------------------------------------------------------------------------
# Simple rule matching
# ---------------------------------------------------------------------------


class TestSimpleMatching:
    def test_contains_match(self):
        rule = _make_rule([{"field": "message", "op": "contains", "value": "Failed password"}])
        engine = RuleEngine([rule])
        findings = engine.process(_event("Failed password for user foo from 1.2.3.4 port 22"))
        assert len(findings) == 1

    def test_contains_no_match(self):
        rule = _make_rule([{"field": "message", "op": "contains", "value": "Failed password"}])
        engine = RuleEngine([rule])
        assert engine.process(_event("Accepted publickey for admin")) == []

    def test_eq_match(self):
        rule = _make_rule([{"field": "parsed_fields.status", "op": "eq", "value": "404"}])
        engine = RuleEngine([rule])
        assert len(engine.process(_event("x", status=404))) == 1

    def test_multiple_conditions_all_must_match(self):
        rule = _make_rule(
            [
                {"field": "message", "op": "contains", "value": "sudo"},
                {"field": "message", "op": "contains", "value": "USER=root"},
            ]
        )
        engine = RuleEngine([rule])
        assert engine.process(_event("sudo without root")) == []
        assert len(engine.process(_event("sudo USER=root COMMAND=ls"))) == 1

    def test_gte_operator(self):
        rule = _make_rule([{"field": "parsed_fields.status", "op": "gte", "value": "500"}])
        engine = RuleEngine([rule])
        assert engine.process(_event("x", status=499)) == []
        assert len(engine.process(_event("x", status=500))) == 1
        assert len(engine.process(_event("x", status=503))) == 1

    def test_regex_operator(self):
        rule = _make_rule([{"field": "message", "op": "re", "value": r"UID=0"}])
        engine = RuleEngine([rule])
        assert len(engine.process(_event("new user: name=bad, UID=0, GID=0"))) == 1


# ---------------------------------------------------------------------------
# Aggregate rules
# ---------------------------------------------------------------------------


class TestAggregateRules:
    def _ssh_rule(self) -> Rule:
        return _make_rule(
            [{"field": "message", "op": "contains", "value": "Failed password"}],
            agg={"group_by_regex": r"from (\S+) port", "count": ">= 3", "timeframe": "5m"},
        )

    def test_fires_after_threshold(self):
        rule = self._ssh_rule()
        engine = RuleEngine([rule])
        base = datetime.now(tz=UTC)
        findings = []
        for i in range(3):
            ts = base + timedelta(seconds=i * 10)
            findings += engine.process(
                _event("Failed password for guest from 1.2.3.4 port 22", ts=ts)
            )
        assert len(findings) == 1

    def test_does_not_fire_below_threshold(self):
        rule = self._ssh_rule()
        engine = RuleEngine([rule])
        base = datetime.now(tz=UTC)
        findings = []
        for i in range(2):
            ts = base + timedelta(seconds=i * 10)
            findings += engine.process(
                _event("Failed password for guest from 1.2.3.4 port 22", ts=ts)
            )
        assert findings == []

    def test_groups_by_ip_separately(self):
        rule = self._ssh_rule()
        engine = RuleEngine([rule])
        base = datetime.now(tz=UTC)
        # 3 from ip_aaa, 3 from ip_bbb → 2 findings (one per group)
        for i in range(3):
            ts = base + timedelta(seconds=i)
            engine.process(_event("Failed password from ip_aaa port 22", ts=ts))
        findings = []
        for i in range(3):
            ts = base + timedelta(seconds=i)
            findings += engine.process(_event("Failed password from ip_bbb port 22", ts=ts))
        assert len(findings) == 1  # ip_bbb crosses threshold
        assert "ip_bbb" in findings[0].message

    def test_cooldown_prevents_duplicate_findings(self):
        rule = self._ssh_rule()
        engine = RuleEngine([rule])
        base = datetime.now(tz=UTC)
        findings = []
        for i in range(6):
            ts = base + timedelta(seconds=i * 5)
            findings += engine.process(_event("Failed password from ip_xxx port 22", ts=ts))
        assert len(findings) == 1  # only one despite 6 matching events


# ---------------------------------------------------------------------------
# RuleLoader
# ---------------------------------------------------------------------------


class TestRuleLoader:
    def test_load_builtin_rules(self):
        rules = load_rules_dir(_BUILTIN)
        assert len(rules) >= 5

    def test_ssh_rule_has_aggregate(self):
        rules = load_rules_dir(_BUILTIN)
        ssh = next(r for r in rules if r.id == "ssh_brute_force")
        assert ssh.aggregate is not None
        assert ssh.aggregate.count_val == 5
        assert ssh.level == FindingSeverity.HIGH

    def test_validate_valid_rule(self, tmp_path):
        rule_file = tmp_path / "ok.yml"
        rule_file.write_text("""
id: my_rule
title: My Rule
level: medium
detection:
  match:
    - field: message
      op: contains
      value: error
""")
        assert validate_rule_file(rule_file) == []

    def test_validate_missing_id(self, tmp_path):
        rule_file = tmp_path / "bad.yml"
        rule_file.write_text("title: No ID\nlevel: low\ndetection:\n  match: []\n")
        errors = validate_rule_file(rule_file)
        assert any("id" in e for e in errors)

    def test_validate_invalid_level(self, tmp_path):
        rule_file = tmp_path / "bad_level.yml"
        rule_file.write_text("id: x\ntitle: X\nlevel: super-critical\ndetection:\n  match: []\n")
        errors = validate_rule_file(rule_file)
        assert any("level" in e for e in errors)


# ---------------------------------------------------------------------------
# Sigma loader
# ---------------------------------------------------------------------------


class TestSigmaLoader:
    def _sigma_rule(self, tmp_path, content: str) -> Path:
        p = tmp_path / "sigma_rule.yml"
        p.write_text(content)
        return p

    def test_basic_sigma_rule(self, tmp_path):
        p = self._sigma_rule(
            tmp_path,
            """
title: SSH Brute Force
id: test-sigma-ssh
level: high
logsource:
  category: authentication
detection:
  selection:
    message|contains: 'Failed password'
  condition: selection
""",
        )
        rule = load_sigma_file(p)
        assert rule.id == "test-sigma-ssh"
        assert rule.level == FindingSeverity.HIGH
        assert any(c.op == "contains" for c in rule.match)

    def test_sigma_with_count_aggregate(self, tmp_path):
        p = self._sigma_rule(
            tmp_path,
            """
title: Many Failures
id: test-sigma-agg
level: high
logsource:
  category: authentication
detection:
  selection:
    message|contains: 'Failed'
  timeframe: 5m
  condition: selection | count() > 10
""",
        )
        rule = load_sigma_file(p)
        assert rule.aggregate is not None
        assert rule.aggregate.count_val == 10
        assert rule.aggregate.count_op == ">"
        assert rule.aggregate.timeframe_seconds == 300

    def test_sigma_logsource_mapped(self, tmp_path):
        p = self._sigma_rule(
            tmp_path,
            """
title: Web Errors
id: test-sigma-web
level: medium
logsource:
  category: webserver
detection:
  selection:
    message|contains: 'error'
  condition: selection
""",
        )
        rule = load_sigma_file(p)
        assert "nginx_combined" in (rule.logsource_formats or [])

    def test_sigma_windows_logsource(self, tmp_path):
        p = self._sigma_rule(
            tmp_path,
            """
title: Windows Event
id: test-sigma-win
level: medium
logsource:
  product: windows
detection:
  selection:
    EventID: 4625
  condition: selection
""",
        )
        rule = load_sigma_file(p)
        assert "evtx" in (rule.logsource_formats or [])
        assert any(c.field == "parsed_fields.event_id" for c in rule.match)

    def test_sigma_count_by_field(self, tmp_path):
        p = self._sigma_rule(
            tmp_path,
            """
title: Brute Force by IP
id: test-sigma-grp
level: high
logsource:
  category: authentication
detection:
  selection:
    message|contains: 'Failed'
  timeframe: 10m
  condition: selection | count() by IpAddress > 5
""",
        )
        rule = load_sigma_file(p)
        assert rule.aggregate is not None
        assert rule.aggregate.group_by == "parsed_fields.ip_address"


# ---------------------------------------------------------------------------
# _get_field — untested field paths
# ---------------------------------------------------------------------------


class TestGetFieldExtended:
    def test_raw_field(self):
        ev = _event("msg")
        ev.raw = "raw line content"
        assert _get_field(ev, "raw") == "raw line content"

    def test_source_field(self):
        ev = Event(raw="x", source="auth.log", message="x", severity=Severity.INFO)
        assert _get_field(ev, "source") == "auth.log"

    def test_severity_field(self):
        ev = _event("x")
        assert _get_field(ev, "severity") == "info"

    def test_unknown_field_returns_none(self):
        assert _get_field(_event("x"), "no_such_field") is None


# ---------------------------------------------------------------------------
# _match_condition — untested operators
# ---------------------------------------------------------------------------


class TestMatchConditionOperators:
    def _rule(self, op: str, value: str, field: str = "message") -> Rule:
        return _make_rule([{"field": field, "op": op, "value": value}])

    def test_ne_matches(self):
        engine = RuleEngine([self._rule("ne", "ok")])
        assert len(engine.process(_event("error"))) == 1

    def test_ne_no_match(self):
        engine = RuleEngine([self._rule("ne", "error")])
        assert engine.process(_event("error")) == []

    def test_startswith_matches(self):
        engine = RuleEngine([self._rule("startswith", "CRIT")])
        assert len(engine.process(_event("CRITICAL: disk full"))) == 1

    def test_startswith_no_match(self):
        engine = RuleEngine([self._rule("startswith", "CRIT")])
        assert engine.process(_event("info: all fine")) == []

    def test_endswith_matches(self):
        engine = RuleEngine([self._rule("endswith", "failed")])
        assert len(engine.process(_event("login failed"))) == 1

    def test_endswith_no_match(self):
        engine = RuleEngine([self._rule("endswith", "failed")])
        assert engine.process(_event("login succeeded")) == []

    def test_gt_matches(self):
        engine = RuleEngine([self._rule("gt", "400", field="parsed_fields.status")])
        assert len(engine.process(_event("x", status=500))) == 1

    def test_gt_no_match(self):
        engine = RuleEngine([self._rule("gt", "400", field="parsed_fields.status")])
        assert engine.process(_event("x", status=400)) == []

    def test_lt_matches(self):
        engine = RuleEngine([self._rule("lt", "300", field="parsed_fields.status")])
        assert len(engine.process(_event("x", status=200))) == 1

    def test_lte_matches(self):
        engine = RuleEngine([self._rule("lte", "404", field="parsed_fields.status")])
        assert len(engine.process(_event("x", status=404))) == 1

    def test_unknown_op_returns_no_match(self):
        engine = RuleEngine([self._rule("unknown_op", "x")])
        assert engine.process(_event("x")) == []

    def test_none_field_value_returns_no_match(self):
        """Condition on a missing parsed field returns no match."""
        engine = RuleEngine([self._rule("eq", "foo", field="parsed_fields.missing")])
        assert engine.process(_event("msg")) == []


# ---------------------------------------------------------------------------
# _eval_count — untested operators
# ---------------------------------------------------------------------------


class TestEvalCount:
    def test_gt(self):
        assert _eval_count(">", 5, 4) is True
        assert _eval_count(">", 4, 4) is False

    def test_eq(self):
        assert _eval_count("==", 3, 3) is True
        assert _eval_count("==", 3, 4) is False

    def test_lte(self):
        assert _eval_count("<=", 3, 3) is True
        assert _eval_count("<=", 4, 3) is False

    def test_lt(self):
        assert _eval_count("<", 2, 3) is True
        assert _eval_count("<", 3, 3) is False

    def test_unknown_op(self):
        assert _eval_count("??", 5, 1) is False


# ---------------------------------------------------------------------------
# _extract_group_key
# ---------------------------------------------------------------------------


class TestExtractGroupKey:
    def _agg(self, group_by=None, group_by_regex=None):
        from log_analyzer.rules.model import AggregateCondition

        return AggregateCondition(
            count_op=">=",
            count_val=1,
            timeframe_seconds=60,
            group_by=group_by,
            group_by_regex=group_by_regex,
        )

    def test_group_by_field(self):
        agg = self._agg(group_by="source")
        ev = Event(raw="x", source="auth.log", message="x", severity=Severity.INFO)
        assert _extract_group_key(agg, ev) == "auth.log"

    def test_group_by_field_none_value(self):
        agg = self._agg(group_by="parsed_fields.missing")
        assert _extract_group_key(agg, _event("x")) == "__none__"

    def test_group_by_regex_matches(self):
        agg = self._agg(group_by_regex=r"from (\S+) port")
        ev = _event("Failed password from 10.0.0.1 port 22")
        assert _extract_group_key(agg, ev) == "10.0.0.1"

    def test_group_by_regex_no_match_returns_global(self):
        agg = self._agg(group_by_regex=r"from (\S+) port")
        assert _extract_group_key(agg, _event("no ip here")) == "__global__"

    def test_no_group_by_returns_global(self):
        agg = self._agg()
        assert _extract_group_key(agg, _event("x")) == "__global__"


# ---------------------------------------------------------------------------
# RuleEngine.reset() and window expiry
# ---------------------------------------------------------------------------


class TestRuleEngineReset:
    def test_reset_clears_buffers(self):
        rule = _make_rule(
            [{"field": "message", "op": "contains", "value": "fail"}],
            agg={"count": ">= 2", "timeframe": "5m"},
        )
        engine = RuleEngine([rule])
        base = datetime.now(tz=UTC)
        engine.process(_event("fail", ts=base))
        engine.reset()
        # After reset, buffer is empty — a single event should not fire
        findings = engine.process(_event("fail", ts=base + timedelta(seconds=1)))
        assert findings == []

    def test_old_events_expire_from_window(self):
        rule = _make_rule(
            [{"field": "message", "op": "contains", "value": "fail"}],
            agg={"count": ">= 3", "timeframe": "10s"},
        )
        engine = RuleEngine([rule])
        base = datetime.now(tz=UTC)
        # Two events within window
        engine.process(_event("fail", ts=base))
        engine.process(_event("fail", ts=base + timedelta(seconds=5)))
        # Third event 20s later — the first two have expired
        findings = engine.process(_event("fail", ts=base + timedelta(seconds=25)))
        assert findings == []


# ---------------------------------------------------------------------------
# _ts_utc helper
# ---------------------------------------------------------------------------


class TestTsUtc:
    def test_naive_datetime_gets_utc(self):
        from datetime import datetime

        naive = datetime(2026, 1, 1, 12, 0, 0)
        result = _ts_utc(naive)
        assert result.tzinfo is not None

    def test_aware_datetime_unchanged(self):
        from datetime import datetime

        aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        result = _ts_utc(aware)
        assert result == aware
