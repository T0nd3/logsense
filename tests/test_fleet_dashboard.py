"""Tests for the dashboard target filter — repo filtering + the options helper."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from logatory.errors.fingerprint import fingerprint
from logatory.models import Event, Finding, FindingSeverity, Severity
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository
from logatory.web.fleet_targets import fleet_options, resolve_filter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(target: str, rule_id: str) -> Finding:
    ev = Event(
        raw="x",
        source="svc",
        message="m",
        timestamp=datetime.now(tz=UTC),
        severity=Severity.ERROR,
        parsed_fields={"target": target},
    )
    return Finding(
        rule_id=rule_id,
        severity=FindingSeverity.HIGH,
        message="m",
        source="svc",
        timestamp=datetime.now(tz=UTC),
        events=[ev],
    )


def _targets_yaml(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "targets.yaml"
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Findings filtering by target
# ---------------------------------------------------------------------------


class TestFindingsTargetFilter:
    def test_filter_by_single_target(self, tmp_path):
        with FindingsRepository(tmp_path / "f.db") as repo:
            repo.add_findings([_finding("web01", "R1"), _finding("web02", "R2")])
            rows = repo.list_findings(targets=["web01"])
            assert [r["rule_id"] for r in rows] == ["R1"]

    def test_filter_by_multiple_targets(self, tmp_path):
        with FindingsRepository(tmp_path / "f.db") as repo:
            repo.add_findings(
                [_finding("web01", "R1"), _finding("web02", "R2"), _finding("db01", "R3")]
            )
            rows = repo.list_findings(targets=["web01", "web02"])
            assert {r["rule_id"] for r in rows} == {"R1", "R2"}

    def test_no_target_filter_returns_all(self, tmp_path):
        with FindingsRepository(tmp_path / "f.db") as repo:
            repo.add_findings([_finding("web01", "R1"), _finding("web02", "R2")])
            assert len(repo.list_findings()) == 2


# ---------------------------------------------------------------------------
# Errors filtering by target (through error_occurrences)
# ---------------------------------------------------------------------------


class TestErrorsTargetFilter:
    def test_filter_errors_by_target(self, tmp_path):
        with ErrorsRepository(tmp_path / "e.db") as repo:
            for name, msg in [("web01", "ValueError: a"), ("web02", "RuntimeError: b")]:
                repo.upsert(
                    fingerprint=fingerprint(msg),
                    error_type="E",
                    normalized_msg=msg,
                    severity="error",
                    source="svc",
                    timestamp=datetime.now(tz=UTC),
                    sample=msg,
                    target=name,
                )
            assert len(repo.list_errors(targets=["web01"])) == 1
            assert len(repo.list_errors()) == 2


# ---------------------------------------------------------------------------
# Dropdown options
# ---------------------------------------------------------------------------


class TestFleetOptions:
    def test_options_from_targets_file(self, tmp_path):
        p = _targets_yaml(
            tmp_path,
            """
targets:
  - name: web01
    type: ssh
    host: h1
    groups: [web]
  - name: db01
    type: ssh
    host: h2
    groups: [db]
""",
        )
        values = {o["value"] for o in fleet_options(p)}
        assert {"t:web01", "t:db01", "g:web", "g:db"} <= values

    def test_no_file_returns_empty(self, tmp_path):
        assert fleet_options(tmp_path / "missing.yaml") == []


# ---------------------------------------------------------------------------
# Selection resolution
# ---------------------------------------------------------------------------


class TestResolveFilter:
    def _file(self, tmp_path: Path) -> Path:
        return _targets_yaml(
            tmp_path,
            """
targets:
  - name: web01
    type: ssh
    host: h1
    groups: [web, prod]
  - name: web02
    type: ssh
    host: h2
    groups: [web]
""",
        )

    def test_resolve_target(self, tmp_path):
        assert resolve_filter("t:web01", self._file(tmp_path)) == ["web01"]

    def test_resolve_group(self, tmp_path):
        assert set(resolve_filter("g:web", self._file(tmp_path))) == {"web01", "web02"}

    def test_resolve_none(self, tmp_path):
        f = self._file(tmp_path)
        assert resolve_filter(None, f) is None
        assert resolve_filter("", f) is None

    def test_resolve_unknown_target(self, tmp_path):
        assert resolve_filter("t:ghost", self._file(tmp_path)) is None
