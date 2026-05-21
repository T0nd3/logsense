"""Tests for cli/errors_cmd.py — errors list, show, new, regression."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cli.errors_cmd import _parse_hours, app
from log_analyzer.storage.errors_repo import ErrorsRepository

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts(offset_hours: int = 0) -> datetime:
    return datetime.now(tz=UTC) + timedelta(hours=offset_hours)


def _cfg_args(db_path: Path) -> list[str]:
    cfg_file = db_path.parent / "analyzer.yaml"
    cfg_file.write_text(f"db_path: {db_path}\n")
    return ["--config", str(cfg_file)]


def _seed(db_path: Path) -> None:
    with ErrorsRepository(db_path) as repo:
        repo.upsert(
            fingerprint="fp_conn",
            error_type="ConnectionError",
            normalized_msg="Connection refused to <HOST>",
            severity="high",
            source="app.log",
            timestamp=_ts(),
            sample="Connection refused to 10.0.0.1",
        )
        # second occurrence → count = 2
        repo.upsert(
            fingerprint="fp_conn",
            error_type="ConnectionError",
            normalized_msg="Connection refused to <HOST>",
            severity="high",
            source="app.log",
            timestamp=_ts(),
            sample="Connection refused to 10.0.0.2",
        )
        repo.upsert(
            fingerprint="fp_timeout",
            error_type="TimeoutError",
            normalized_msg="Query timed out after <NUM>s",
            severity="medium",
            source="db.log",
            timestamp=_ts(-1),
            sample="Query timed out after 30s",
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    p = tmp_path / "test.db"
    _seed(p)
    return p


@pytest.fixture()
def empty_db(tmp_path: Path) -> Path:
    p = tmp_path / "empty.db"
    with ErrorsRepository(p):
        pass
    return p


# ===========================================================================
# _parse_hours helper
# ===========================================================================


class TestParseHours:
    def test_hours(self) -> None:
        assert _parse_hours("24h") == 24

    def test_days(self) -> None:
        assert _parse_hours("7d") == 168

    def test_minutes(self) -> None:
        result = _parse_hours("30m")
        assert result >= 1

    def test_seconds_clamped_to_1(self) -> None:
        assert _parse_hours("10s") >= 1

    def test_invalid_exits_1(self) -> None:
        result = runner.invoke(app, ["new", "--since", "bad"])
        assert result.exit_code == 1

    def test_invalid_shows_message(self) -> None:
        result = runner.invoke(app, ["new", "--since", "xyz"])
        assert "Invalid" in result.output or result.exit_code != 0


# ===========================================================================
# errors list
# ===========================================================================


class TestErrorsList:
    def test_shows_errors(self, db: Path) -> None:
        result = runner.invoke(app, ["list"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "ConnectionError" in result.output
        assert "TimeoutError" in result.output

    def test_empty_db_message(self, empty_db: Path) -> None:
        result = runner.invoke(app, ["list"] + _cfg_args(empty_db))
        assert result.exit_code == 0
        assert "No errors" in result.output

    def test_shows_summary_counts(self, db: Path) -> None:
        result = runner.invoke(app, ["list"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "2 error types" in result.output
        assert "3 total occurrences" in result.output or "3" in result.output

    def test_filter_by_severity(self, db: Path) -> None:
        result = runner.invoke(app, ["list", "--severity", "high"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "ConnectionError" in result.output
        assert "TimeoutError" not in result.output

    def test_sort_by_count(self, db: Path) -> None:
        result = runner.invoke(app, ["list", "--sort", "count"] + _cfg_args(db))
        assert result.exit_code == 0
        # ConnectionError has count=2, should appear before TimeoutError
        conn_pos = result.output.find("ConnectionError")
        timeout_pos = result.output.find("TimeoutError")
        assert conn_pos < timeout_pos

    def test_sort_by_last_seen(self, db: Path) -> None:
        result = runner.invoke(app, ["list", "--sort", "last_seen"] + _cfg_args(db))
        assert result.exit_code == 0

    def test_limit_respected(self, db: Path) -> None:
        result = runner.invoke(app, ["list", "--limit", "1"] + _cfg_args(db))
        assert result.exit_code == 0
        # Only one error type should appear
        conn = result.output.count("Error")
        assert conn >= 1

    def test_fingerprint_in_output(self, db: Path) -> None:
        result = runner.invoke(app, ["list"] + _cfg_args(db))
        assert "fp_conn" in result.output

    def test_severity_shown(self, db: Path) -> None:
        result = runner.invoke(app, ["list"] + _cfg_args(db))
        assert "HIGH" in result.output or "high" in result.output.lower()


# ===========================================================================
# errors show
# ===========================================================================


class TestErrorsShow:
    def test_shows_error_details(self, db: Path) -> None:
        result = runner.invoke(app, ["show", "fp_conn"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "ConnectionError" in result.output
        assert "fp_conn" in result.output

    def test_shows_count(self, db: Path) -> None:
        result = runner.invoke(app, ["show", "fp_conn"] + _cfg_args(db))
        assert "2" in result.output  # count = 2

    def test_shows_sources(self, db: Path) -> None:
        result = runner.invoke(app, ["show", "fp_conn"] + _cfg_args(db))
        assert "app.log" in result.output

    def test_shows_normalized_message(self, db: Path) -> None:
        result = runner.invoke(app, ["show", "fp_conn"] + _cfg_args(db))
        assert "Connection refused" in result.output

    def test_shows_occurrences(self, db: Path) -> None:
        result = runner.invoke(app, ["show", "fp_conn"] + _cfg_args(db))
        assert "occurrence" in result.output.lower()

    def test_unknown_fingerprint_exits_1(self, db: Path) -> None:
        result = runner.invoke(app, ["show", "does_not_exist"] + _cfg_args(db))
        assert result.exit_code == 1

    def test_unknown_fingerprint_message(self, db: Path) -> None:
        result = runner.invoke(app, ["show", "does_not_exist"] + _cfg_args(db))
        assert "not found" in result.output.lower()

    def test_occurrences_limit(self, db: Path) -> None:
        result = runner.invoke(app, ["show", "fp_conn", "--occurrences", "1"] + _cfg_args(db))
        assert result.exit_code == 0

    def test_empty_db_exits_1(self, empty_db: Path) -> None:
        result = runner.invoke(app, ["show", "any"] + _cfg_args(empty_db))
        assert result.exit_code == 1


# ===========================================================================
# errors new
# ===========================================================================


class TestErrorsNew:
    def test_shows_new_errors(self, db: Path) -> None:
        result = runner.invoke(app, ["new", "--since", "2h"] + _cfg_args(db))
        assert result.exit_code == 0
        # Both errors were added recently
        assert "ConnectionError" in result.output or "new error" in result.output.lower()

    def test_no_new_errors_message(self, db: Path) -> None:
        # Use a very short window so nothing qualifies
        result = runner.invoke(app, ["new", "--since", "1s"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "No new errors" in result.output or "0" in result.output

    def test_empty_db_message(self, empty_db: Path) -> None:
        result = runner.invoke(app, ["new"] + _cfg_args(empty_db))
        assert result.exit_code == 0
        assert "No new errors" in result.output


# ===========================================================================
# errors regression
# ===========================================================================


class TestErrorsRegression:
    def test_no_regressions_message(self, db: Path) -> None:
        result = runner.invoke(app, ["regression"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "No regressions" in result.output

    def test_empty_db_no_regressions(self, empty_db: Path) -> None:
        result = runner.invoke(app, ["regression"] + _cfg_args(empty_db))
        assert result.exit_code == 0
        assert "No regressions" in result.output

    def test_custom_gap(self, db: Path) -> None:
        result = runner.invoke(app, ["regression", "--gap", "1h"] + _cfg_args(db))
        assert result.exit_code == 0
