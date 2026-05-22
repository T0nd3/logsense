"""Tests for the `fleet scan` command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from logatory.cli.fleet_cmd import _fetch_target, app
from logatory.fleet import Target

runner = CliRunner()


def _log_file(tmp_path: Path, name: str, lines: list[str]) -> Path:
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _targets_file(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "targets.yaml"
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Per-target fetch (worker-thread unit)
# ---------------------------------------------------------------------------


class TestFetchTarget:
    def test_fetches_file_target(self, tmp_path):
        log = _log_file(tmp_path, "a.log", ["hello world", "second line"])
        result = _fetch_target(Target("alpha", "file", {"path": log.as_posix()}))
        assert result.error is None
        assert len(result.events) == 2
        assert all(e.parsed_fields["target"] == "alpha" for e in result.events)

    def test_failure_is_isolated(self, tmp_path):
        # a nonexistent file makes the adapter raise — it must be captured
        missing = (tmp_path / "nope.log").as_posix()
        result = _fetch_target(Target("ghost", "file", {"path": missing}))
        assert result.error is not None
        assert result.events == []


# ---------------------------------------------------------------------------
# fleet scan command
# ---------------------------------------------------------------------------


class TestFleetScanCommand:
    def test_scans_multiple_targets(self, tmp_path):
        a = _log_file(tmp_path, "a.log", ["alpha one", "alpha two"])
        b = _log_file(tmp_path, "b.log", ["beta one"])
        tf = _targets_file(
            tmp_path,
            f"""
targets:
  - name: alpha
    type: file
    path: {a.as_posix()}
  - name: beta
    type: file
    path: {b.as_posix()}
""",
        )
        result = runner.invoke(app, ["scan", "--targets", str(tf), "--no-rules"])
        assert result.exit_code == 0
        assert "Fleet scan" in result.output
        assert "alpha" in result.output and "beta" in result.output
        assert "2 ok" in result.output

    def test_dead_target_does_not_abort(self, tmp_path):
        a = _log_file(tmp_path, "a.log", ["alpha one"])
        tf = _targets_file(
            tmp_path,
            f"""
targets:
  - name: alpha
    type: file
    path: {a.as_posix()}
  - name: ghost
    type: file
    path: {(tmp_path / "missing.log").as_posix()}
""",
        )
        result = runner.invoke(app, ["scan", "--targets", str(tf), "--no-rules"])
        assert result.exit_code == 0
        assert "1 ok" in result.output
        assert "1 failed" in result.output

    def test_group_selection(self, tmp_path):
        a = _log_file(tmp_path, "a.log", ["x"])
        b = _log_file(tmp_path, "b.log", ["y"])
        tf = _targets_file(
            tmp_path,
            f"""
targets:
  - name: alpha
    type: file
    path: {a.as_posix()}
    groups: [web]
  - name: beta
    type: file
    path: {b.as_posix()}
    groups: [db]
""",
        )
        result = runner.invoke(app, ["scan", "--targets", str(tf), "--group", "web", "--no-rules"])
        assert result.exit_code == 0
        assert "1 target(s)" in result.output
        assert "alpha" in result.output

    def test_missing_targets_file_exits_nonzero(self, tmp_path):
        result = runner.invoke(app, ["scan", "--targets", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 1
