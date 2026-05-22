"""Tests for the `fleet list` command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from logatory.cli.fleet_cmd import _probe, app
from logatory.fleet import Target

runner = CliRunner()


def _targets_file(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "targets.yaml"
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Reachability probe
# ---------------------------------------------------------------------------


class TestProbe:
    def test_file_target_reachable(self, tmp_path):
        log = tmp_path / "a.log"
        log.write_text("x\n", encoding="utf-8")
        ok, _ = _probe(Target("t", "file", {"path": str(log)}), 5.0)
        assert ok is True

    def test_file_target_unreachable(self, tmp_path):
        ok, detail = _probe(Target("t", "file", {"path": str(tmp_path / "missing.log")}), 5.0)
        assert ok is False
        assert detail


# ---------------------------------------------------------------------------
# fleet list command
# ---------------------------------------------------------------------------


class TestFleetListCommand:
    def test_lists_targets(self, tmp_path):
        tf = _targets_file(
            tmp_path,
            """
targets:
  - name: web01
    type: ssh
    host: h1
    groups: [web]
  - name: local
    type: journald
""",
        )
        result = runner.invoke(app, ["list", "--targets", str(tf)])
        assert result.exit_code == 0
        assert "web01" in result.output
        assert "local" in result.output
        assert "2 target(s)" in result.output

    def test_check_reports_reachability(self, tmp_path):
        log = tmp_path / "a.log"
        log.write_text("x\n", encoding="utf-8")
        tf = _targets_file(
            tmp_path,
            f"""
targets:
  - name: present
    type: file
    path: {log.as_posix()}
  - name: missing
    type: file
    path: {(tmp_path / "nope.log").as_posix()}
""",
        )
        result = runner.invoke(app, ["list", "--targets", str(tf), "--check"])
        assert result.exit_code == 0
        assert "1 reachable" in result.output
        assert "1 unreachable" in result.output

    def test_group_selection(self, tmp_path):
        tf = _targets_file(
            tmp_path,
            """
targets:
  - name: web01
    type: journald
    groups: [web]
  - name: db01
    type: journald
    groups: [db]
""",
        )
        result = runner.invoke(app, ["list", "--targets", str(tf), "--group", "web"])
        assert result.exit_code == 0
        assert "web01" in result.output
        assert "1 target(s)" in result.output

    def test_missing_targets_file_exits_nonzero(self, tmp_path):
        result = runner.invoke(app, ["list", "--targets", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 1
