"""Tests for the `fleet tail` command."""

from __future__ import annotations

import queue
from pathlib import Path

from typer.testing import CliRunner

from logatory.cli.fleet_cmd import _event_visible, _tail_worker, app
from logatory.models import Event, Severity

runner = CliRunner()


class _FakePollAdapter:
    """A poll()-only adapter that yields a finite set of events, then ends."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines

    async def poll(self, interval: float):
        for line in self._lines:
            yield Event(
                raw=line,
                source="fake",
                message=line,
                timestamp=None,
                severity=Severity.INFO,
                parsed_fields={},
            )


def _ev(severity: Severity) -> Event:
    return Event(
        raw="x", source="s", message="x", timestamp=None, severity=severity, parsed_fields={}
    )


def _targets_file(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "targets.yaml"
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Event visibility filter
# ---------------------------------------------------------------------------


class TestEventVisible:
    def test_show_events_always_visible(self):
        assert _event_visible(_ev(Severity.DEBUG), show_events=True, min_threshold=None) is True

    def test_default_hidden(self):
        assert _event_visible(_ev(Severity.ERROR), show_events=False, min_threshold=None) is False

    def test_min_severity_threshold(self):
        # error = 3, info = 1
        assert _event_visible(_ev(Severity.ERROR), False, 3) is True
        assert _event_visible(_ev(Severity.INFO), False, 3) is False


# ---------------------------------------------------------------------------
# Per-target poll worker
# ---------------------------------------------------------------------------


class TestTailWorker:
    def test_drains_poll_into_queue(self):
        q: queue.Queue = queue.Queue()
        _tail_worker("web01", _FakePollAdapter(["line one", "line two"]), 0.0, q)
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        assert [it[0] for it in items] == ["event", "event", "down"]
        assert items[0][2].parsed_fields["target"] == "web01"


# ---------------------------------------------------------------------------
# fleet tail command
# ---------------------------------------------------------------------------


class TestFleetTailCommand:
    def test_merges_targets_and_stops_when_all_down(self, tmp_path, monkeypatch):
        def _fake_build(target):
            return _FakePollAdapter([f"{target.name} one", f"{target.name} two"])

        monkeypatch.setattr("logatory.cli.fleet_cmd.build_adapter", _fake_build)
        tf = _targets_file(
            tmp_path,
            """
targets:
  - name: web01
    type: ssh
    host: h1
  - name: web02
    type: ssh
    host: h2
""",
        )
        result = runner.invoke(app, ["tail", "--targets", str(tf), "--no-rules", "--no-heartbeat"])
        assert result.exit_code == 0
        assert "All targets down" in result.output
        assert "Stopped." in result.output
        assert "Events   : 4" in result.output

    def test_file_only_fleet_has_nothing_to_tail(self, tmp_path):
        log = tmp_path / "a.log"
        log.write_text("x\n", encoding="utf-8")
        tf = _targets_file(
            tmp_path,
            f"""
targets:
  - name: local
    type: file
    path: {log.as_posix()}
""",
        )
        result = runner.invoke(app, ["tail", "--targets", str(tf)])
        assert result.exit_code == 1
