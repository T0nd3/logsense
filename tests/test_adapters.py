from pathlib import Path

from log_analyzer.adapters.file import FileAdapter
from log_analyzer.models import Severity

DATA_DIR = Path(__file__).parent / "data"


async def collect(adapter) -> list:
    return [e async for e in adapter.events()]


class TestFileAdapter:
    async def test_nginx_log_parses_all_lines(self, nginx_log):
        events = await collect(FileAdapter(nginx_log))
        assert len(events) == 7

    async def test_nginx_event_has_status_field(self, nginx_log):
        events = await collect(FileAdapter(nginx_log))
        assert all("status" in e.parsed_fields for e in events)

    async def test_nginx_500_is_error(self, nginx_log):
        events = await collect(FileAdapter(nginx_log))
        errors = [e for e in events if e.severity == Severity.ERROR]
        assert len(errors) == 1
        assert errors[0].parsed_fields["status"] == 500

    async def test_auth_log_parses(self, auth_log):
        events = await collect(FileAdapter(auth_log))
        assert len(events) == 7

    async def test_syslog_parses(self, syslog_log):
        events = await collect(FileAdapter(syslog_log))
        assert len(events) == 6

    async def test_json_log_parses(self, json_log):
        events = await collect(FileAdapter(json_log))
        assert len(events) == 6
        error_events = [e for e in events if e.severity == Severity.ERROR]
        assert len(error_events) == 1

    async def test_source_is_file_path(self, nginx_log):
        events = await collect(FileAdapter(nginx_log))
        assert all(str(nginx_log) in e.source for e in events)
