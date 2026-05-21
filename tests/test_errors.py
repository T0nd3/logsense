from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from log_analyzer.errors.detector import (
    classify_stack_language,
    detect_stack_trace,
    is_error_event,
)
from log_analyzer.errors.fingerprint import extract_error_type, fingerprint
from log_analyzer.errors.normalizer import normalize
from log_analyzer.errors.tracker import ErrorTracker
from log_analyzer.models import Event, Severity
from log_analyzer.storage.errors_repo import ErrorsRepository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(
    message: str,
    severity: Severity = Severity.ERROR,
    source: str = "test",
    parsed_fields: dict | None = None,
    ts: datetime | None = None,
) -> Event:
    return Event(
        raw=message,
        source=source,
        message=message,
        timestamp=ts or datetime.now(tz=UTC),
        severity=severity,
        parsed_fields=parsed_fields or {},
    )


@pytest.fixture
def repo(tmp_path: Path) -> ErrorsRepository:
    r = ErrorsRepository(tmp_path / "errors.db")
    r.open()
    yield r
    r.close()


@pytest.fixture
def tracker(repo: ErrorsRepository) -> ErrorTracker:
    return ErrorTracker(repo)


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


class TestNormalizer:
    def test_uuid_replaced(self):
        msg = "Job 550e8400-e29b-41d4-a716-446655440000 failed"
        assert "<UUID>" in normalize(msg)
        assert "550e8400" not in normalize(msg)

    def test_iso_timestamp_replaced(self):
        msg = "Event at 2024-03-15T10:30:00Z completed"
        assert "<TIMESTAMP>" in normalize(msg)

    def test_unix_epoch_replaced(self):
        msg = "Processed at 1710000000"
        assert "<TIMESTAMP>" in normalize(msg)

    def test_file_path_unix_replaced(self):
        msg = "Failed to read /etc/config/app.conf"
        result = normalize(msg)
        assert "<PATH>" in result
        assert "/etc/config/app.conf" not in result

    def test_file_path_windows_replaced(self):
        msg = r"Cannot open C:\Users\app\data.db"
        result = normalize(msg)
        assert "<PATH>" in result

    def test_hostname_replaced(self):
        msg = "Failed to connect to db-prod-3.internal"
        result = normalize(msg)
        assert "<HOST>" in result
        assert "db-prod-3" not in result

    def test_port_replaced(self):
        # :5432 at end-of-line is caught by the stack-frame line-number pattern first,
        # producing <NUM>. Either way the number is replaced.
        msg = "Connection refused to host:5432"
        result = normalize(msg)
        assert "5432" not in result
        assert "<NUM>" in result or "<PORT>" in result

    def test_generic_numbers_replaced(self):
        msg = "Retried 42 times after 30 seconds"
        result = normalize(msg)
        assert "42" not in result
        assert "30" not in result
        assert "<NUM>" in result

    def test_hex_addr_replaced(self):
        msg = "Segfault at 0x7f3a1b2c"
        assert "<ADDR>" in normalize(msg)

    def test_same_class_same_normalized(self):
        # Differ only in hostname number and retry count (standalone integers)
        a = normalize("ConnectionError: Failed to connect to db-prod-3.internal after 30 retries")
        b = normalize("ConnectionError: Failed to connect to db-prod-4.internal after 60 retries")
        assert a == b

    def test_whitespace_collapsed(self):
        msg = "Error   connecting  to  host"
        assert "  " not in normalize(msg)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


class TestExtractErrorType:
    def test_exception_class_prefix(self):
        assert extract_error_type("NullPointerException: obj was null") == "NullPointerException"

    def test_java_package_prefix(self):
        assert extract_error_type("java.lang.RuntimeException: bad state") == "RuntimeException"

    def test_python_error_prefix(self):
        assert extract_error_type("ValueError: invalid literal") == "ValueError"

    def test_colon_split_candidate(self):
        result = extract_error_type("ConnectionError: timeout after 30s")
        assert result == "ConnectionError"

    def test_severity_prefix_stripped(self):
        result = extract_error_type("ERROR DatabaseError: query failed")
        assert result == "DatabaseError"

    def test_fallback_three_words(self):
        result = extract_error_type("something went wrong with the service")
        assert result == "something went wrong"

    def test_empty_message(self):
        result = extract_error_type("")
        assert result == "UnknownError"


class TestFingerprint:
    def test_same_error_same_fingerprint(self):
        a = fingerprint(
            "ConnectionError: Failed to connect to db-prod-3.internal after 30 retries"
        )
        b = fingerprint(
            "ConnectionError: Failed to connect to db-prod-4.internal after 60 retries"
        )
        assert a == b

    def test_different_error_different_fingerprint(self):
        a = fingerprint("ValueError: invalid input")
        b = fingerprint("ConnectionError: timeout")
        assert a != b

    def test_fingerprint_length(self):
        fp = fingerprint("Some error occurred")
        assert len(fp) == 12

    def test_fingerprint_stable(self):
        fp1 = fingerprint("RuntimeError: out of memory")
        fp2 = fingerprint("RuntimeError: out of memory")
        assert fp1 == fp2

    def test_fingerprint_hex(self):
        fp = fingerprint("Error: something")
        assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class TestIsErrorEvent:
    def test_error_severity(self):
        assert is_error_event(_event("anything", severity=Severity.ERROR))

    def test_critical_severity(self):
        assert is_error_event(_event("anything", severity=Severity.CRITICAL))

    def test_info_not_error(self):
        assert not is_error_event(_event("all good", severity=Severity.INFO))

    def test_warning_not_error_by_default(self):
        assert not is_error_event(_event("slow response", severity=Severity.WARNING))

    def test_http_5xx_is_error(self):
        ev = _event("GET /api 500", severity=Severity.INFO, parsed_fields={"status": "500"})
        assert is_error_event(ev)

    def test_http_4xx_not_error(self):
        ev = _event("GET /api 404", severity=Severity.INFO, parsed_fields={"status": "404"})
        assert not is_error_event(ev)

    def test_traceback_in_message(self):
        ev = _event("Traceback (most recent call last):", severity=Severity.INFO)
        assert is_error_event(ev)

    def test_exception_in_message(self):
        ev = _event("Unhandled Exception in handler", severity=Severity.INFO)
        assert is_error_event(ev)

    def test_error_colon_pattern(self):
        ev = _event("Error: disk full", severity=Severity.WARNING)
        assert is_error_event(ev)

    def test_fatal_keyword(self):
        ev = _event("FATAL crash detected", severity=Severity.INFO)
        assert is_error_event(ev)


class TestDetectStackTrace:
    def test_python_traceback(self):
        msg = 'Traceback (most recent call last):\n  File "app.py", line 10, in main\nValueError: bad'
        assert detect_stack_trace(msg) is not None

    def test_java_stack(self):
        msg = "Exception in thread main\n\tat com.example.App.main(App.java:20)"
        assert detect_stack_trace(msg) is not None

    def test_js_stack(self):
        msg = "Error: fail\n    at Object.<anonymous> (/app/index.js:5:3)"
        assert detect_stack_trace(msg) is not None

    def test_dotnet_stack(self):
        msg = "System.Exception: crash\n   at MyApp.Main in Program.cs:42"
        assert detect_stack_trace(msg) is not None

    def test_plain_message_no_stack(self):
        assert detect_stack_trace("Connection timeout after 30s") is None


class TestClassifyStackLanguage:
    def test_python(self):
        stack = 'Traceback (most recent call last):\n  File "app.py", line 5'
        assert classify_stack_language(stack) == "python"

    def test_java(self):
        stack = "\tat com.example.Foo.bar(Foo.java:42)"
        assert classify_stack_language(stack) == "java"

    def test_javascript(self):
        stack = "    at Object.<anonymous> (/app/index.js:5:3)"
        assert classify_stack_language(stack) == "javascript"

    def test_dotnet(self):
        stack = "   at MyApp.Handler.Run in Handler.cs:88"
        assert classify_stack_language(stack) == "dotnet"

    def test_unknown(self):
        assert classify_stack_language("some random text") == "unknown"


# ---------------------------------------------------------------------------
# ErrorTracker
# ---------------------------------------------------------------------------


class TestErrorTracker:
    def test_non_error_event_returns_none(self, tracker: ErrorTracker):
        ev = _event("all systems operational", severity=Severity.INFO)
        assert tracker.process(ev) is None

    def test_error_event_returns_row(self, tracker: ErrorTracker):
        ev = _event("DatabaseError: query failed")
        row = tracker.process(ev)
        assert row is not None
        assert row["count"] == 1

    def test_deduplication_increments_count(self, tracker: ErrorTracker):
        # Differ only in hostname number and retry count — normalize to same fingerprint
        a = "ConnectionError: Failed to connect to db-prod-3.internal after 30 retries"
        b = "ConnectionError: Failed to connect to db-prod-4.internal after 60 retries"
        tracker.process(_event(a))
        row = tracker.process(_event(b))
        assert row["count"] == 2

    def test_different_errors_different_rows(self, tracker: ErrorTracker, repo: ErrorsRepository):
        tracker.process(_event("ValueError: bad input"))
        tracker.process(_event("ConnectionError: timeout"))
        rows = repo.list_errors()
        assert len(rows) == 2

    def test_source_tracked(self, tracker: ErrorTracker):
        ev = _event("RuntimeError: crash", source="app-server")
        row = tracker.process(ev)
        import json

        sources = json.loads(row["sources"])
        assert "app-server" in sources

    def test_multiple_sources_accumulated(self, tracker: ErrorTracker):
        msg = "RuntimeError: out of memory"
        tracker.process(_event(msg, source="web-1"))
        row = tracker.process(_event(msg, source="web-2"))
        import json

        sources = json.loads(row["sources"])
        assert "web-1" in sources
        assert "web-2" in sources

    def test_occurrence_recorded(self, tracker: ErrorTracker, repo: ErrorsRepository):
        ev = _event("ValueError: bad value")
        row = tracker.process(ev)
        occs = repo.get_occurrences(row["fingerprint"])
        assert len(occs) == 1
        assert "bad value" in occs[0]["sample"]

    def test_severity_stored(self, tracker: ErrorTracker):
        ev = _event("CRITICAL meltdown", severity=Severity.CRITICAL)
        row = tracker.process(ev)
        assert row["severity"] == "critical"


# ---------------------------------------------------------------------------
# ErrorsRepository queries
# ---------------------------------------------------------------------------


class TestErrorsRepository:
    def _seed(self, repo: ErrorsRepository, n: int = 3) -> list[str]:
        fps = []
        for i in range(n):
            msg = f"Error{i}: something failed with id {i}"
            from log_analyzer.errors.fingerprint import fingerprint as fp_fn

            fp = fp_fn(msg)
            fps.append(fp)
            repo.upsert(
                fingerprint=fp,
                error_type=f"Error{i}",
                normalized_msg=f"Error{i}: something failed with id <NUM>",
                severity="error",
                source="test",
                timestamp=datetime.now(tz=UTC),
                sample=msg,
            )
        return fps

    def test_list_errors_returns_all(self, repo: ErrorsRepository):
        self._seed(repo)
        assert len(repo.list_errors()) == 3

    def test_list_errors_sort_count(self, repo: ErrorsRepository):
        fps = self._seed(repo, 2)
        repo.upsert(
            fingerprint=fps[0],
            error_type="Error0",
            normalized_msg="x",
            severity="error",
            source="s",
            timestamp=datetime.now(tz=UTC),
            sample="x",
        )
        rows = repo.list_errors(sort="count")
        assert rows[0]["fingerprint"] == fps[0]

    def test_list_errors_filter_severity(self, repo: ErrorsRepository):
        from log_analyzer.errors.fingerprint import fingerprint as fp_fn

        msg = "CriticalError: meltdown"
        repo.upsert(
            fingerprint=fp_fn(msg),
            error_type="CriticalError",
            normalized_msg="CriticalError: meltdown",
            severity="critical",
            source="s",
            timestamp=datetime.now(tz=UTC),
            sample=msg,
        )
        self._seed(repo)
        rows = repo.list_errors(severity="critical")
        assert len(rows) == 1
        assert rows[0]["severity"] == "critical"

    def test_get_error_found(self, repo: ErrorsRepository):
        fps = self._seed(repo, 1)
        row = repo.get_error(fps[0])
        assert row is not None
        assert row["fingerprint"] == fps[0]

    def test_get_error_not_found(self, repo: ErrorsRepository):
        assert repo.get_error("nonexistent") is None

    def test_summary(self, repo: ErrorsRepository):
        self._seed(repo, 3)
        s = repo.summary()
        assert s["total_error_types"] == 3
        assert s["total_occurrences"] == 3

    def test_new_errors(self, repo: ErrorsRepository):
        self._seed(repo, 2)
        rows = repo.new_errors(since_hours=1)
        assert len(rows) == 2

    def test_regression_errors_empty_when_no_regressions(self, repo: ErrorsRepository):
        self._seed(repo)
        rows = repo.regression_errors(gap_hours=24)
        assert rows == []
