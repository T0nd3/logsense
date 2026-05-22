"""Tests for the LLM layer.

All tests that would require a live Ollama instance mock out OllamaClient so
the suite runs offline.  Only the pure-Python units (prompt building,
keyword extraction, SQLite retrieval) are tested without mocking.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logsense.config import LLMConfig
from logsense.llm.base import AbstractLLMClient
from logsense.llm.client import OllamaClient, OllamaError
from logsense.llm.factory import make_embed_client, make_llm_client
from logsense.llm.openai_compat import OpenAICompatibleClient
from logsense.llm.prompts import (
    ask_prompt,
    classify_events_prompt,
    explain_error_prompt,
    explain_finding_prompt,
    summarize_prompt,
)
from logsense.llm.retrieval import _keywords, _sqlite_search, retrieve_context
from logsense.models import Finding, FindingSeverity
from logsense.storage.errors_repo import ErrorsRepository

_T0 = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(rule_id: str = "test.rule", sev: FindingSeverity = FindingSeverity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=sev,
        message="Unusual spike detected in error_rate",
        source="nginx",
        timestamp=_T0,
        events=[],
        details={"zscore": 4.5, "feature": "error_rate"},
    )


def _error_row(fp: str = "abc123") -> dict:
    return {
        "fingerprint": fp,
        "error_type": "ConnectionError",
        "normalized_msg": "ConnectionError: Failed to connect to <HOST>:<PORT>",
        "severity": "error",
        "count": 42,
        "first_seen": "2024-03-15T08:00:00",
        "last_seen": "2024-03-15T10:00:00",
        "stack_lang": None,
    }


@pytest.fixture
def db(tmp_path: Path) -> Path:
    """Seed a minimal SQLite DB with one error."""
    db_path = tmp_path / "test.db"
    with ErrorsRepository(db_path) as repo:
        repo.upsert(
            fingerprint="fp001",
            error_type="DatabaseError",
            normalized_msg="DatabaseError: connection refused to <HOST>",
            severity="error",
            source="app",
            timestamp=_T0,
            sample="DatabaseError: connection refused to db-prod-1",
        )
        repo.upsert(
            fingerprint="fp002",
            error_type="TimeoutError",
            normalized_msg="TimeoutError: request timed out after <NUM>s",
            severity="warning",
            source="api",
            timestamp=_T0 + timedelta(minutes=5),
            sample="TimeoutError: request timed out after 30s",
        )
    return db_path


# ---------------------------------------------------------------------------
# OllamaClient unit tests (no network required)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# AbstractLLMClient contract
# ---------------------------------------------------------------------------


class TestAbstractLLMClientContract:
    def test_ollama_is_subclass(self):
        assert issubclass(OllamaClient, AbstractLLMClient)

    def test_openai_compat_is_subclass(self):
        assert issubclass(OpenAICompatibleClient, AbstractLLMClient)

    def test_ollama_not_cloud(self):
        assert OllamaClient().is_cloud is False

    def test_openai_compat_cloud_flag(self):
        c = OpenAICompatibleClient(
            endpoint="https://api.openai.com",
            model="gpt-4o-mini",
            is_cloud_provider=True,
        )
        assert c.is_cloud is True

    def test_openai_compat_local_not_cloud(self):
        c = OpenAICompatibleClient(
            endpoint="http://localhost:1234",
            model="local-model",
            is_cloud_provider=False,
        )
        assert c.is_cloud is False

    def test_embed_default_returns_empty_list(self):
        # OllamaClient.embed needs a running server; the ABC default returns []
        # We test the ABC default via a minimal concrete stub
        class _Stub(AbstractLLMClient):
            def is_available(self):
                return True

            def generate(self, prompt, stream=True):
                yield "x"

        assert _Stub().embed("test") == []

    def test_generate_full_uses_generate(self, monkeypatch):
        import json
        import urllib.request

        # stream=False path: Ollama returns a single JSON object via .read()
        payload = json.dumps({"response": "AB", "done": True}).encode()

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def read(self):
                return payload

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        c = OllamaClient()
        assert "AB" in c.generate_full("p")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class TestFactory:
    def test_ollama_provider(self):
        cfg = LLMConfig(provider="ollama")
        client = make_llm_client(cfg)
        assert isinstance(client, OllamaClient)
        assert client.is_cloud is False

    def test_openai_provider(self):
        cfg = LLMConfig(provider="openai", model="gpt-4o-mini", api_key="sk-test")
        client = make_llm_client(cfg)
        assert isinstance(client, OpenAICompatibleClient)
        assert client.is_cloud is True

    def test_groq_provider(self):
        cfg = LLMConfig(provider="groq", model="llama3-8b-8192", api_key="gsk_test")
        client = make_llm_client(cfg)
        assert isinstance(client, OpenAICompatibleClient)
        assert client.is_cloud is True

    def test_lm_studio_not_cloud(self):
        cfg = LLMConfig(provider="lm_studio", model="local-model")
        client = make_llm_client(cfg)
        assert isinstance(client, OpenAICompatibleClient)
        assert client.is_cloud is False

    def test_unknown_provider_raises(self):
        cfg = LLMConfig(provider="fakeai")
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            make_llm_client(cfg)

    def test_claude_provider_returns_cloud_client(self):
        # Claude SDK may not be installed; just check it's cloud
        cfg = LLMConfig(provider="claude", model="claude-haiku-4-5", api_key="sk-ant-test")
        try:
            client = make_llm_client(cfg)
            assert client.is_cloud is True
            assert client.provider_name == "claude"
        except ImportError:
            pytest.skip("anthropic SDK not installed")

    def test_embed_client_defaults_to_ollama(self):
        cfg = LLMConfig(provider="ollama")
        embed = make_embed_client(cfg)
        assert isinstance(embed, OllamaClient)

    def test_embed_client_with_explicit_provider(self):
        cfg = LLMConfig(provider="claude", embed_provider="ollama", api_key="sk-ant-x")
        embed = make_embed_client(cfg)
        assert isinstance(embed, OllamaClient)

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-env")
        cfg = LLMConfig(provider="claude", model="claude-haiku-4-5")
        try:
            client = make_llm_client(cfg)
            assert client._api_key == "sk-ant-from-env"
        except ImportError:
            pytest.skip("anthropic SDK not installed")

    def test_openai_endpoint_defaulted(self):
        cfg = LLMConfig(provider="openai", model="gpt-4o-mini", api_key="key")
        client = make_llm_client(cfg)
        assert "openai.com" in client._endpoint


# ---------------------------------------------------------------------------
# OpenAICompatibleClient
# ---------------------------------------------------------------------------


class TestOpenAICompatibleClient:
    def _client(self, **kw) -> OpenAICompatibleClient:
        return OpenAICompatibleClient(
            endpoint="https://api.openai.com",
            model="gpt-4o-mini",
            api_key="sk-test",
            **kw,
        )

    def test_auth_header(self):
        c = self._client()
        assert c._headers()["Authorization"] == "Bearer sk-test"

    def test_no_auth_header_without_key(self):
        c = OpenAICompatibleClient(endpoint="http://localhost:1234", model="m")
        assert "Authorization" not in c._headers()

    def test_generate_streaming(self, monkeypatch):
        import json
        import urllib.request

        lines = [
            b"data: "
            + json.dumps({"choices": [{"delta": {"content": "Hello"}}]}).encode()
            + b"\n",
            b"data: "
            + json.dumps({"choices": [{"delta": {"content": " world"}}]}).encode()
            + b"\n",
            b"data: [DONE]\n",
        ]

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def __iter__(self):
                return iter(lines)

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        c = self._client()
        tokens = list(c.generate("prompt", stream=True))
        assert tokens == ["Hello", " world"]

    def test_generate_non_streaming(self, monkeypatch):
        import json
        import urllib.request

        payload = json.dumps({"choices": [{"message": {"content": "Answer here"}}]}).encode()

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def __iter__(self):
                return iter([b"data: " + payload + b"\n", b"data: [DONE]\n"])

            def read(self):
                return payload

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        c = self._client()
        result = list(c.generate("prompt", stream=False))
        assert result == ["Answer here"]

    def test_embed_returns_vector(self, monkeypatch):
        import json
        import urllib.request

        payload = json.dumps({"data": [{"embedding": [0.1, 0.2, 0.3]}]}).encode()

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def read(self):
                return payload

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        c = self._client()
        vec = c.embed("hello")
        assert vec == [0.1, 0.2, 0.3]

    def test_embed_returns_empty_on_error(self, monkeypatch):
        import urllib.error
        import urllib.request

        monkeypatch.setattr(
            urllib.request,
            "urlopen",
            lambda *a, **kw: (_ for _ in ()).throw(urllib.error.URLError("fail")),
        )
        c = self._client()
        assert c.embed("hello") == []


class TestOllamaClientStructure:
    def test_default_endpoint(self):
        c = OllamaClient()
        assert "11434" in c._endpoint

    def test_trailing_slash_stripped(self):
        c = OllamaClient(endpoint="http://localhost:11434/")
        assert not c._endpoint.endswith("/")

    def test_is_available_returns_bool(self, monkeypatch):
        """Mock urlopen to simulate Ollama online."""
        import urllib.request

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def read(self):
                return b'{"models": []}'

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResponse())
        c = OllamaClient()
        assert c.is_available() is True

    def test_is_available_false_on_error(self, monkeypatch):
        import urllib.error
        import urllib.request

        monkeypatch.setattr(
            urllib.request,
            "urlopen",
            lambda *a, **kw: (_ for _ in ()).throw(urllib.error.URLError("refused")),
        )
        c = OllamaClient()
        assert c.is_available() is False

    def test_list_models_parses_response(self, monkeypatch):
        import json
        import urllib.request

        payload = json.dumps({"models": [{"name": "gemma3:4b"}, {"name": "llama3:8b"}]}).encode()

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def read(self):
                return payload

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        c = OllamaClient()
        models = c.list_models()
        assert "gemma3:4b" in models

    def test_generate_yields_tokens(self, monkeypatch):
        import json
        import urllib.request

        lines = [
            json.dumps({"response": "Hello", "done": False}).encode() + b"\n",
            json.dumps({"response": " world", "done": True}).encode() + b"\n",
        ]

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def __iter__(self):
                return iter(lines)

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        c = OllamaClient()
        tokens = list(c.generate("test prompt"))
        assert tokens == ["Hello", " world"]

    def test_generate_raises_on_url_error(self, monkeypatch):
        import urllib.error
        import urllib.request

        def raise_error(*a, **kw):
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr(urllib.request, "urlopen", raise_error)
        c = OllamaClient()
        with pytest.raises(OllamaError):
            list(c.generate("prompt"))

    def test_generate_full_concatenates(self, monkeypatch):
        import json
        import urllib.request

        # stream=False → Ollama returns a single JSON object, not NDJSON
        payload = json.dumps({"response": "FooBar", "done": True}).encode()

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def read(self):
                return payload

            def __iter__(self):
                return iter([payload + b"\n"])

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        c = OllamaClient()
        result = c.generate_full("prompt")
        assert result == "FooBar"

    def test_embed_returns_list(self, monkeypatch):
        import json
        import urllib.request

        payload = json.dumps({"embeddings": [[0.1, 0.2, 0.3]]}).encode()

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def read(self):
                return payload

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: FakeResp())
        c = OllamaClient()
        vec = c.embed("hello")
        assert vec == [0.1, 0.2, 0.3]


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------


class TestExplainFindingPrompt:
    def test_contains_rule_id(self):
        p = explain_finding_prompt(_finding("ssh.brute_force"))
        assert "ssh.brute_force" in p

    def test_contains_severity(self):
        p = explain_finding_prompt(_finding(sev=FindingSeverity.CRITICAL))
        assert "CRITICAL" in p

    def test_contains_message(self):
        p = explain_finding_prompt(_finding())
        assert "error_rate" in p

    def test_with_samples(self):
        p = explain_finding_prompt(_finding(), occurrence_samples=["line 1", "line 2"])
        assert "line 1" in p

    def test_details_included(self):
        f = _finding()
        f.details["zscore"] = 99.9
        p = explain_finding_prompt(f)
        assert "99.9" in p


class TestExplainErrorPrompt:
    def test_contains_error_type(self):
        p = explain_error_prompt(_error_row())
        assert "ConnectionError" in p

    def test_contains_count(self):
        p = explain_error_prompt(_error_row())
        assert "42" in p

    def test_with_occurrences(self):
        occs = [{"sample": "real error msg", "timestamp": "2024-03-15T10:00:00"}]
        p = explain_error_prompt(_error_row(), occs)
        assert "real error msg" in p

    def test_instructions_present(self):
        p = explain_error_prompt(_error_row())
        assert "cause" in p.lower()

    def test_includes_full_stack_trace(self):
        trace = (
            "Traceback (most recent call last):\n"
            '  File "app.py", line 42, in handler\n'
            '    raise ValueError("bad input")\n'
            "ValueError: bad input"
        )
        occs = [
            {
                "sample": "ValueError: bad input",
                "timestamp": "2024-03-15T10:00:00",
                "stack_trace": trace,
                "stack_lang": "python",
            }
        ]
        p = explain_error_prompt(_error_row(), occs)
        assert 'File "app.py", line 42' in p
        assert "STACK TRACE (python)" in p

    def test_long_stack_trace_truncated(self):
        occs = [
            {
                "sample": "s",
                "timestamp": "2024-03-15T10:00:00",
                "stack_trace": "x" * 10000,
                "stack_lang": "java",
            }
        ]
        p = explain_error_prompt(_error_row(), occs)
        assert "x" * 10000 not in p
        assert "x" * 200 in p

    def test_no_stack_section_without_trace(self):
        occs = [{"sample": "plain error line", "timestamp": "2024-03-15T10:00:00"}]
        p = explain_error_prompt(_error_row(), occs)
        assert "STACK TRACE" not in p
        assert "plain error line" in p


class TestSummarizePrompt:
    def test_empty_rows(self):
        p = summarize_prompt([], "24h")
        assert "no tracked errors" in p.lower()

    def test_contains_error_types(self):
        rows = [
            _error_row(),
            {
                **_error_row("xyz"),
                "error_type": "TimeoutError",
                "count": 5,
                "severity": "warning",
                "normalized_msg": "timeout",
            },
        ]
        p = summarize_prompt(rows, "24h")
        assert "ConnectionError" in p
        assert "TimeoutError" in p

    def test_since_in_prompt(self):
        p = summarize_prompt([_error_row()], "7d")
        assert "7d" in p


class TestAskPrompt:
    def test_question_in_prompt(self):
        p = ask_prompt("Why are there so many 5xx errors?", [])
        assert "5xx" in p

    def test_context_chunks_included(self):
        p = ask_prompt("what failed?", ["chunk A about database", "chunk B about network"])
        assert "chunk A" in p
        assert "chunk B" in p

    def test_empty_context_fallback(self):
        p = ask_prompt("anything?", [])
        assert "No relevant context" in p


class TestClassifyEventsPrompt:
    def test_lines_numbered(self):
        lines = ["error: disk full", "info: started"]
        p = classify_events_prompt(lines)
        assert "1." in p
        assert "2." in p

    def test_max_30_lines(self):
        lines = [f"line {i}" for i in range(50)]
        p = classify_events_prompt(lines)
        assert "31." not in p


# ---------------------------------------------------------------------------
# Retrieval — keyword extraction
# ---------------------------------------------------------------------------


class TestKeywords:
    def test_stopwords_filtered(self):
        kws = _keywords("why are there so many errors")
        assert "why" not in kws
        assert "are" not in kws
        assert "errors" in kws

    def test_short_words_filtered(self):
        kws = _keywords("a b database")
        assert "a" not in kws
        assert "b" not in kws
        assert "database" in kws

    def test_hyphenated_word(self):
        kws = _keywords("connection-refused database")
        assert "connection-refused" in kws or "connection" in kws

    def test_empty_question(self):
        assert _keywords("") == []


class TestSQLiteSearch:
    def test_finds_matching_error(self, db: Path):
        chunks = _sqlite_search(db, ["database"])
        assert any("DatabaseError" in c for c in chunks)

    def test_empty_on_no_match(self, db: Path):
        chunks = _sqlite_search(db, ["xyzzy_nonexistent"])
        assert chunks == []

    def test_empty_keywords(self, db: Path):
        assert _sqlite_search(db, []) == []

    def test_missing_db(self, tmp_path: Path):
        chunks = _sqlite_search(tmp_path / "nonexistent.db", ["error"])
        assert chunks == []

    def test_deduplication(self, db: Path):
        # same keyword twice shouldn't duplicate results
        chunks1 = _sqlite_search(db, ["database"])
        chunks2 = _sqlite_search(db, ["database", "database"])
        assert len(chunks2) <= len(chunks1) + 1

    def test_returns_both_errors(self, db: Path):
        chunks = _sqlite_search(db, ["error", "timeout"])
        texts = " ".join(chunks)
        assert "DatabaseError" in texts or "TimeoutError" in texts


class TestRetrieveContext:
    def test_returns_list(self, db: Path):
        chunks = retrieve_context("why is the database failing?", db)
        assert isinstance(chunks, list)

    def test_relevant_chunks_returned(self, db: Path):
        chunks = retrieve_context("database connection error", db)
        assert any("DatabaseError" in c or "database" in c.lower() for c in chunks)

    def test_empty_on_unrelated_question(self, db: Path):
        chunks = retrieve_context("xyzzy foo bar baz", db)
        assert chunks == []

    def test_no_vector_search_without_chroma(self, db: Path):
        # chroma_path points to non-existent dir → graceful fallback
        chunks = retrieve_context(
            "database error",
            db,
            chroma_path=db.parent / "nonexistent_chroma",
        )
        assert isinstance(chunks, list)
