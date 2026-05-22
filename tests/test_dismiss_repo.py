"""Tests for DismissRepository — false-positive / rule-suppression management."""

from __future__ import annotations

from pathlib import Path

import pytest

from logatory.storage.dismiss_repo import DismissRepository


@pytest.fixture()
def repo(tmp_path: Path) -> DismissRepository:
    r = DismissRepository(tmp_path / "test.db")
    r.open()
    yield r
    r.close()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_context_manager(self, tmp_path: Path) -> None:
        with DismissRepository(tmp_path / "ctx.db") as repo:
            assert repo._conn is not None

    def test_double_close_safe(self, tmp_path: Path) -> None:
        repo = DismissRepository(tmp_path / "dc.db")
        repo.open()
        repo.close()
        repo.close()  # should not raise


# ---------------------------------------------------------------------------
# dismiss()
# ---------------------------------------------------------------------------


class TestDismiss:
    def test_dismiss_returns_true_on_insert(self, repo: DismissRepository) -> None:
        assert repo.dismiss("SSH_BRUTE", source="auth.log") is True

    def test_dismiss_duplicate_returns_false(self, repo: DismissRepository) -> None:
        repo.dismiss("SSH_BRUTE", source="auth.log")
        assert repo.dismiss("SSH_BRUTE", source="auth.log") is False

    def test_dismiss_global_no_source(self, repo: DismissRepository) -> None:
        assert repo.dismiss("GLOBAL_RULE") is True

    def test_dismiss_with_reason(self, repo: DismissRepository) -> None:
        repo.dismiss("RULE_X", reason="false positive in test env")
        rows = repo.list_dismissed()
        assert any(r["reason"] == "false positive in test env" for r in rows)

    def test_dismiss_different_sources_independent(self, repo: DismissRepository) -> None:
        assert repo.dismiss("RULE_Y", source="a.log") is True
        assert repo.dismiss("RULE_Y", source="b.log") is True

    def test_dismiss_different_rules_independent(self, repo: DismissRepository) -> None:
        assert repo.dismiss("RULE_A") is True
        assert repo.dismiss("RULE_B") is True


# ---------------------------------------------------------------------------
# undismiss()
# ---------------------------------------------------------------------------


class TestUndismiss:
    def test_undismiss_existing_returns_true(self, repo: DismissRepository) -> None:
        repo.dismiss("RULE_DEL", source="app.log")
        assert repo.undismiss("RULE_DEL", source="app.log") is True

    def test_undismiss_nonexistent_returns_false(self, repo: DismissRepository) -> None:
        assert repo.undismiss("NONEXISTENT") is False

    def test_undismiss_removes_entry(self, repo: DismissRepository) -> None:
        repo.dismiss("RULE_RM")
        repo.undismiss("RULE_RM")
        assert repo.is_dismissed("RULE_RM") is False

    def test_undismiss_global_only_removes_global(self, repo: DismissRepository) -> None:
        repo.dismiss("RULE_PARTIAL")  # global
        repo.dismiss("RULE_PARTIAL", source="specific.log")
        repo.undismiss("RULE_PARTIAL")  # removes global only
        # specific source should still be dismissed
        assert repo.is_dismissed("RULE_PARTIAL", source="specific.log") is True


# ---------------------------------------------------------------------------
# is_dismissed()
# ---------------------------------------------------------------------------


class TestIsDismissed:
    def test_not_dismissed_initially(self, repo: DismissRepository) -> None:
        assert repo.is_dismissed("UNKNOWN_RULE") is False

    def test_dismissed_by_source(self, repo: DismissRepository) -> None:
        repo.dismiss("RULE_1", source="auth.log")
        assert repo.is_dismissed("RULE_1", source="auth.log") is True

    def test_dismissed_for_wrong_source(self, repo: DismissRepository) -> None:
        repo.dismiss("RULE_1", source="auth.log")
        assert repo.is_dismissed("RULE_1", source="other.log") is False

    def test_global_dismiss_suppresses_any_source(self, repo: DismissRepository) -> None:
        repo.dismiss("GLOBAL")  # no source = suppress all
        assert repo.is_dismissed("GLOBAL", source="auth.log") is True
        assert repo.is_dismissed("GLOBAL", source="web.log") is True
        assert repo.is_dismissed("GLOBAL") is True

    def test_specific_source_does_not_suppress_others(self, repo: DismissRepository) -> None:
        repo.dismiss("RULE_S", source="only.log")
        assert repo.is_dismissed("RULE_S", source="other.log") is False


# ---------------------------------------------------------------------------
# list_dismissed()
# ---------------------------------------------------------------------------


class TestListDismissed:
    def test_empty_initially(self, repo: DismissRepository) -> None:
        assert repo.list_dismissed() == []

    def test_returns_inserted_entries(self, repo: DismissRepository) -> None:
        repo.dismiss("A")
        repo.dismiss("B", source="x.log")
        rows = repo.list_dismissed()
        rule_ids = {r["rule_id"] for r in rows}
        assert rule_ids == {"A", "B"}

    def test_ordered_newest_first(self, repo: DismissRepository) -> None:
        import time

        repo.dismiss("FIRST")
        time.sleep(0.01)  # ensure distinct created_at timestamps
        repo.dismiss("SECOND")
        rows = repo.list_dismissed()
        assert rows[0]["rule_id"] == "SECOND"

    def test_contains_created_at(self, repo: DismissRepository) -> None:
        repo.dismiss("RULE_TS")
        row = repo.list_dismissed()[0]
        assert "created_at" in row
        assert row["created_at"] is not None

    def test_undismissed_rule_not_in_list(self, repo: DismissRepository) -> None:
        repo.dismiss("TEMP")
        repo.undismiss("TEMP")
        assert repo.list_dismissed() == []
