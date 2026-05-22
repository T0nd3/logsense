"""Tests for the browser fleet config editor."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from logatory.config import Config
from logatory.web.app import create_app
from logatory.web.fleet_config import read_targets, write_targets

# ---------------------------------------------------------------------------
# Raw targets.yaml read/write
# ---------------------------------------------------------------------------


class TestFleetConfigIO:
    def test_write_then_read(self, tmp_path):
        p = tmp_path / "targets.yaml"
        write_targets([{"name": "web01", "type": "ssh", "host": "h1"}], p)
        assert read_targets(p) == [{"name": "web01", "type": "ssh", "host": "h1"}]

    def test_read_missing_file(self, tmp_path):
        assert read_targets(tmp_path / "nope.yaml") == []

    def test_secret_reference_is_not_interpolated(self, tmp_path):
        p = tmp_path / "targets.yaml"
        p.write_text(
            "targets:\n  - name: l\n    type: loki\n    token: ${LOKI_TOKEN}\n",
            encoding="utf-8",
        )
        assert read_targets(p)[0]["token"] == "${LOKI_TOKEN}"


# ---------------------------------------------------------------------------
# Editor routes
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.chdir(tmp_path)  # targets.yaml is resolved relative to cwd
    cfg = Config(db_path=tmp_path / "test.db")
    with TestClient(create_app(cfg)) as c:
        yield c


@pytest.fixture()
def locked_client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.chdir(tmp_path)
    cfg = Config(db_path=tmp_path / "test.db", api_token="secret")
    with TestClient(create_app(cfg)) as c:
        yield c


class TestFleetPage:
    def test_page_renders(self, client: TestClient):
        r = client.get("/fleet")
        assert r.status_code == 200
        assert "Fleet" in r.text

    def test_fields_partial_for_ssh(self, client: TestClient):
        r = client.get("/api/fleet/fields?type=ssh")
        assert r.status_code == 200
        assert 'name="host"' in r.text


class TestFleetEditor:
    def test_add_target(self, client: TestClient, tmp_path):
        r = client.post(
            "/api/fleet/targets",
            data={"name": "web01", "type": "journald", "unit": "nginx.service", "groups": "web"},
        )
        assert r.status_code == 200
        targets = read_targets(tmp_path / "targets.yaml")
        assert len(targets) == 1
        assert targets[0]["name"] == "web01"
        assert targets[0]["unit"] == "nginx.service"
        assert targets[0]["groups"] == ["web"]

    def test_secret_field_becomes_env_reference(self, client: TestClient, tmp_path):
        r = client.post(
            "/api/fleet/targets", data={"name": "l", "type": "loki", "token": "LOKI_TOKEN"}
        )
        assert r.status_code == 200
        assert read_targets(tmp_path / "targets.yaml")[0]["token"] == "${LOKI_TOKEN}"

    def test_duplicate_name_rejected(self, client: TestClient, tmp_path):
        client.post("/api/fleet/targets", data={"name": "dup", "type": "journald"})
        r = client.post("/api/fleet/targets", data={"name": "dup", "type": "journald"})
        assert r.status_code == 200
        assert "already exists" in r.text
        assert len(read_targets(tmp_path / "targets.yaml")) == 1

    def test_delete_target(self, client: TestClient, tmp_path):
        client.post("/api/fleet/targets", data={"name": "gone", "type": "journald"})
        r = client.post("/api/fleet/delete", data={"name": "gone"})
        assert r.status_code == 200
        assert read_targets(tmp_path / "targets.yaml") == []


class TestFleetEditorLocked:
    def test_write_rejected_when_token_set(self, locked_client: TestClient):
        r = locked_client.post("/api/fleet/targets", data={"name": "x", "type": "journald"})
        assert r.status_code == 403

    def test_page_shows_readonly_notice(self, locked_client: TestClient):
        r = locked_client.get("/fleet")
        assert r.status_code == 200
        assert "disabled" in r.text.lower()
