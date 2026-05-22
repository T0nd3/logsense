"""Tests for the fleet foundation — targets config loader and adapter factory."""

from __future__ import annotations

from pathlib import Path

import pytest

from logatory.fleet import (
    Target,
    TargetConfigError,
    build_adapter,
    load_targets,
    select_targets,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_targets(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "targets.yaml"
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Loading & validation
# ---------------------------------------------------------------------------


class TestLoadTargets:
    def test_loads_basic_targets(self, tmp_path):
        p = _write_targets(
            tmp_path,
            """
targets:
  - name: web01
    type: ssh
    host: web01.example
    journald: true
  - name: local
    type: journald
""",
        )
        targets = load_targets(p)
        assert [t.name for t in targets] == ["web01", "local"]
        assert targets[0].type == "ssh"
        assert targets[0].params["host"] == "web01.example"
        assert targets[0].params["journald"] is True

    def test_groups_parsed(self, tmp_path):
        p = _write_targets(
            tmp_path,
            """
targets:
  - name: web01
    type: ssh
    host: h
    groups: [web, prod]
""",
        )
        assert load_targets(p)[0].groups == ["web", "prod"]

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(TargetConfigError, match="not found"):
            load_targets(tmp_path / "nope.yaml")

    def test_no_targets_list_raises(self, tmp_path):
        p = _write_targets(tmp_path, "other: stuff\n")
        with pytest.raises(TargetConfigError, match="no 'targets:'"):
            load_targets(p)

    def test_missing_name_raises(self, tmp_path):
        p = _write_targets(tmp_path, "targets:\n  - type: journald\n")
        with pytest.raises(TargetConfigError, match="name"):
            load_targets(p)

    def test_invalid_type_raises(self, tmp_path):
        p = _write_targets(tmp_path, "targets:\n  - name: x\n    type: bogus\n")
        with pytest.raises(TargetConfigError, match="invalid type"):
            load_targets(p)

    def test_duplicate_name_raises(self, tmp_path):
        p = _write_targets(
            tmp_path,
            """
targets:
  - name: dup
    type: journald
  - name: dup
    type: journald
""",
        )
        with pytest.raises(TargetConfigError, match="duplicate"):
            load_targets(p)


# ---------------------------------------------------------------------------
# Environment-variable interpolation
# ---------------------------------------------------------------------------


class TestEnvInterpolation:
    def test_env_var_interpolated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FLEET_TEST_TOKEN", "s3cret")
        p = _write_targets(
            tmp_path,
            """
targets:
  - name: loki
    type: loki
    url: http://loki:3100
    token: ${FLEET_TEST_TOKEN}
""",
        )
        assert load_targets(p)[0].params["token"] == "s3cret"

    def test_missing_env_var_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FLEET_NOPE", raising=False)
        p = _write_targets(
            tmp_path,
            """
targets:
  - name: loki
    type: loki
    token: ${FLEET_NOPE}
""",
        )
        with pytest.raises(TargetConfigError, match="FLEET_NOPE"):
            load_targets(p)


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------


class TestSelectTargets:
    def _targets(self) -> list[Target]:
        return [
            Target("web01", "ssh", {}, ["web", "prod"]),
            Target("web02", "ssh", {}, ["web", "prod"]),
            Target("db01", "ssh", {}, ["db", "prod"]),
        ]

    def test_no_filter_returns_all(self):
        assert len(select_targets(self._targets())) == 3

    def test_select_by_name(self):
        sel = select_targets(self._targets(), names=["web01"])
        assert [t.name for t in sel] == ["web01"]

    def test_select_by_group(self):
        sel = select_targets(self._targets(), groups=["web"])
        assert {t.name for t in sel} == {"web01", "web02"}

    def test_unknown_name_raises(self):
        with pytest.raises(TargetConfigError, match="no target named"):
            select_targets(self._targets(), names=["nope"])

    def test_unknown_group_raises(self):
        with pytest.raises(TargetConfigError, match="group"):
            select_targets(self._targets(), groups=["nope"])


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------


class TestBuildAdapter:
    def test_file(self):
        from logatory.adapters.file import FileAdapter

        adapter = build_adapter(Target("f", "file", {"path": "/var/log/x.log"}))
        assert isinstance(adapter, FileAdapter)

    def test_journald(self):
        from logatory.adapters.journald import JournaldAdapter

        adapter = build_adapter(Target("j", "journald", {"unit": "nginx.service"}))
        assert isinstance(adapter, JournaldAdapter)
        assert adapter._unit == "nginx.service"

    def test_ssh(self):
        from logatory.adapters.ssh import SSHAdapter

        adapter = build_adapter(
            Target("s", "ssh", {"host": "web01", "journald": True, "port": 2222})
        )
        assert isinstance(adapter, SSHAdapter)
        assert adapter._host == "web01"
        assert adapter._port == 2222
        assert adapter._journald is True

    def test_loki(self):
        from logatory.adapters.loki import LokiAdapter

        adapter = build_adapter(Target("l", "loki", {"url": "http://loki:3100"}))
        assert isinstance(adapter, LokiAdapter)

    def test_graylog(self):
        from logatory.adapters.graylog import GraylogAdapter

        adapter = build_adapter(Target("g", "graylog", {"url": "http://gl:9000"}))
        assert isinstance(adapter, GraylogAdapter)

    def test_docker(self):
        from logatory.adapters.docker import DockerAdapter

        adapter = build_adapter(Target("d", "docker", {"name": "web"}))
        assert isinstance(adapter, DockerAdapter)

    def test_opensearch(self):
        from logatory.adapters.opensearch import OpenSearchAdapter

        adapter = build_adapter(Target("o", "opensearch", {"host": "es", "index": "logs-*"}))
        assert isinstance(adapter, OpenSearchAdapter)

    def test_ssh_missing_host_raises(self):
        with pytest.raises(TargetConfigError, match="host"):
            build_adapter(Target("s", "ssh", {}))

    def test_file_missing_path_raises(self):
        with pytest.raises(TargetConfigError, match="path"):
            build_adapter(Target("f", "file", {}))
