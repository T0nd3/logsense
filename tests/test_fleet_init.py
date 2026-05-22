"""Tests for the `fleet init` interactive wizard."""

from __future__ import annotations

import yaml
from typer.testing import CliRunner

from logatory.cli.fleet_cmd import app
from logatory.fleet import load_targets

runner = CliRunner()


class TestFleetInit:
    def test_builds_an_ssh_target(self, tmp_path):
        out = tmp_path / "targets.yaml"
        # name, type, host, journald?, unit, path, port, identity, groups, another?
        feed = "web01\nssh\nweb01.example\nn\n\n/var/log/app.log\n\n\nweb\nn\n"
        result = runner.invoke(app, ["init", "-o", str(out)], input=feed)

        assert result.exit_code == 0
        data = yaml.safe_load(out.read_text(encoding="utf-8"))
        target = data["targets"][0]
        assert target["name"] == "web01"
        assert target["type"] == "ssh"
        assert target["host"] == "web01.example"
        assert target["path"] == "/var/log/app.log"
        assert target["groups"] == ["web"]
        # 'n' to journald and empty optionals are omitted
        assert "journald" not in target
        assert "unit" not in target

        # the generated file round-trips through the real loader
        loaded = load_targets(out)
        assert [t.name for t in loaded] == ["web01"]

    def test_secret_field_becomes_env_reference(self, tmp_path):
        out = tmp_path / "targets.yaml"
        # name, type, url(default), query(default), token-env-var, org_id, groups, another?
        feed = "prod-loki\nloki\n\n\nLOKI_TOKEN\n\n\nn\n"
        result = runner.invoke(app, ["init", "-o", str(out)], input=feed)

        assert result.exit_code == 0
        target = yaml.safe_load(out.read_text(encoding="utf-8"))["targets"][0]
        assert target["token"] == "${LOKI_TOKEN}"
        assert target["url"] == "http://localhost:3100"  # accepted default
        assert "LOKI_TOKEN" in result.output  # reminded to set the env var

    def test_existing_file_without_force_exits(self, tmp_path):
        out = tmp_path / "targets.yaml"
        out.write_text("targets: []\n", encoding="utf-8")
        result = runner.invoke(app, ["init", "-o", str(out)])
        assert result.exit_code == 1

    def test_force_overwrites(self, tmp_path):
        out = tmp_path / "targets.yaml"
        out.write_text("targets: []\n", encoding="utf-8")
        feed = "t1\nfile\n/var/log/x.log\n\nn\n"
        result = runner.invoke(app, ["init", "-o", str(out), "--force"], input=feed)

        assert result.exit_code == 0
        target = yaml.safe_load(out.read_text(encoding="utf-8"))["targets"][0]
        assert target["name"] == "t1"
        assert target["type"] == "file"
        assert target["path"] == "/var/log/x.log"
