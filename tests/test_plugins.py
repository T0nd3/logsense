"""Tests for plugin loader and registry."""

from __future__ import annotations

from pathlib import Path

from logsense.plugins.loader import load_plugins
from logsense.plugins.registry import PluginRegistry

# ---------------------------------------------------------------------------
# PluginRegistry
# ---------------------------------------------------------------------------


class TestPluginRegistry:
    def test_empty_by_default(self) -> None:
        r = PluginRegistry()
        assert r.rules == []
        assert r.rule_dirs == []
        assert r.pii_patterns == []

    def test_add_rule(self) -> None:
        r = PluginRegistry()
        r.add_rule(
            {
                "id": "PLUGIN_RULE",
                "title": "Plugin test rule",
                "level": "high",
                "conditions": [{"field": "message", "op": "contains", "value": "BADWORD"}],
            }
        )
        assert len(r.rules) == 1
        assert r.rules[0].id == "PLUGIN_RULE"

    def test_add_rule_dir(self, tmp_path: Path) -> None:
        r = PluginRegistry()
        r.add_rule_dir(tmp_path)
        assert Path(tmp_path) in r.rule_dirs

    def test_add_rule_dir_string(self, tmp_path: Path) -> None:
        r = PluginRegistry()
        r.add_rule_dir(str(tmp_path))
        assert Path(tmp_path) in r.rule_dirs

    def test_add_pii_pattern(self) -> None:
        r = PluginRegistry()
        r.add_pii_pattern("employee_id", r"EMP-\d{6}", prefix="employee")
        assert len(r.pii_patterns) == 1
        p = r.pii_patterns[0]
        assert p["name"] == "employee_id"
        assert p["prefix"] == "employee"

    def test_add_pii_pattern_default_prefix(self) -> None:
        r = PluginRegistry()
        r.add_pii_pattern("secret", r"SECRET-\w+")
        assert r.pii_patterns[0]["prefix"] == "redacted"

    def test_multiple_rules(self) -> None:
        r = PluginRegistry()
        for i in range(3):
            r.add_rule(
                {
                    "id": f"RULE_{i}",
                    "title": f"Rule {i}",
                    "level": "low",
                    "conditions": [{"field": "message", "op": "contains", "value": str(i)}],
                }
            )
        assert len(r.rules) == 3


# ---------------------------------------------------------------------------
# load_plugins()
# ---------------------------------------------------------------------------


class TestLoadPlugins:
    def test_none_dir_returns_empty_registry(self) -> None:
        registry = load_plugins(None)
        assert registry.rules == []
        assert registry.pii_patterns == []

    def test_nonexistent_dir_returns_empty_registry(self, tmp_path: Path) -> None:
        registry = load_plugins(tmp_path / "does_not_exist")
        assert registry.rules == []

    def test_empty_dir_returns_empty_registry(self, tmp_path: Path) -> None:
        registry = load_plugins(tmp_path)
        assert registry.rules == []

    def test_loads_plugin_with_register_function(self, tmp_path: Path) -> None:
        plugin = tmp_path / "my_plugin.py"
        plugin.write_text(
            "def register(registry):\n"
            "    registry.add_pii_pattern('test_id', r'TEST-\\d+', prefix='test')\n"
        )
        registry = load_plugins(tmp_path)
        assert len(registry.pii_patterns) == 1
        assert registry.pii_patterns[0]["name"] == "test_id"

    def test_plugin_without_register_is_skipped_silently(self, tmp_path: Path) -> None:
        plugin = tmp_path / "no_register.py"
        plugin.write_text("# This plugin has no register() function\nX = 42\n")
        registry = load_plugins(tmp_path)
        assert registry.rules == []

    def test_underscore_files_ignored(self, tmp_path: Path) -> None:
        hidden = tmp_path / "_internal.py"
        hidden.write_text(
            "def register(registry):\n"
            "    registry.add_pii_pattern('hidden', r'HIDDEN', prefix='h')\n"
        )
        registry = load_plugins(tmp_path)
        assert registry.pii_patterns == []

    def test_broken_plugin_does_not_crash_loader(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.py"
        bad.write_text("raise RuntimeError('plugin error')\n")
        # Should not raise — bad plugins are logged and skipped
        registry = load_plugins(tmp_path)
        assert registry.rules == []

    def test_multiple_plugins_all_loaded(self, tmp_path: Path) -> None:
        for i in range(3):
            (tmp_path / f"plugin_{i}.py").write_text(
                f"def register(registry):\n"
                f"    registry.add_pii_pattern('pat_{i}', r'PAT{i}', prefix='p{i}')\n"
            )
        registry = load_plugins(tmp_path)
        assert len(registry.pii_patterns) == 3

    def test_plugin_adds_rule(self, tmp_path: Path) -> None:
        plugin = tmp_path / "rule_plugin.py"
        plugin.write_text(
            "def register(registry):\n"
            "    registry.add_rule({\n"
            "        'id': 'PLUGIN_RULE_01',\n"
            "        'title': 'Plugin Rule',\n"
            "        'level': 'medium',\n"
            "        'conditions': [{'field': 'message', 'op': 'contains', 'value': 'ALERT'}],\n"
            "    })\n"
        )
        registry = load_plugins(tmp_path)
        assert len(registry.rules) == 1
        assert registry.rules[0].id == "PLUGIN_RULE_01"
