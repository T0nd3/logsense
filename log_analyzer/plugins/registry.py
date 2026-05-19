"""Plugin registry — collects rules and PII patterns contributed by plugins."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from log_analyzer.rules.model import Rule


@dataclass
class PluginRegistry:
    """Accumulates contributions from all loaded plugins.

    Plugin authors call the ``add_*`` methods inside their ``register()``
    function; the host application then reads the collected lists.
    """

    #: Rules loaded from inline dicts (same schema as built-in YAML rules).
    rules: list[Rule] = field(default_factory=list)
    #: Extra YAML rule directories contributed by plugins.
    rule_dirs: list[Path] = field(default_factory=list)
    #: Extra PII pattern dicts ({name, pattern, prefix}).
    pii_patterns: list[dict] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Public plugin API
    # ------------------------------------------------------------------

    def add_rule(self, data: dict) -> None:
        """Register a rule from a dict (same schema as YAML rule files).

        Required keys: ``id``, ``title``, ``level``.
        Detection conditions go under ``detection.match``.

        Example::

            registry.add_rule({
                "id": "MY_RULE",
                "title": "My custom rule",
                "level": "high",
                "detection": {
                    "match": [{"field": "message", "op": "contains", "value": "BADWORD"}]
                },
            })
        """
        from log_analyzer.rules.loader import rule_from_dict

        rule = rule_from_dict(data, source_file="<plugin>")
        self.rules.append(rule)

    def add_rule_dir(self, path: Path | str) -> None:
        """Register a directory of YAML rule files to be loaded."""
        self.rule_dirs.append(Path(path))

    def add_pii_pattern(self, name: str, pattern: str, prefix: str = "redacted") -> None:
        """Register a custom PII regex pattern.

        Args:
            name:    Unique name (e.g. "employee_id").
            pattern: Python regex string.
            prefix:  Replacement prefix (e.g. "employee" → ``<employee_XYZ>``).
        """
        self.pii_patterns.append({"name": name, "pattern": pattern, "prefix": prefix})
