"""Example Logatory plugin — demonstrates how to add custom rules and PII patterns.

Enable this plugin by setting in config.yaml:
    plugins_dir: plugins/

Or copy it to your own plugins directory and configure accordingly.
"""


def register(registry) -> None:
    """Called once at startup. Add rules and PII patterns to the registry."""

    # ── Custom detection rule ──────────────────────────────────────────
    # Same schema as built-in YAML rules.
    registry.add_rule(
        {
            "id": "CUSTOM_EXAMPLE",
            "title": "Example: custom trigger word",
            "description": "Fires when the message contains 'EXAMPLE_TRIGGER'. Replace with your pattern.",
            "level": "medium",
            "detection": {
                "match": [
                    {"field": "message", "op": "contains", "value": "EXAMPLE_TRIGGER"},
                ]
            },
        }
    )

    # ── Custom PII pattern ─────────────────────────────────────────────
    # Redacts strings matching the regex; replacement: <employee_XYZ123>
    registry.add_pii_pattern(
        name="employee_id",
        pattern=r"\bEMP-\d{4,8}\b",
        prefix="employee",
    )

    # Uncomment to load an entire directory of YAML rule files:
    # from pathlib import Path
    # registry.add_rule_dir(Path(__file__).parent / "my_rules")
