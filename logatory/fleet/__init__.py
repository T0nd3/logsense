"""Fleet — pull logs from multiple configured targets at once."""

from .factory import build_adapter
from .schema import TYPE_FIELDS, Field
from .targets import Target, TargetConfigError, load_targets, select_targets

__all__ = [
    "TYPE_FIELDS",
    "Field",
    "Target",
    "TargetConfigError",
    "build_adapter",
    "load_targets",
    "select_targets",
]
