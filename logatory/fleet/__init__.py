"""Fleet — pull logs from multiple configured targets at once."""

from .factory import build_adapter
from .targets import Target, TargetConfigError, load_targets, select_targets

__all__ = [
    "Target",
    "TargetConfigError",
    "build_adapter",
    "load_targets",
    "select_targets",
]
