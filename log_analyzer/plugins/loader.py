"""Plugin discovery and loading."""
from __future__ import annotations

import importlib.util
import logging
from pathlib import Path

from .registry import PluginRegistry

logger = logging.getLogger(__name__)


def load_plugins(plugins_dir: Path | None) -> PluginRegistry:
    """Discover and load all plugins from *plugins_dir*.

    Each ``*.py`` file (excluding ``_``-prefixed names) is imported and its
    ``register(registry)`` function is called if present.

    Plugins that fail to load are logged as warnings — they never crash the
    main process.

    Returns:
        A :class:`PluginRegistry` populated by all successfully loaded plugins.
    """
    registry = PluginRegistry()
    if not plugins_dir or not plugins_dir.is_dir():
        return registry

    for path in sorted(plugins_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        _load_one(path, registry)

    return registry


def _load_one(path: Path, registry: PluginRegistry) -> None:
    module_name = f"logsense_plugin.{path.stem}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            logger.warning("Plugin %s: could not create module spec — skipped", path.name)
            return
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]

        if hasattr(mod, "register"):
            mod.register(registry)
            logger.info("Plugin loaded: %s", path.name)
        else:
            logger.debug("Plugin %s has no register() function — skipped", path.name)
    except Exception as exc:
        logger.warning("Plugin %s failed to load: %s", path.name, exc)
