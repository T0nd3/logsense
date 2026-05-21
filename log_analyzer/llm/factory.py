"""Factory functions that instantiate the right LLM client from config.

Two separate clients are returned:
  make_llm_client(cfg)   — text generation (explain, summarize, ask)
  make_embed_client(cfg) — embeddings for ChromaDB vector search

They may be the same object (Ollama) or different (Claude text + Ollama embed).
"""

from __future__ import annotations

import os

from ..config import LLMConfig
from .base import AbstractLLMClient

# Known default endpoints per provider
_DEFAULT_ENDPOINTS: dict[str, str] = {
    "openai": "https://api.openai.com",
    "groq": "https://api.groq.com/openai",
    "mistral": "https://api.mistral.ai",
    "lm_studio": "http://localhost:1234",
    "ollama": "http://localhost:11434",
}

# Env var names per provider (for API key lookup)
_API_KEY_ENV: dict[str, list[str]] = {
    "claude": ["ANTHROPIC_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "groq": ["GROQ_API_KEY"],
    "mistral": ["MISTRAL_API_KEY"],
}

_CLOUD_PROVIDERS = {"claude", "openai", "groq", "mistral"}


def _resolve_api_key(provider: str, cfg_key: str | None) -> str | None:
    """Return API key: config file > env vars > None."""
    if cfg_key:
        return cfg_key
    for env_var in _API_KEY_ENV.get(provider, []):
        val = os.environ.get(env_var)
        if val:
            return val
    return None


def _resolve_endpoint(provider: str, cfg_endpoint: str) -> str:
    """Return the base URL for the given provider.

    If the config still holds the default Ollama URL (http://localhost:11434)
    but the provider is something else, swap to that provider's default.
    """
    ollama_default = "http://localhost:11434"
    if cfg_endpoint and cfg_endpoint != ollama_default:
        return cfg_endpoint
    return _DEFAULT_ENDPOINTS.get(provider, cfg_endpoint)


# ---------------------------------------------------------------------------
# Text-generation client
# ---------------------------------------------------------------------------


def make_llm_client(cfg: LLMConfig) -> AbstractLLMClient:
    """Create a text-generation client from the LLM config section."""
    provider = cfg.provider.lower()
    api_key = _resolve_api_key(provider, cfg.api_key)
    endpoint = _resolve_endpoint(provider, cfg.endpoint)

    if provider == "ollama":
        from .client import OllamaClient

        return OllamaClient(
            endpoint=endpoint,
            model=cfg.model,
            temperature=cfg.temperature,
            max_context_tokens=cfg.max_context_tokens,
            embed_model=cfg.embed_model,
        )

    if provider == "claude":
        from .claude import ClaudeClient

        return ClaudeClient(
            api_key=api_key,
            model=cfg.model or "claude-haiku-4-5",
            temperature=cfg.temperature,
            max_tokens=cfg.max_context_tokens,
        )

    if provider in ("openai", "groq", "mistral", "lm_studio", "openai_compat"):
        from .openai_compat import OpenAICompatibleClient

        return OpenAICompatibleClient(
            endpoint=endpoint,
            model=cfg.model or "gpt-4o-mini",
            api_key=api_key,
            temperature=cfg.temperature,
            max_tokens=cfg.max_context_tokens,
            embed_model=cfg.embed_model or "text-embedding-3-small",
            is_cloud_provider=provider in _CLOUD_PROVIDERS,
        )

    raise ValueError(
        f"Unknown LLM provider: '{cfg.provider}'.\n"
        f"Supported: ollama, claude, openai, groq, mistral, lm_studio, openai_compat"
    )


# ---------------------------------------------------------------------------
# Embedding client (may differ from the text-generation client)
# ---------------------------------------------------------------------------


def make_embed_client(cfg: LLMConfig) -> AbstractLLMClient:
    """Create an embedding client.

    Uses cfg.embed_provider if set; falls back to cfg.provider.
    If the resolved provider doesn't support embeddings (e.g. Claude),
    returns the same client — embed() will return [] and vector search
    is skipped automatically.
    """
    embed_prov = (cfg.embed_provider or cfg.provider).lower()

    if embed_prov == "ollama":
        from .client import OllamaClient

        return OllamaClient(
            endpoint=_resolve_endpoint("ollama", cfg.endpoint),
            model=cfg.embed_model,
            embed_model=cfg.embed_model,
        )

    if embed_prov in ("openai", "openai_compat"):
        from .openai_compat import OpenAICompatibleClient

        api_key = _resolve_api_key(embed_prov, cfg.api_key)
        return OpenAICompatibleClient(
            endpoint=_resolve_endpoint(embed_prov, cfg.endpoint),
            model=cfg.embed_model or "text-embedding-3-small",
            api_key=api_key,
            embed_model=cfg.embed_model or "text-embedding-3-small",
            is_cloud_provider=(embed_prov == "openai"),
        )

    # For any other provider (including claude), just return the main client.
    # embed() will return [] → vector search gracefully disabled.
    return make_llm_client(cfg)
