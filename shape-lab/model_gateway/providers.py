"""Closed allowlist of upstream model providers for SHAPE agent runs."""

from __future__ import annotations

PROVIDERS = {
    "zai": {"host": "api.z.ai", "prefix": "/api/anthropic", "key_name": "ZAI_API_KEY"},
    "ollama": {"host": "ollama.com", "prefix": "", "key_name": "OLLAMA_API_KEY"},
}


def provider_spec(name: str) -> dict[str, str]:
    try:
        return PROVIDERS[name]
    except KeyError as exc:
        raise ValueError("Unsupported model provider") from exc
