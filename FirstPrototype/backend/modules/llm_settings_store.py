"""Backend-local persistence for mutable LLM provider settings."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

from config import settings as env_settings


SECRET_FIELDS = {
    "gemini": {"api_key"},
    "openrouter": {"api_key"},
}


def _settings_file_path() -> Path:
    backend_dir = Path(__file__).resolve().parent.parent
    configured = Path(env_settings.llm_settings_path)
    if configured.is_absolute():
        return configured
    return (backend_dir / configured).resolve()


def _default_settings() -> Dict[str, Any]:
    return {
        "selected_provider": "ollama",
        "providers": {
            "ollama": {
                "enabled": True,
                "base_url": env_settings.ollama_base_url,
                "model": env_settings.ollama_model,
            },
            "gemini": {
                "enabled": False,
                "model": env_settings.gemini_model,
                "api_key": "",
            },
            "openrouter": {
                "enabled": False,
                "base_url": env_settings.openrouter_base_url,
                "model": env_settings.openrouter_model,
                "api_key": "",
            },
        },
    }


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _read_runtime_settings() -> Dict[str, Any]:
    path = _settings_file_path()
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def get_effective_llm_settings() -> Dict[str, Any]:
    return _deep_merge(_default_settings(), _read_runtime_settings())


def get_public_llm_settings() -> Dict[str, Any]:
    effective = deepcopy(get_effective_llm_settings())
    for provider_name, fields in SECRET_FIELDS.items():
        provider = effective["providers"].get(provider_name, {})
        for field in fields:
            secret_value = provider.pop(field, "")
            provider[f"has_{field}"] = bool(secret_value)
    return effective


def update_llm_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    current = get_effective_llm_settings()

    selected_provider = payload.get("selected_provider")
    if selected_provider:
        current["selected_provider"] = selected_provider

    providers_payload = payload.get("providers", {})
    for provider_name, provider_patch in providers_payload.items():
        provider = current["providers"].setdefault(provider_name, {})
        for key, value in provider_patch.items():
            if key.startswith("clear_"):
                secret_field = key.replace("clear_", "", 1)
                if value and secret_field in SECRET_FIELDS.get(provider_name, set()):
                    provider[secret_field] = ""
                continue

            if key in SECRET_FIELDS.get(provider_name, set()):
                if isinstance(value, str) and value.strip():
                    provider[key] = value.strip()
                continue

            provider[key] = value

    path = _settings_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return get_public_llm_settings()


def get_active_provider_snapshot() -> Dict[str, Any]:
    effective = get_effective_llm_settings()
    selected = effective.get("selected_provider", "ollama")
    providers = effective.get("providers", {})
    provider_config = deepcopy(providers.get(selected, {}))
    provider_config["provider"] = selected
    return provider_config
