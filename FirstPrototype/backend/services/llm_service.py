"""LLM provider readiness and client construction service."""

from importlib import import_module
from typing import Any


def get_ready_provider_snapshot() -> tuple[dict[str, Any], dict[str, Any]]:
    """Return active provider settings and readiness status or raise provider error."""
    llm_provider = import_module("modules.llm_provider")
    settings_store = import_module("modules.llm_settings_store")

    provider_snapshot = settings_store.get_active_provider_snapshot()
    provider_status = llm_provider.assert_provider_ready(provider_snapshot)
    return provider_snapshot, provider_status


def build_role_client(provider_snapshot: dict[str, Any], role: str = "agent") -> Any:
    """Build an LLM client for a specific pipeline role."""
    llm_provider = import_module("modules.llm_provider")

    return llm_provider.build_llm_client(provider_snapshot, role=role)
