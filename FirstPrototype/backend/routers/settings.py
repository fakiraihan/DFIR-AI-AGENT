"""LLM settings endpoints."""

from fastapi import APIRouter

from schemas.llm import LLMSettingsPayload


router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("/llm")
async def get_llm_settings():
    from modules.llm_settings_store import get_public_llm_settings

    return get_public_llm_settings()


@router.put("/llm")
async def update_llm_settings(payload: LLMSettingsPayload):
    from modules.llm_settings_store import update_llm_settings as persist_llm_settings

    return persist_llm_settings(payload.model_dump(exclude_none=True))


@router.get("/llm/status")
async def get_llm_provider_status():
    from modules.llm_provider import get_all_provider_health
    from modules.llm_settings_store import get_effective_llm_settings

    effective = get_effective_llm_settings()
    return {
        "selected_provider": effective.get("selected_provider", "ollama"),
        "providers": get_all_provider_health(effective),
    }
