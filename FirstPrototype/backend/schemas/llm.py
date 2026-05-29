"""Schemas for LLM settings endpoints."""

from pydantic import BaseModel, Field


class ProviderSettingsPayload(BaseModel):
    enabled: bool | None = None
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    num_ctx: int | None = None
    num_predict: int | None = None
    max_tokens: int | None = None
    max_output_tokens: int | None = None
    clear_api_key: bool = False


class LLMSettingsPayload(BaseModel):
    selected_provider: str = Field(pattern="^(ollama|gemini|openrouter)$")
    providers: dict[str, ProviderSettingsPayload] = Field(default_factory=dict)
