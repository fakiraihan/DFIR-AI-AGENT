"""Provider abstraction for local-first LLM routing."""

from __future__ import annotations

import json
import time
from typing import Any, Dict
from urllib import error, parse, request

from langchain_community.llms import Ollama


class LLMProviderError(RuntimeError):
    """Raised when a provider is misconfigured or unhealthy."""


class GeminiRuntimeClient:
    def __init__(self, model: str, api_key: str, temperature: float = 0.4):
        self.model = model
        self.api_key = api_key
        self.temperature = temperature

    def invoke(self, prompt: str) -> str:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={parse.quote(self.api_key)}"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": self.temperature},
        }
        data = _json_request(url, method="POST", body=payload)
        candidates = data.get("candidates", [])
        if not candidates:
            raise LLMProviderError("Gemini returned no candidates")
        parts = candidates[0].get("content", {}).get("parts", [])
        text_parts = [part.get("text", "") for part in parts if part.get("text")]
        return "\n".join(text_parts).strip()


class OpenRouterRuntimeClient:
    def __init__(
        self, base_url: str, model: str, api_key: str, temperature: float = 0.4
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.temperature = temperature

    def invoke(self, prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
        }
        data = _json_request(
            url,
            method="POST",
            body=payload,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        choices = data.get("choices", [])
        if not choices:
            raise LLMProviderError("OpenRouter returned no choices")
        message = choices[0].get("message", {})
        return str(message.get("content", "")).strip()


def _json_request(
    url: str,
    method: str = "GET",
    body: Dict[str, Any] | None = None,
    headers: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)

    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")

    req = request.Request(url, data=payload, headers=request_headers, method=method)
    try:
        with request.urlopen(req, timeout=10) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise LLMProviderError(f"HTTP {exc.code}: {detail or exc.reason}") from exc
    except error.URLError as exc:
        raise LLMProviderError(str(exc.reason)) from exc


def build_llm_client(provider_settings: Dict[str, Any], role: str = "agent") -> Any:
    provider = provider_settings.get("provider", "ollama")
    model = provider_settings.get("model")

    if not model:
        raise LLMProviderError(f"Model is required for provider '{provider}'")

    if provider == "ollama":
        base_url = provider_settings.get("base_url", "http://localhost:11434")
        temperature = 0.1
        return Ollama(
            base_url=base_url,
            model=model,
            temperature=temperature,
            top_p=0.7,
            top_k=20,
            num_ctx=4096,
            num_predict=2048,
            repeat_penalty=1.15,
        )

    if provider == "gemini":
        api_key = provider_settings.get("api_key", "")
        if not api_key:
            raise LLMProviderError("Gemini API key is not configured")
        return GeminiRuntimeClient(
            model=model, api_key=api_key, temperature=0.2 if role == "filter" else 0.4
        )

    if provider == "openrouter":
        api_key = provider_settings.get("api_key", "")
        if not api_key:
            raise LLMProviderError("OpenRouter API key is not configured")
        base_url = provider_settings.get("base_url", "https://openrouter.ai/api/v1")
        return OpenRouterRuntimeClient(
            base_url=base_url,
            model=model,
            api_key=api_key,
            temperature=0.2 if role == "filter" else 0.4,
        )

    raise LLMProviderError(f"Unsupported provider '{provider}'")


def check_provider_health(
    provider_name: str, provider_settings: Dict[str, Any]
) -> Dict[str, Any]:
    started_at = time.perf_counter()
    status: Dict[str, Any] = {
        "provider": provider_name,
        "configured": True,
        "ok": False,
        "latency_ms": None,
        "error": None,
        "model": provider_settings.get("model"),
    }

    try:
        if provider_name == "ollama":
            base_url = provider_settings.get(
                "base_url", "http://localhost:11434"
            ).rstrip("/")
            model = provider_settings.get("model")
            if not model:
                raise LLMProviderError("Ollama model is not configured")
            data = _json_request(f"{base_url}/api/tags")
            models = {item.get("name") for item in data.get("models", [])}
            status["reachable"] = True
            status["model_available"] = model in models
            if not status["model_available"]:
                raise LLMProviderError(f"Model '{model}' is not available in Ollama")

        elif provider_name == "gemini":
            api_key = provider_settings.get("api_key", "")
            model = provider_settings.get("model")
            if not api_key:
                status["configured"] = False
                raise LLMProviderError("Gemini API key is not configured")
            if not model:
                raise LLMProviderError("Gemini model is not configured")
            encoded_key = parse.quote(api_key)
            data = _json_request(
                f"https://generativelanguage.googleapis.com/v1beta/models?key={encoded_key}"
            )
            available_models = {
                item.get("name", "").split("/")[-1] for item in data.get("models", [])
            }
            status["model_available"] = model in available_models
            if not status["model_available"]:
                raise LLMProviderError(f"Model '{model}' is not available for Gemini")

        elif provider_name == "openrouter":
            api_key = provider_settings.get("api_key", "")
            model = provider_settings.get("model")
            base_url = provider_settings.get(
                "base_url", "https://openrouter.ai/api/v1"
            ).rstrip("/")
            if not api_key:
                status["configured"] = False
                raise LLMProviderError("OpenRouter API key is not configured")
            if not model:
                raise LLMProviderError("OpenRouter model is not configured")
            data = _json_request(
                f"{base_url}/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            model_ids = {item.get("id") for item in data.get("data", [])}
            status["model_available"] = model in model_ids
            if not status["model_available"]:
                raise LLMProviderError(
                    f"Model '{model}' is not available in OpenRouter"
                )
        else:
            raise LLMProviderError(f"Unsupported provider '{provider_name}'")

        status["ok"] = True
    except LLMProviderError as exc:
        status["error"] = str(exc)
    finally:
        status["latency_ms"] = round((time.perf_counter() - started_at) * 1000, 2)

    return status


def get_all_provider_health(effective_settings: Dict[str, Any]) -> Dict[str, Any]:
    providers = effective_settings.get("providers", {})
    statuses = {}
    for provider_name, provider_settings in providers.items():
        provider_snapshot = dict(provider_settings)
        provider_snapshot["provider"] = provider_name
        statuses[provider_name] = check_provider_health(
            provider_name, provider_snapshot
        )
    return statuses


def assert_provider_ready(provider_snapshot: Dict[str, Any]) -> Dict[str, Any]:
    status = check_provider_health(
        provider_snapshot.get("provider", "ollama"), provider_snapshot
    )
    if not status.get("ok"):
        raise LLMProviderError(
            status.get("error") or "Selected provider is unavailable"
        )
    return status
