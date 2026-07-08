from importlib import import_module
import unittest
from unittest.mock import patch

llm_provider = import_module("modules.llm_provider")


class FakeJsonResponse:
    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return False

    def read(self):
        return b"{}"


class LLMProviderHealthTest(unittest.TestCase):
    def test_json_request_uses_explicit_api_client_headers(self):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["headers"] = req.headers
            captured["timeout"] = timeout
            return FakeJsonResponse()

        with patch("modules.llm_provider.request.urlopen", side_effect=fake_urlopen):
            llm_provider._json_request(
                "https://example.test/v1/models",
                headers={"Authorization": "Bearer test-key"},
            )

        headers = captured["headers"]
        self.assertIn("User-agent", headers)
        self.assertNotIn("Python-urllib", headers["User-agent"])
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(headers["Authorization"], "Bearer test-key")
        self.assertEqual(captured["timeout"], 10)

    def test_ollama_health_accepts_latest_tag_for_untagged_model(self):
        with patch(
            "modules.llm_provider._json_request",
            return_value={"models": [{"name": "foundation-sec-8b:latest"}]},
        ):
            status = llm_provider.check_provider_health(
                "ollama",
                {
                    "provider": "ollama",
                    "base_url": "http://localhost:11434",
                    "model": "foundation-sec-8b",
                },
            )

        self.assertTrue(status["ok"])
        self.assertTrue(status["model_available"])

    def test_ollama_health_reads_model_field_from_tags_response(self):
        with patch(
            "modules.llm_provider._json_request",
            return_value={"models": [{"model": "sec-foundation:8b-gpu"}]},
        ):
            status = llm_provider.check_provider_health(
                "ollama",
                {
                    "provider": "ollama",
                    "base_url": "http://localhost:11434",
                    "model": "sec-foundation:8b-gpu",
                },
            )

        self.assertTrue(status["ok"])
        self.assertEqual(status["available_models"], ["sec-foundation:8b-gpu"])

    def test_all_provider_health_returns_error_status_when_probe_crashes(self):
        with patch(
            "modules.llm_provider.check_provider_health",
            side_effect=ValueError("bad provider response"),
        ):
            statuses = llm_provider.get_all_provider_health(
                {
                    "providers": {
                        "ollama": {
                            "base_url": "http://localhost:11434",
                            "model": "demo",
                        }
                    }
                }
            )

        self.assertFalse(statuses["ollama"]["ok"])
        self.assertIn("bad provider response", statuses["ollama"]["error"])

    def test_groq_client_posts_chat_completion_payload_without_reasoning_effort(self):
        captured = {}

        def fake_json_request(url, method="GET", body=None, headers=None):
            captured["url"] = url
            captured["method"] = method
            captured["body"] = body
            captured["headers"] = headers
            return {"choices": [{"message": {"content": "done"}}]}

        with patch("modules.llm_provider._json_request", side_effect=fake_json_request):
            client = llm_provider.build_llm_client(
                {
                    "provider": "groq",
                    "base_url": "https://api.groq.com/openai/v1",
                    "model": "groq/compound",
                    "api_key": "test-key",
                    "max_completion_tokens": 2048,
                    "reasoning_effort": "medium",
                }
            )
            response = client.invoke("hello")

        self.assertEqual(response, "done")
        self.assertEqual(
            captured["url"], "https://api.groq.com/openai/v1/chat/completions"
        )
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["headers"], {"Authorization": "Bearer test-key"})
        self.assertEqual(captured["body"]["model"], "groq/compound")
        self.assertEqual(captured["body"]["max_completion_tokens"], 2048)
        self.assertNotIn("reasoning_effort", captured["body"])

    def test_groq_health_checks_model_catalog(self):
        with patch(
            "modules.llm_provider._json_request",
            return_value={"data": [{"id": "groq/compound"}]},
        ):
            status = llm_provider.check_provider_health(
                "groq",
                {
                    "provider": "groq",
                    "base_url": "https://api.groq.com/openai/v1",
                    "model": "groq/compound",
                    "api_key": "test-key",
                },
            )

        self.assertTrue(status["ok"])
        self.assertTrue(status["model_available"])


if __name__ == "__main__":
    _ = unittest.main()
