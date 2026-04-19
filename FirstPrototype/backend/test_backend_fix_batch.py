import io
import shutil
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import DATA_DIR, active_sessions, app, settings
from modules.agent import DFIRAgent
from modules.llm_provider import LLMProviderError
from modules.report import ReportGenerator
from modules.threat_intel import ThreatIntelToolkit


class FakeLLM:
    def __init__(self, response: str):
        self.response = response

    def invoke(self, prompt: str) -> str:
        return self.response


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class BackendFixBatchTest(unittest.TestCase):
    def setUp(self):
        active_sessions.clear()
        self.client = TestClient(app)
        self.original_max_upload_size_mb = settings.max_upload_size_mb

    def tearDown(self):
        settings.max_upload_size_mb = self.original_max_upload_size_mb
        for session_id in list(active_sessions):
            session_dir = DATA_DIR / session_id
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
        active_sessions.clear()

    def test_upload_rejects_oversized_file_with_client_error(self):
        settings.max_upload_size_mb = 0

        response = self.client.post(
            "/api/upload",
            files={"file": ("sample.log", b"1234567890", "text/plain")},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(active_sessions, {})

    def test_upload_sanitizes_filename_and_generates_unique_session_ids(self):
        response_one = self.client.post(
            "/api/upload",
            files={"file": ("../../bad name?.log", b"line 1", "text/plain")},
        )
        response_two = self.client.post(
            "/api/upload",
            files={"file": ("../../bad name?.log", b"line 2", "text/plain")},
        )

        payload_one = response_one.json()
        payload_two = response_two.json()

        self.assertEqual(response_one.status_code, 200)
        self.assertEqual(response_two.status_code, 200)
        self.assertEqual(payload_one["file_name"], "bad_name_.log")
        self.assertEqual(payload_two["file_name"], "bad_name_.log")
        self.assertNotEqual(payload_one["session_id"], payload_two["session_id"])

        stored_path = Path(active_sessions[payload_one["session_id"]]["file_path"])
        self.assertEqual(stored_path.name, "bad_name_.log")
        self.assertEqual(stored_path.parent.parent, DATA_DIR)

    def test_start_investigation_preserves_provider_readiness_as_client_error(self):
        active_sessions["session_test"] = {
            "file_name": "sample.log",
            "file_path": str(DATA_DIR / "session_test" / "sample.log"),
            "status": "uploaded",
            "stage": "pending",
        }

        with (
            patch(
                "modules.llm_settings_store.get_active_provider_snapshot",
                return_value={"provider": "ollama", "model": "demo"},
            ),
            patch(
                "modules.llm_provider.assert_provider_ready",
                side_effect=LLMProviderError("provider unavailable"),
            ),
        ):
            response = self.client.post("/api/investigate/session_test")

        self.assertEqual(response.status_code, 400)
        self.assertIn("provider unavailable", response.json()["detail"])

    def test_ioc_typing_rejects_filenames_and_keeps_valid_indicators(self):
        agent = DFIRAgent(llm=FakeLLM(""))

        self.assertIsNone(agent._identify_ioc_type("invoice.exe"))
        self.assertIsNone(agent._identify_ioc_type(r"C:\Temp\run.ps1"))
        self.assertIsNone(agent._identify_ioc_type("WScript.Shell"))
        self.assertIsNone(agent._identify_ioc_type("WScript.CreateObject"))
        self.assertIsNone(agent._identify_ioc_type("objShell.Run"))
        self.assertEqual(agent._identify_ioc_type("8.8.8.8"), "ip")
        self.assertEqual(agent._identify_ioc_type("https://example.com/payload"), "url")
        self.assertEqual(agent._identify_ioc_type("evil.example"), "domain")
        self.assertEqual(agent._identify_ioc_type("Api.Google.Com"), "domain")
        self.assertEqual(
            agent._identify_ioc_type(
                "5DE788D23B247B29F116CD0583280CE10A429E9F8C1D80C42DEAB20C6F4DBB4E"
            ),
            "sha256",
        )
        self.assertNotIn(
            "reserved_special_token",
            " ".join(agent._generate_default_recommendations({"tool_results": []})),
        )

    def test_agent_can_select_and_execute_all_six_threat_intel_tools(self):
        llm_response = "\n".join(
            [
                "ip:8.8.8.8 -> greynoise_lookup",
                "ip:8.8.8.8 -> threatfox_lookup",
                "domain:evil.example -> alienvault_otx_lookup",
                "domain:evil.example -> virustotal_lookup",
                "url:https://bad.example/payload.exe -> urlhaus_lookup",
                "sha256:5DE788D23B247B29F116CD0583280CE10A429E9F8C1D80C42DEAB20C6F4DBB4E -> malwarebazaar_lookup",
            ]
        )
        agent = DFIRAgent(llm=FakeLLM(llm_response))
        iocs = [
            {"type": "ip", "value": "8.8.8.8"},
            {"type": "domain", "value": "evil.example"},
            {"type": "url", "value": "https://bad.example/payload.exe"},
            {
                "type": "sha256",
                "value": "5DE788D23B247B29F116CD0583280CE10A429E9F8C1D80C42DEAB20C6F4DBB4E",
            },
        ]

        with redirect_stdout(io.StringIO()):
            selection = agent.select_tools({"iocs_extracted": iocs})
        tool_calls = selection["tool_calls"]
        self.assertEqual(
            {call["tool"] for call in tool_calls},
            {
                "greynoise_lookup",
                "threatfox_lookup",
                "alienvault_otx_lookup",
                "virustotal_lookup",
                "urlhaus_lookup",
                "malwarebazaar_lookup",
            },
        )

        agent.threat_intel.greynoise_lookup = lambda ioc: {
            "tool": "greynoise",
            "ip": ioc,
        }
        agent.threat_intel.threatfox_lookup = lambda ioc, ioc_type: {
            "tool": "threatfox",
            "ioc": ioc,
            "ioc_type": ioc_type,
        }
        agent.threat_intel.alienvault_otx_lookup = lambda ioc, ioc_type: {
            "tool": "alienvault_otx",
            "ioc": ioc,
            "ioc_type": ioc_type,
        }
        agent.threat_intel.virustotal_lookup = lambda ioc, ioc_type: {
            "tool": "virustotal",
            "ioc": ioc,
            "ioc_type": ioc_type,
        }
        agent.threat_intel.urlhaus_lookup = lambda ioc: {"tool": "urlhaus", "url": ioc}
        agent.threat_intel.malwarebazaar_lookup = lambda ioc: {
            "tool": "malwarebazaar",
            "hash": ioc,
        }

        with redirect_stdout(io.StringIO()):
            execution = agent.execute_tools({"tool_calls": tool_calls})
        self.assertEqual(len(execution["tool_results"]), 6)
        self.assertFalse(
            any("error" in result for result in execution["tool_results"]),
            execution["tool_results"],
        )

    def test_execute_tools_skips_invalid_or_unsupported_ioc_tool_calls(self):
        agent = DFIRAgent(llm=FakeLLM(""))

        agent.threat_intel.threatfox_lookup = lambda *_args, **_kwargs: self.fail(
            "ThreatFox should not be called for invalid IOC"
        )
        agent.threat_intel.greynoise_lookup = lambda *_args, **_kwargs: self.fail(
            "GreyNoise should not be called for unsupported IOC type"
        )

        tool_calls = [
            {
                "tool": "threatfox_lookup",
                "ioc": "WScript.Shell",
                "ioc_type": "domain",
            },
            {"tool": "greynoise_lookup", "ioc": "evil.example", "ioc_type": "domain"},
        ]

        with redirect_stdout(io.StringIO()):
            execution = agent.execute_tools({"tool_calls": tool_calls})

        self.assertEqual(len(execution["tool_results"]), 2)
        self.assertTrue(all(result.get("status") == "skipped" for result in execution["tool_results"]))
        self.assertTrue(all(result.get("skipped") is True for result in execution["tool_results"]))
        self.assertIn("failed validation", execution["tool_results"][0]["reason"])
        self.assertIn("does not support IOC type", execution["tool_results"][1]["reason"])

    def test_threatfox_lookup_returns_safe_empty_result_for_no_result_payload(self):
        toolkit = ThreatIntelToolkit(api_keys={})

        with patch(
            "modules.threat_intel.requests.post",
            return_value=FakeResponse({"query_status": "no_result", "data": ""}),
        ):
            with redirect_stdout(io.StringIO()):
                result = toolkit.threatfox_lookup("WScript.Shell", "domain")

        self.assertEqual(result["status"], "no_result")
        self.assertEqual(result["data"], [])
        self.assertIsNone(result["malware_family"])
        self.assertIsNone(result["confidence_level"])
        self.assertIsNone(result["threat_type"])

    def test_threatfox_lookup_returns_safe_empty_result_for_malformed_payload(self):
        toolkit = ThreatIntelToolkit(api_keys={})

        with patch(
            "modules.threat_intel.requests.post",
            return_value=FakeResponse("unexpected string payload"),
        ):
            with redirect_stdout(io.StringIO()):
                result = toolkit.threatfox_lookup("8.8.8.8", "ip")

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["data"], [])
        self.assertIsNone(result["malware_family"])
        self.assertIsNone(result["confidence_level"])
        self.assertIsNone(result["threat_type"])

    def test_report_uses_single_fallback_timestamp_for_missing_timeline_entries(self):
        generator = ReportGenerator()
        report = generator.generate_report(
            session_id="timeline-test",
            file_name="sample.evtx",
            investigation_state={
                "anomalies": [],
                "iocs_extracted": [],
                "tool_results": [],
                "attack_timeline": [
                    {"event_template": "Event A", "description": "First"},
                    {"event_template": "Event B", "description": "Second"},
                ],
                "investigation_summary": "Ringkasan investigasi yang cukup panjang untuk lolos validasi kualitas.",
                "recommendations": [],
            },
        )

        timestamps = [item["timestamp"] for item in report["attack_timeline"]]
        self.assertEqual(len(set(timestamps)), 1)
        self.assertEqual(timestamps[0], report["metadata"]["timestamp"])


if __name__ == "__main__":
    unittest.main()
