import io
import json
import pickle
import shutil
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pandas as pd
import torch
from fastapi.testclient import TestClient

from main import (
    DATA_DIR,
    _parse_with_profile,
    _resolve_config_path,
    app,
    session_store,
    settings,
)
from logadempirical.data.vocab import Vocab
from logadempirical.models.lstm import DeepLog
from session_store import SessionStore
from modules.agent import DFIRAgent
from modules.anomaly import DeepLogDetector
from modules.gate_observations import append_gate_observations, summarize_downstream_metrics
from modules.llm_provider import LLMProviderError
from modules.parsing import parse_log_file
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
        session_store.clear()
        self.client = TestClient(app)
        self.original_max_upload_size_mb = settings.max_upload_size_mb

    def tearDown(self):
        settings.max_upload_size_mb = self.original_max_upload_size_mb
        for session_id in list(session_store):
            session_dir = DATA_DIR / session_id
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
        session_store.clear()

    def test_upload_rejects_oversized_file_with_client_error(self):
        settings.max_upload_size_mb = 0

        response = self.client.post(
            "/api/upload",
            files={"file": ("sample.log", b"1234567890", "text/plain")},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(len(session_store), 0)

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

        stored_path = Path(
            session_store.get_session(payload_one["session_id"], touch=False)["file_path"]
        )
        self.assertEqual(stored_path.name, "bad_name_.log")
        self.assertEqual(stored_path.parent.parent, DATA_DIR)

    def test_start_investigation_preserves_provider_readiness_as_client_error(self):
        session_store.set_session("session_test", {
            "file_name": "sample.log",
            "file_path": str(DATA_DIR / "session_test" / "sample.log"),
            "status": "uploaded",
            "stage": "pending",
        })

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

    def test_session_store_persists_and_cleans_stale_raw_log_directories(self):
        cache_dir = DATA_DIR.parent / "test_session_store_cache"
        raw_logs_dir = DATA_DIR.parent / "test_session_store_raw_logs"
        shutil.rmtree(cache_dir, ignore_errors=True)
        shutil.rmtree(raw_logs_dir, ignore_errors=True)
        raw_logs_dir.mkdir(parents=True, exist_ok=True)

        try:
            store = SessionStore(cache_dir, raw_logs_dir, session_timeout_minutes=1)
            store.set_session("persisted", {"status": "uploaded"})

            reopened = SessionStore(cache_dir, raw_logs_dir, session_timeout_minutes=1)
            self.assertEqual(
                reopened.get_session("persisted", touch=False),
                {"status": "uploaded"},
            )

            active_dir = raw_logs_dir / "persisted"
            stale_dir = raw_logs_dir / "stale_session"
            active_dir.mkdir(exist_ok=True)
            stale_dir.mkdir(exist_ok=True)

            stale_timestamp = datetime.now().timestamp() - 3600
            import os

            os.utime(stale_dir, (stale_timestamp, stale_timestamp))
            reopened.cleanup_expired_sessions()

            self.assertTrue(active_dir.exists())
            self.assertFalse(stale_dir.exists())
        finally:
            shutil.rmtree(cache_dir, ignore_errors=True)
            shutil.rmtree(raw_logs_dir, ignore_errors=True)

    def test_parse_csv_falls_back_to_local_drain_when_training_workspace_missing(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write("TimeGenerated,Message\n")
            tmp.write('2026-04-21T10:00:00Z,"Process started pid=1234 user=alice"\n')
            tmp.write('2026-04-21T10:00:01Z,"Process started pid=5678 user=bob"\n')
            csv_path = tmp.name

        try:
            with patch(
                "modules.parsing._resolve_training_workspace",
                side_effect=FileNotFoundError("missing workspace"),
            ):
                parsed_df, templates = parse_log_file(csv_path)

            self.assertEqual(len(parsed_df), 2)
            self.assertGreaterEqual(len(templates), 1)
            self.assertIn("event_template", parsed_df.columns)
            self.assertIn("parameter_map", parsed_df.columns)
        finally:
            Path(csv_path).unlink(missing_ok=True)

    def test_parse_with_profile_keeps_general_for_non_sysmon_logs(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write("TimeGenerated,Message\n")
            tmp.write('2026-04-21T10:00:00Z,"Windows Event Log started"\n')
            tmp.write('2026-04-21T10:00:01Z,"Service Control Manager event"\n')
            csv_path = tmp.name

        try:
            parsed_df, templates, profile = _parse_with_profile(csv_path, settings, max_lines=50)
            self.assertEqual(profile["name"], "general")
            self.assertEqual(profile["template_strategy"], settings.parser_template_strategy)
            self.assertGreaterEqual(len(parsed_df), 2)
            self.assertGreaterEqual(len(templates), 1)
        finally:
            Path(csv_path).unlink(missing_ok=True)

    def test_general_profile_uses_lmd2023_artifacts(self):
        model_path = _resolve_config_path(settings.deeplog_model_path)
        vocab_path = _resolve_config_path(settings.deeplog_vocab_path)

        self.assertIn("lmd2023", str(model_path).lower())
        self.assertIn("lmd2023", str(vocab_path).lower())
        self.assertTrue(model_path.exists())
        self.assertTrue(vocab_path.exists())

    def test_parse_with_profile_switches_to_sysmon_for_evtx_rows(self):
        first_parse = pd.DataFrame(
            [
                {"raw_line": "Microsoft-Windows-Sysmon EventID=1", "event_template": "tmp1"},
                {"raw_line": "Microsoft-Windows-Sysmon EventID=11", "event_template": "tmp2"},
            ]
        )
        sysmon_parse = pd.DataFrame(
            [
                {
                    "raw_line": "Microsoft-Windows-Sysmon EventID=1",
                    "event_template": "Microsoft-Windows-Sysmon EventID=1",
                }
            ]
        )

        with patch(
            "modules.parsing.parse_log_file",
            side_effect=[(first_parse, ["general-template"]), (sysmon_parse, ["sysmon-template"])],
        ) as mock_parse:
            parsed_df, templates, profile = _parse_with_profile("sample.evtx", settings, max_lines=10)

        self.assertEqual(profile["name"], "sysmon")
        self.assertEqual(profile["template_strategy"], settings.sysmon_parser_template_strategy)
        self.assertEqual(parsed_df.iloc[0]["event_template"], "Microsoft-Windows-Sysmon EventID=1")
        self.assertEqual(templates, ["sysmon-template"])
        self.assertEqual(mock_parse.call_count, 2)

    def test_gate_observation_logging_records_retained_and_dropped_windows(self):
        initial_anomalies = pd.DataFrame(
            [
                {
                    "window_id": 1,
                    "start_idx": 0,
                    "end_idx": 20,
                    "is_anomaly": True,
                    "strict_is_anomaly": True,
                    "anomaly_score": 0.91,
                    "evaluation_status": "evaluated",
                    "unknown_ratio": 0.1,
                    "unknown_count": 2,
                    "actual_event": "EventA",
                    "predicted_event": "EventB",
                    "expected_events": "EventB|EventC",
                    "window_key_indicators": {"image": ["evil.exe"]},
                },
                {
                    "window_id": 2,
                    "start_idx": 1,
                    "end_idx": 21,
                    "is_anomaly": True,
                    "strict_is_anomaly": False,
                    "anomaly_score": 0.2,
                    "evaluation_status": "evaluated",
                    "unknown_ratio": 0.0,
                    "unknown_count": 0,
                    "actual_event": "EventC",
                    "predicted_event": "EventC",
                    "expected_events": "EventC|EventD",
                    "window_key_indicators": {},
                },
            ]
        )
        filtered_anomalies = initial_anomalies.iloc[[0]].copy()
        filtered_anomalies["llm_gate_policy"] = "keep_high_confidence_only"
        filtered_anomalies["llm_reason"] = "Prioritaskan anomaly kuat"
        filtered_anomalies["llm_gate_mode"] = "batch_sanity"
        filtered_anomalies["llm_gate_priority"] = "high_confidence"
        filtered_anomalies["llm_gate_priority_rank"] = 2
        filtered_anomalies["llm_gate_active"] = True
        filtered_anomalies["llm_gate_confidence"] = 0.77
        filtered_anomalies["llm_gate_requested_context"] = ""
        filtered_anomalies["llm_gate_prioritized_window_ids"] = "[1]"
        investigation_state = {
            "anomalies": filtered_anomalies.to_dict("records"),
            "iocs_extracted": [{"type": "hash", "value": "abc"}],
            "tool_results": [
                {"ioc": "abc", "classification": "malicious", "tool": "test"}
            ],
            "attack_timeline": [],
            "recommendations": ["Block IOC"],
            "investigation_summary": "Suspicious activity found in retained anomaly window.",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "gate_observations.jsonl"
            count = append_gate_observations(
                output_path,
                session_id="session_test",
                file_name="sample.evtx",
                model_profile="general",
                initial_anomalies_df=initial_anomalies,
                filtered_anomalies_df=filtered_anomalies,
                investigation_state=investigation_state,
                llm_provider="ollama",
                llm_model="slm-gate",
            )

            records = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(count, 2)
        self.assertEqual(len(records), 2)
        self.assertTrue(records[0]["current_llm_gate"]["retained_for_investigation"])
        self.assertEqual(
            records[0]["current_llm_gate"]["decision"],
            "escalate_to_investigation",
        )
        self.assertEqual(records[0]["current_llm_gate"]["priority"], "high_confidence")
        self.assertEqual(records[0]["current_llm_gate"]["priority_rank"], 2)
        self.assertTrue(records[0]["current_llm_gate"]["active"])
        self.assertEqual(records[0]["current_llm_gate"]["confidence"], 0.77)
        self.assertEqual(records[0]["current_llm_gate"]["prioritized_window_ids"], [1])
        self.assertFalse(records[1]["current_llm_gate"]["retained_for_investigation"])
        self.assertEqual(records[1]["current_llm_gate"]["decision"], "drop_or_archive")
        self.assertEqual(records[1]["current_llm_gate"]["priority"], "not_retained")
        self.assertEqual(records[0]["indicator_counts"], {"image": 1})
        self.assertEqual(records[0]["investigation_result"]["malicious_hit_count"], 1)
        self.assertEqual(records[0]["investigation_result"]["utility_label_hint"], "high_value")

    def test_downstream_metrics_low_value_when_investigation_has_no_signal(self):
        metrics = summarize_downstream_metrics(
            {
                "anomalies": [],
                "iocs_extracted": [],
                "tool_results": [],
                "attack_timeline": [],
                "recommendations": [],
                "investigation_summary": "short",
            }
        )

        self.assertEqual(metrics["utility_label_hint"], "low_value")
        self.assertEqual(metrics["ioc_count"], 0)
        self.assertEqual(metrics["malicious_hit_count"], 0)

    def test_deeplog_detector_initializes_without_external_workspace_resolution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            vocab_path = tmp_path / "DeepLog.pkl"
            model_path = tmp_path / "DeepLog.pt"
            embeddings_path = tmp_path / "embeddings.json"
            embeddings_path.write_text(
                json.dumps({"EventA": [1, 0, 0, 0], "EventB": [0, 1, 0, 0]}),
                encoding="utf-8",
            )

            vocab = Vocab(
                [["EventA", "EventB"]],
                emb_file=str(embeddings_path),
                embedding_dim=4,
            )
            vocab.semantic_vectors = {
                "padding": [-1, -1, -1, -1],
                "EventA": [1, 0, 0, 0],
                "EventB": [0, 1, 0, 0],
            }
            with open(vocab_path, "wb") as handle:
                pickle.dump(vocab, handle)

            model = DeepLog(vocab_size=len(vocab), embedding_dim=4, hidden_size=8, num_layers=1, dropout=0.1)
            torch.save(model.state_dict(), model_path)

            with patch(
                "modules.workspace.resolve_training_workspace",
                side_effect=AssertionError("external workspace resolution should not happen"),
            ):
                detector = DeepLogDetector(
                    str(model_path),
                    str(vocab_path),
                    window_size=2,
                    step_size=1,
                    topk=1,
                )

            self.assertEqual(type(detector.model).__name__, "DeepLog")
            self.assertEqual(len(detector.vocab), len(vocab))

    def test_vendored_logadempirical_vocab_pickle_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vocab_path = Path(tmpdir) / "DeepLog.pkl"
            embeddings_path = Path(tmpdir) / "embeddings.json"
            embeddings_path.write_text(
                json.dumps({"EventA": [1, 0, 0, 0], "EventB": [0, 1, 0, 0]}),
                encoding="utf-8",
            )
            vocab = Vocab(
                [["EventA", "EventB"]],
                emb_file=str(embeddings_path),
                embedding_dim=4,
            )
            vocab.semantic_vectors = {
                "padding": [-1, -1, -1, -1],
                "EventA": [1, 0, 0, 0],
                "EventB": [0, 1, 0, 0],
            }
            vocab.save_vocab(vocab_path)

            restored = Vocab.load_vocab(vocab_path)
            self.assertEqual(restored.__class__.__module__, "logadempirical.data.vocab")
            self.assertEqual(restored.get_event("EventA"), vocab.get_event("EventA"))

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

    def test_execute_tools_runs_independent_api_calls_in_parallel(self):
        agent = DFIRAgent(llm=FakeLLM(""))
        barrier = threading.Barrier(2)

        def fake_greynoise_lookup(ioc):
            barrier.wait(timeout=2)
            return {"tool": "greynoise", "ip": ioc, "status": "ok", "data": {"noise": False}}

        def fake_threatfox_lookup(ioc, ioc_type):
            barrier.wait(timeout=2)
            return {"tool": "threatfox", "ioc": ioc, "ioc_type": ioc_type, "status": "ok", "data": []}

        agent.threat_intel.greynoise_lookup = fake_greynoise_lookup
        agent.threat_intel.threatfox_lookup = fake_threatfox_lookup

        with redirect_stdout(io.StringIO()):
            execution = agent.execute_tools(
                {
                    "tool_calls": [
                        {"tool": "greynoise_lookup", "ioc": "8.8.8.8", "ioc_type": "ip"},
                        {"tool": "threatfox_lookup", "ioc": "8.8.8.8", "ioc_type": "ip"},
                    ]
                }
            )

        self.assertEqual(len(execution["tool_results"]), 2)
        self.assertFalse(any(result.get("error") for result in execution["tool_results"]))
        self.assertEqual(
            [result["tool_call"] for result in execution["tool_results"]],
            ["greynoise_lookup", "threatfox_lookup"],
        )

    def test_execute_tools_preserves_original_ioc_type_for_dedupe_keys(self):
        agent = DFIRAgent(llm=FakeLLM(""))
        file_hash = "5de788d23b247b29f116cd0583280ce10a429e9f8c1d80c42deab20c6f4dbb4e"

        agent.threat_intel.alienvault_otx_lookup = lambda ioc, ioc_type: {
            "tool": "alienvault_otx",
            "ioc": ioc,
            "ioc_type": "IPv4",
            "provider_ioc_type": ioc_type,
            "status": "ok",
            "data": {"pulse_info": {"count": 0}},
        }
        agent.threat_intel.virustotal_lookup = lambda ioc, ioc_type: {
            "tool": "virustotal",
            "ioc": ioc,
            "ioc_type": "file",
            "provider_ioc_type": ioc_type,
            "status": "ok",
            "data": {"attributes": {"last_analysis_stats": {}}},
            "malicious": 0,
            "suspicious": 0,
        }

        tool_calls = [
            {"tool": "alienvault_otx_lookup", "ioc": "8.8.8.8", "ioc_type": "ip"},
            {"tool": "virustotal_lookup", "ioc": file_hash, "ioc_type": "sha256"},
        ]

        with redirect_stdout(io.StringIO()):
            execution = agent.execute_tools({"tool_calls": tool_calls})

        results = execution["tool_results"]
        self.assertEqual(results[0]["ioc_type"], "ip")
        self.assertEqual(results[0]["provider_ioc_type"], "IPv4")
        self.assertEqual(results[1]["ioc_type"], "sha256")
        self.assertEqual(results[1]["provider_ioc_type"], "file")
        self.assertEqual(
            agent._attempted_tool_call_keys({"tool_results": results}),
            {
                ("alienvault_otx_lookup", "ip", "8.8.8.8"),
                ("virustotal_lookup", "sha256", file_hash),
            },
        )

    def test_correlation_prompt_does_not_treat_benign_raw_data_as_suspicious(self):
        agent = DFIRAgent(llm=FakeLLM(""))
        prompt = agent._create_correlation_prompt(
            anomalies=[{"window_id": 1, "actual_event": "network connection"}],
            tool_results=[
                {
                    "tool": "greynoise_lookup",
                    "ioc": "8.8.8.8",
                    "ioc_type": "ip",
                    "status": "ok",
                    "classification": "benign",
                    "data": {"noise": False, "riot": False},
                },
                {
                    "tool": "virustotal_lookup",
                    "ioc": "example.com",
                    "ioc_type": "domain",
                    "status": "ok",
                    "malicious": 0,
                    "suspicious": 0,
                    "data": {"attributes": {"last_analysis_stats": {}}},
                },
            ],
        )

        self.assertIn("- **Suspicious IOCs:** 0", prompt)
        self.assertIn("- **Clean/Unknown:** 2", prompt)
        self.assertIn("Response available, no explicit threat signal", prompt)

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

    def test_threatfox_lookup_ignores_non_exact_subdomain_matches(self):
        toolkit = ThreatIntelToolkit(api_keys={})

        with patch(
            "modules.threat_intel.requests.post",
            return_value=FakeResponse(
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "ioc": "test-nonexistent-domain-12345.example.com",
                            "ioc_type": "domain",
                            "malware": "win.appleseed",
                            "confidence_level": 75,
                            "threat_type": "botnet_cc",
                        }
                    ],
                }
            ),
        ):
            with redirect_stdout(io.StringIO()):
                result = toolkit.threatfox_lookup("example.com", "domain")

        self.assertEqual(result["status"], "no_exact_match")
        self.assertEqual(result["data"], [])
        self.assertIsNone(result["malware_family"])
        self.assertIsNone(result["confidence_level"])
        self.assertIsNone(result["threat_type"])

    def test_otx_lookup_maps_hash_ioc_to_file_endpoint_slug(self):
        toolkit = ThreatIntelToolkit(api_keys={"alienvault_otx_api_key": "test-key"})
        file_hash = "5de788d23b247b29f116cd0583280ce10a429e9f8c1d80c42deab20c6f4dbb4e"

        with patch(
            "modules.threat_intel.requests.get",
            return_value=FakeResponse({"pulse_info": {"count": 0, "pulses": []}}),
        ) as mock_get:
            result = toolkit.alienvault_otx_lookup(file_hash, "sha256")

        requested_url = mock_get.call_args.args[0]
        self.assertIn(f"/api/v1/indicators/file/{file_hash}/general", requested_url)
        self.assertEqual(result["ioc_type"], "file")
        self.assertIn("data", result)

    def test_otx_lookup_maps_and_encodes_url_endpoint_slug(self):
        toolkit = ThreatIntelToolkit(api_keys={"alienvault_otx_api_key": "test-key"})
        suspicious_url = "https://bad.example/payload.exe?a=1&b=two"

        with patch(
            "modules.threat_intel.requests.get",
            return_value=FakeResponse({"pulse_info": {"count": 0, "pulses": []}}),
        ) as mock_get:
            result = toolkit.alienvault_otx_lookup(suspicious_url, "url")

        requested_url = mock_get.call_args.args[0]
        self.assertIn("/api/v1/indicators/url/https%3A%2F%2Fbad.example%2Fpayload.exe%3Fa%3D1%26b%3Dtwo/general", requested_url)
        self.assertEqual(result["ioc_type"], "url")
        self.assertIn("data", result)

    def test_virustotal_lookup_uses_v3_ip_addresses_endpoint(self):
        toolkit = ThreatIntelToolkit(api_keys={"virustotal_api_key": "test-key"})

        with patch(
            "modules.threat_intel.requests.get",
            return_value=FakeResponse({"data": {"attributes": {"last_analysis_stats": {}}}}),
        ) as mock_get:
            result = toolkit.virustotal_lookup("8.8.8.8", "ip")

        requested_url = mock_get.call_args.args[0]
        self.assertIn("/api/v3/ip_addresses/8.8.8.8", requested_url)
        self.assertEqual(result["tool"], "virustotal")
        self.assertIn("data", result)

    def test_virustotal_lookup_retries_after_rate_limit(self):
        toolkit = ThreatIntelToolkit(api_keys={"virustotal_api_key": "test-key"})

        with patch(
            "modules.threat_intel.requests.get",
            side_effect=[
                FakeResponse({"error": "rate limited"}, status_code=429),
                FakeResponse(
                    {
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {
                                    "malicious": 0,
                                    "suspicious": 0,
                                }
                            }
                        }
                    }
                ),
            ],
        ) as mock_get, patch("modules.threat_intel.time.sleep") as mock_sleep:
            result = toolkit.virustotal_lookup("8.8.8.8", "ip")

        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called_once_with(30)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["malicious"], 0)

    def test_extract_recommendations_accepts_flexible_headers(self):
        agent = DFIRAgent(llm=FakeLLM(""))
        recommendations = agent._extract_recommendations(
            "## LANGKAH PERBAIKAN\n"
            "1. Isolasi host yang terkait IOC prioritas.\n"
            "- Hunt IOC pada DNS dan proxy log.\n"
            "## Section berikutnya\n"
            "- jangan ambil ini"
        )

        self.assertEqual(
            recommendations,
            [
                "Isolasi host yang terkait IOC prioritas.",
                "Hunt IOC pada DNS dan proxy log.",
            ],
        )

    def test_extract_severity_ignores_negated_critical_mentions(self):
        agent = DFIRAgent(llm=FakeLLM(""))

        self.assertEqual(
            agent._extract_severity(
                "Severity: MEDIUM\nTidak ada ancaman CRITICAL yang teridentifikasi."
            ),
            "MEDIUM",
        )

    def test_report_prompt_uses_longer_correlation_preview_after_evidence(self):
        agent = DFIRAgent(llm=FakeLLM(""))
        correlation = "A" * 1300 + " important tail"
        state = {
            "anomalies": [
                {"window_id": 1, "actual_event": "Event 1", "anomaly_score": 0.9}
            ],
            "iocs_extracted": [],
            "tool_results": [],
            "reasoning_steps": [],
            "attack_timeline": [],
            "correlation_analysis": correlation,
        }

        prompt = agent._create_report_prompt(state)

        self.assertIn("important tail", prompt)
        self.assertLess(
            prompt.index("### DeepLog Anomaly Evidence"),
            prompt.index("### Correlation Analysis Summary"),
        )

    def test_threat_intel_cache_is_bounded(self):
        toolkit = ThreatIntelToolkit(api_keys={})
        toolkit.max_cache_entries = 2

        toolkit._set_cache("tool", "ioc-1", {"ioc": "ioc-1"})
        toolkit._set_cache("tool", "ioc-2", {"ioc": "ioc-2"})
        toolkit._set_cache("tool", "ioc-3", {"ioc": "ioc-3"})

        self.assertIsNone(toolkit._get_cached("tool", "ioc-1"))
        self.assertEqual(toolkit._get_cached("tool", "ioc-2"), {"ioc": "ioc-2"})
        self.assertEqual(toolkit._get_cached("tool", "ioc-3"), {"ioc": "ioc-3"})

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
