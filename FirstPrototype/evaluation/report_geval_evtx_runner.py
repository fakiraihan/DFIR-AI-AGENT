from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import io
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

import requests
from dotenv import load_dotenv

from deepeval import assert_test
from deepeval.metrics import GEval
from deepeval.models.llms.openai_model import GPTModel
from deepeval.test_case import LLMTestCase, SingleTurnParams


EVALUATION_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVALUATION_DIR.parent
BACKEND_DIR = REPO_ROOT / "backend"
DATASET_PATH = EVALUATION_DIR / "datasets" / "report_geval_evtx_cases.json"
RESULTS_DIR = EVALUATION_DIR / "results"
RUNTIME_DIR = EVALUATION_DIR / "runtime" / "report_geval_evtx"
LATEST_RESULTS_PATH = RESULTS_DIR / "report_geval_evtx_latest.json"
TEST_ENTRYPOINT = EVALUATION_DIR / "tests" / "test_report_geval_evtx.py"
VALIDATION_CSV_PATH = (
    BACKEND_DIR
    / "data"
    / "evtx_attack_validation_lmd_enriched_20260528"
    / "evtx_attack_validation.csv"
)

EXPECTED_CASE_COUNT = 8
SELECTION_RULE = (
    "largest EVTX by byte size per selected MITRE tactic folder; "
    "alphabetical relative path tie-breaker"
)

load_dotenv(BACKEND_DIR / ".env", override=False)
load_dotenv(EVALUATION_DIR / ".env", override=True)

DEFAULT_EVTX_ROOT = Path(
    os.getenv("EVTX_ATTACK_SAMPLES_ROOT", r"D:\FAKI\LogADEmpirical-dev\EVTX-ATTACK-SAMPLES")
)
SUBJECT_BASE_URL = os.getenv("EVAL_REPORT_GEEVAL_OLLAMA_BASE_URL") or os.getenv(
    "EVAL_REPORT_GEVAL_OLLAMA_BASE_URL", "http://localhost:11434"
)
SUBJECT_MODEL = os.getenv("EVAL_REPORT_GEEVAL_OLLAMA_MODEL") or os.getenv(
    "EVAL_REPORT_GEVAL_OLLAMA_MODEL", "sec-foundation:8b-gpu"
)
DEFAULT_REPETITIONS = int(
    os.getenv("EVAL_REPORT_GEEVAL_REPETITIONS")
    or os.getenv("EVAL_REPORT_GEVAL_REPETITIONS", "3")
)
DEFAULT_THRESHOLD = float(
    os.getenv("EVAL_REPORT_GEEVAL_THRESHOLD")
    or os.getenv("EVAL_REPORT_GEVAL_THRESHOLD", "0.8")
)
DEFAULT_MAX_LINES = int(
    os.getenv("EVAL_REPORT_GEEVAL_MAX_LINES")
    or os.getenv("EVAL_REPORT_GEVAL_MAX_LINES", "20000")
)
DEFAULT_OUTPUT_MODES = tuple(
    item.strip()
    for item in (
        os.getenv("EVAL_REPORT_GEEVAL_OUTPUT_MODES")
        or os.getenv("EVAL_REPORT_GEVAL_OUTPUT_MODES", "json,markdown")
    ).split(",")
    if item.strip()
)


@dataclass
class OllamaInvokeClient:
    base_url: str = SUBJECT_BASE_URL
    model: str = SUBJECT_MODEL
    timeout_seconds: int = 180

    def invoke(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.7,
                "top_k": 20,
                "num_ctx": 16384,
                "num_predict": 6144,
                "repeat_penalty": 1.15,
            },
        }
        response = requests.post(
            f"{self.base_url.rstrip('/')}/api/generate",
            json=payload,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        return str(data.get("response") or "").strip()


def ensure_backend_import_path() -> None:
    backend_path = str(BACKEND_DIR)
    if backend_path not in sys.path:
        sys.path.insert(0, backend_path)


def load_runtime_env() -> None:
    load_dotenv(BACKEND_DIR / ".env", override=False)
    load_dotenv(EVALUATION_DIR / ".env", override=True)
    os.environ["OLLAMA_BASE_URL"] = SUBJECT_BASE_URL
    os.environ["OLLAMA_MODEL"] = SUBJECT_MODEL


def load_cases(path: Path = DATASET_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def evtx_root() -> Path:
    return Path(
        os.getenv("EVTX_ATTACK_SAMPLES_ROOT", str(DEFAULT_EVTX_ROOT))
    ).resolve()


def case_path(case: dict[str, Any], root: Path | None = None) -> Path:
    return (root or evtx_root()) / case["relative_path"]


def relative_key(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("/", "\\").lower()


def largest_evtx_for_folder(root: Path, tactic_folder: str) -> Path | None:
    folder = root / tactic_folder
    if not folder.exists():
        return None
    files = list(folder.rglob("*.evtx"))
    if not files:
        return None
    return min(
        files,
        key=lambda item: (
            -item.stat().st_size,
            str(item.relative_to(root)).replace("/", "\\").lower(),
        ),
    )


def load_runtime_validation_rows(path: Path = VALIDATION_CSV_PATH) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    rows: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8", newline="") as file_obj:
        for row in csv.DictReader(file_obj):
            topk = str(row.get("topk") or "")
            profile = str(row.get("profile") or "")
            if (profile == "sysmon" and topk == "9") or (
                profile == "windows_apt" and topk == "5"
            ):
                key = str(row.get("relative_path") or "").replace("/", "\\").lower()
                rows[key] = row
    return rows


def safe_int(value: Any) -> int | None:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return None


def build_judge_model() -> GPTModel:
    load_runtime_env()
    api_key = os.getenv("OPENAI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL")
    model_name = os.getenv("OPENAI_MODEL_NAME")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is missing from evaluation/.env")
    if not base_url:
        raise RuntimeError("OPENAI_BASE_URL is missing from evaluation/.env")
    if not model_name:
        raise RuntimeError("OPENAI_MODEL_NAME is missing from evaluation/.env")
    return GPTModel(
        model=model_name,
        api_key=api_key,
        base_url=base_url,
        cost_per_input_token=0,
        cost_per_output_token=0,
    )


def ollama_status() -> dict[str, Any]:
    try:
        response = requests.get(f"{SUBJECT_BASE_URL.rstrip('/')}/api/tags", timeout=10)
        response.raise_for_status()
        data = response.json()
        models = [
            str(item.get("name") or item.get("model") or "")
            for item in data.get("models", [])
            if isinstance(item, dict)
        ]
        return {
            "reachable": True,
            "base_url": SUBJECT_BASE_URL,
            "model": SUBJECT_MODEL,
            "model_available": SUBJECT_MODEL in models,
            "available_models": models,
        }
    except Exception as exc:
        return {
            "reachable": False,
            "base_url": SUBJECT_BASE_URL,
            "model": SUBJECT_MODEL,
            "model_available": False,
            "error": str(exc),
        }


def live_key_status() -> dict[str, Any]:
    load_runtime_env()
    required = {
        "ABUSECH_API_KEY": bool(os.getenv("ABUSECH_API_KEY")),
        "ALIENVAULT_OTX_API_KEY": bool(os.getenv("ALIENVAULT_OTX_API_KEY")),
        "VIRUSTOTAL_API_KEY": bool(os.getenv("VIRUSTOTAL_API_KEY")),
    }
    optional = {
        "GREYNOISE_API_KEY": bool(os.getenv("GREYNOISE_API_KEY")),
    }
    return {
        "required": required,
        "optional": optional,
        "required_ready": all(required.values()),
        "missing_required": [key for key, value in required.items() if not value],
        "notes": [
            "GreyNoise can use the community endpoint without GREYNOISE_API_KEY, "
            "but paid context requires the key."
        ],
    }


def judge_env_status() -> dict[str, Any]:
    load_runtime_env()
    return {
        "env_ready": bool(
            os.getenv("OPENAI_API_KEY")
            and os.getenv("OPENAI_BASE_URL")
            and os.getenv("OPENAI_MODEL_NAME")
        ),
        "base_url": os.getenv("OPENAI_BASE_URL"),
        "model": os.getenv("OPENAI_MODEL_NAME"),
    }


def preflight_checks() -> dict[str, Any]:
    load_runtime_env()
    ensure_backend_import_path()
    cases = load_cases()
    root = evtx_root()
    validation_rows = load_runtime_validation_rows()

    case_checks = []
    for case in cases:
        path = case_path(case, root)
        largest = largest_evtx_for_folder(root, case["tactic_folder"])
        runtime_row = validation_rows.get(
            str(case["relative_path"]).replace("/", "\\").lower()
        )
        parsed_events = safe_int((runtime_row or {}).get("parsed_events"))
        size_bytes = path.stat().st_size if path.exists() else None
        case_checks.append(
            {
                "case_id": case["case_id"],
                "tactic_folder": case["tactic_folder"],
                "relative_path": case["relative_path"],
                "exists": path.exists(),
                "size_bytes": size_bytes,
                "expected_size_bytes": case.get("expected_size_bytes"),
                "size_matches_expected": bool(
                    size_bytes is not None
                    and size_bytes == safe_int(case.get("expected_size_bytes"))
                ),
                "is_largest": bool(
                    largest is not None
                    and path.exists()
                    and relative_key(largest, root)
                    == str(case["relative_path"]).replace("/", "\\").lower()
                ),
                "largest_relative_path": str(largest.relative_to(root)).replace("/", "\\")
                if largest is not None
                else None,
                "runtime_validation": runtime_row,
                "has_runtime_validation": runtime_row is not None,
                "detected_runtime_like": bool(
                    runtime_row is not None and str(runtime_row.get("detected")) == "1"
                ),
                "max_lines_cap_hit_in_validation": bool(
                    parsed_events is not None and parsed_events >= DEFAULT_MAX_LINES
                ),
            }
        )

    deep_log_artifacts = []
    for item in case_checks:
        row = item.get("runtime_validation") or {}
        for key in ("model_path", "vocab_path"):
            path_value = row.get(key)
            if path_value:
                path_obj = Path(path_value)
                deep_log_artifacts.append(
                    {"path": str(path_obj), "exists": path_obj.exists(), "kind": key}
                )

    dataset = {
        "case_count": len(cases),
        "selection_rule": SELECTION_RULE,
        "evtx_root": str(root),
        "validation_csv": str(VALIDATION_CSV_PATH),
        "all_cases_exist": all(item["exists"] for item in case_checks),
        "all_case_sizes_match": all(item["size_matches_expected"] for item in case_checks),
        "all_cases_largest": all(item["is_largest"] for item in case_checks),
        "all_cases_have_runtime_validation": all(
            item["has_runtime_validation"] for item in case_checks
        ),
        "all_cases_detected_runtime_like": all(
            item["detected_runtime_like"] for item in case_checks
        ),
        "cases": case_checks,
    }
    artifacts_ready = all(item["exists"] for item in deep_log_artifacts)
    status = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": dataset,
        "deeplog_artifacts": {
            "ready": artifacts_ready,
            "items": deep_log_artifacts,
        },
        "ollama": ollama_status(),
        "live_threat_intel": live_key_status(),
        "judge": judge_env_status(),
    }
    status["ready"] = bool(
        dataset["case_count"] == EXPECTED_CASE_COUNT
        and dataset["all_cases_exist"]
        and dataset["all_case_sizes_match"]
        and dataset["all_cases_largest"]
        and dataset["all_cases_have_runtime_validation"]
        and dataset["all_cases_detected_runtime_like"]
        and artifacts_ready
        and status["ollama"]["reachable"]
        and status["ollama"]["model_available"]
        and status["live_threat_intel"]["required_ready"]
        and status["judge"]["env_ready"]
    )
    return status


def build_report_quality_metric(judge_model: GPTModel, threshold: float) -> GEval:
    return GEval(
        name="EVTX Report Quality",
        evaluation_steps=[
            "Compare the final report against the EVTX evidence context, expected tactic, "
            "runtime validation, anomaly summary, extracted IOC summary, and live tool-result summary.",
            "Reward reports that cite concrete evidence such as EventID, provider, window ID, "
            "host, user, process, registry, share, IP, timeline, or tool result.",
            "Penalize unsupported claims of confirmed malware, command-and-control, exfiltration, "
            "system compromise, or malicious private/internal IOC without supporting evidence.",
            "Check whether severity, confidence, recommendations, and limitations are calibrated "
            "to the evidence, live enrichment result, and missing-data conditions.",
            "For JSON output, evaluate structured report fields. For Markdown output, evaluate "
            "the analyst-facing rendered report. Do not penalize harmless formatting differences.",
        ],
        evaluation_params=[
            SingleTurnParams.INPUT,
            SingleTurnParams.ACTUAL_OUTPUT,
            SingleTurnParams.EXPECTED_OUTPUT,
            SingleTurnParams.CONTEXT,
        ],
        model=judge_model,
        threshold=threshold,
        async_mode=False,
        verbose_mode=False,
    )


def summarize_dict_counts(rows: list[dict[str, Any]], key: str, limit: int = 12) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "")
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit])


def compact_tool_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": result.get("tool"),
        "ioc": result.get("ioc")
        or result.get("ip")
        or result.get("url")
        or result.get("hash")
        or result.get("domain"),
        "ioc_type": result.get("ioc_type"),
        "status": result.get("status"),
        "classification": result.get("classification"),
        "malicious": result.get("malicious"),
        "suspicious": result.get("suspicious"),
        "error": result.get("error"),
        "data_present": bool(result.get("data")),
    }


def is_internal_ioc(ioc: dict[str, Any]) -> bool:
    value = str(ioc.get("value") or ioc.get("ioc") or "")
    ioc_type = str(ioc.get("type") or ioc.get("ioc_type") or "").lower()
    if ioc_type == "ip":
        try:
            parsed = ip_address(value)
            return bool(parsed.is_private or parsed.is_loopback or parsed.is_link_local)
        except ValueError:
            return False
    if ioc_type == "domain":
        lowered = value.lower()
        return lowered.endswith((".local", ".corp", ".example", ".test"))
    return False


def build_expected_output(case: dict[str, Any], validation_row: dict[str, Any]) -> str:
    focus = "\n".join(f"- {item}" for item in case.get("expected_focus", []))
    return f"""A correct FirstPrototype report for this EVTX sample should:
- Identify the selected tactic folder as {case['tactic_folder']}.
- Stay grounded in EVTX log evidence and runtime validation.
- Mention relevant EventID/provider/window/timeline/tool evidence when available.
- Treat private IPs and internal domains as local telemetry unless live enrichment supports a stronger claim.
- Calibrate severity and confidence to anomaly count, live enrichment result, and missing-data limitations.
- Provide specific DFIR recommendations for the tactic, not generic security advice.

Expected focus:
{focus}

Runtime-like validation baseline:
- profile: {validation_row.get('profile')}
- parsed events: {validation_row.get('parsed_events')}
- windows: {validation_row.get('windows')}
- anomalies: {validation_row.get('anomalies')}
- detected: {validation_row.get('detected')}
"""


def build_eval_context(
    case: dict[str, Any],
    validation_row: dict[str, Any],
    run_record: dict[str, Any],
) -> list[str]:
    return [
        json.dumps(
            {
                "case": {
                    "case_id": case["case_id"],
                    "tactic_folder": case["tactic_folder"],
                    "relative_path": case["relative_path"],
                    "expected_focus": case.get("expected_focus", []),
                },
                "runtime_validation": {
                    "profile": validation_row.get("profile"),
                    "template_strategy": validation_row.get("template_strategy"),
                    "parsed_events": validation_row.get("parsed_events"),
                    "windows": validation_row.get("windows"),
                    "anomalies": validation_row.get("anomalies"),
                    "top_anomaly_actual_events": validation_row.get(
                        "top_anomaly_actual_events"
                    ),
                },
                "pipeline_evidence": run_record["pipeline_evidence"],
                "live_enrichment": run_record["live_enrichment"],
            },
            ensure_ascii=False,
        )
    ]


def output_for_mode(report: dict[str, Any], markdown: str, mode: str) -> str:
    if mode == "json":
        return json.dumps(report, ensure_ascii=False, indent=2, default=str)
    if mode == "markdown":
        return markdown
    raise ValueError(f"Unsupported output mode: {mode}")


def measure_output(
    *,
    case: dict[str, Any],
    validation_row: dict[str, Any],
    run_record: dict[str, Any],
    output_mode: str,
    actual_output: str,
    judge_model: GPTModel,
    threshold: float,
) -> dict[str, Any]:
    metric = build_report_quality_metric(judge_model, threshold)
    test_case = LLMTestCase(
        name=f"{case['case_id']}::{output_mode}::run_{run_record['repetition']}",
        input=(
            "Evaluate the FirstPrototype final EVTX DFIR report. "
            f"Output mode: {output_mode}. "
            "Use the context as the evidence boundary."
        ),
        actual_output=actual_output,
        expected_output=build_expected_output(case, validation_row),
        context=build_eval_context(case, validation_row, run_record),
        metadata={
            "case_id": case["case_id"],
            "tactic_folder": case["tactic_folder"],
            "relative_path": case["relative_path"],
            "output_mode": output_mode,
            "repetition": run_record["repetition"],
            "subject_model": SUBJECT_MODEL,
        },
    )
    assertion_error = None
    try:
        assert_test(test_case, [metric], run_async=False)
    except AssertionError as exc:
        assertion_error = str(exc)
    except Exception as exc:
        metric.error = str(exc)
        assertion_error = str(exc)

    score = metric.score if metric.score is not None else 0.0
    return {
        "output_mode": output_mode,
        "score": float(score),
        "success": bool(metric.is_successful()) if metric.score is not None else False,
        "threshold": threshold,
        "reason": metric.reason,
        "error": getattr(metric, "error", None),
        "assertion_error": assertion_error,
        "output_sha256": hashlib.sha256(actual_output.encode("utf-8")).hexdigest(),
        "output_chars": len(actual_output),
    }


def runtime_like_validation_for_case(
    case: dict[str, Any], validation_rows: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    key = str(case["relative_path"]).replace("/", "\\").lower()
    row = validation_rows.get(key)
    if row is None:
        raise RuntimeError(f"No runtime-like validation row found for {case['relative_path']}")
    return row


def run_pipeline_for_case(
    *,
    case: dict[str, Any],
    validation_row: dict[str, Any],
    repetition: int,
    max_lines: int,
    runtime_root: Path,
) -> dict[str, Any]:
    load_runtime_env()
    ensure_backend_import_path()

    from config import settings
    from modules.agent import DFIRAgent
    from modules.anomaly import detect_anomalies_in_logs
    from modules.llm_filter import LLMAnomalyFilter
    from modules.report import ReportGenerator
    from services.orchestrator_service import (
        _is_recall_preserving_deeplog_policy,
        _merge_llm_gate_annotations,
    )
    from services.parsing_service import parse_with_profile

    start = time.time()
    root = evtx_root()
    evtx_path = case_path(case, root)
    run_dir = runtime_root / case["case_id"] / f"run_{repetition}"
    run_dir.mkdir(parents=True, exist_ok=True)

    stdout_buffer = io.StringIO()
    with contextlib.redirect_stdout(stdout_buffer):
        parsed_df, templates, selected_profile = parse_with_profile(
            str(evtx_path), settings, max_lines=max_lines
        )
        results_df, anomalies_df = detect_anomalies_in_logs(
            parsed_df,
            str(selected_profile["model_path"]),
            str(selected_profile["vocab_path"]),
            window_size=selected_profile["window_size"],
            step_size=settings.deeplog_step_size,
            topk=selected_profile.get("topk", settings.deeplog_topk),
            skip_unknown_windows=settings.deeplog_skip_unknown_windows,
            max_unknown_ratio=settings.deeplog_max_unknown_ratio,
            unknown_template_mode=settings.deeplog_unknown_template_mode,
            evtx_sparse_fallback_enabled=settings.deeplog_evtx_sparse_fallback_enabled,
            evtx_sparse_fallback_threshold=settings.deeplog_evtx_sparse_fallback_threshold,
            template_similarity_enabled=settings.deeplog_template_similarity_enabled,
            template_similarity_threshold=settings.deeplog_template_similarity_threshold,
            decision_policy=settings.deeplog_decision_policy,
            score_threshold=settings.deeplog_score_threshold,
            medium_score_threshold=settings.deeplog_medium_score_threshold,
            recall_floor=settings.deeplog_target_recall,
            use_bos_context=selected_profile.get("use_bos_context", False),
            bos_token=selected_profile.get("bos_token", "<BOS>"),
            bos_count=selected_profile.get("bos_count"),
        )

        local_llm = OllamaInvokeClient()
        llm_filter = LLMAnomalyFilter(
            ollama_base_url=SUBJECT_BASE_URL,
            ollama_model=SUBJECT_MODEL,
            llm=local_llm,
            provider_name="ollama",
        )
        filtered_anomalies_df = llm_filter.filter_anomalies(anomalies_df, parsed_df)
        recall_preserving_gate = (
            _is_recall_preserving_deeplog_policy(settings.deeplog_decision_policy)
            or str(getattr(settings, "deeplog_llm_filter_mode", "filter")).lower()
            == "annotate"
        )
        investigation_anomalies_df = (
            _merge_llm_gate_annotations(anomalies_df, filtered_anomalies_df)
            if recall_preserving_gate
            else filtered_anomalies_df
        )

        agent = DFIRAgent(
            ollama_base_url=SUBJECT_BASE_URL,
            ollama_model=SUBJECT_MODEL,
            threat_intel_api_keys={
                "abusech_api_key": settings.abusech_api_key,
                "alienvault_otx_api_key": settings.alienvault_otx_api_key,
                "greynoise_api_key": settings.greynoise_api_key,
                "virustotal_api_key": settings.virustotal_api_key,
            },
            llm=local_llm,
            provider_name="ollama",
        )
        investigation_state = agent.investigate(
            investigation_anomalies_df,
            parsed_df,
            session_id=f"geval-{case['case_id']}-run-{repetition}",
        )
        report_generator = ReportGenerator()
        report = report_generator.generate_report(
            f"geval-{case['case_id']}-run-{repetition}",
            Path(case["relative_path"]).name,
            investigation_state,
        )
        markdown = report_generator._to_markdown(report)

    json_path = run_dir / "report.json"
    markdown_path = run_dir / "report.md"
    state_path = run_dir / "investigation_state_summary.json"
    stdout_path = run_dir / "stdout.txt"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    markdown_path.write_text(markdown, encoding="utf-8")
    stdout_path.write_text(stdout_buffer.getvalue(), encoding="utf-8")

    anomalies_records = investigation_anomalies_df.to_dict("records")
    iocs = list(investigation_state.get("iocs_extracted") or [])
    tool_results = list(investigation_state.get("tool_results") or [])
    tool_calls = list(investigation_state.get("tool_calls") or [])
    top_events = summarize_dict_counts(anomalies_records, "actual_event", limit=10)
    compact_results = [compact_tool_result(result) for result in tool_results]
    internal_iocs = [ioc for ioc in iocs if is_internal_ioc(ioc)]
    pipeline_evidence = {
        "evtx_path": str(evtx_path),
        "selected_profile": selected_profile["name"],
        "template_strategy": selected_profile.get("template_strategy"),
        "max_lines": max_lines,
        "max_lines_reached": len(parsed_df) >= max_lines,
        "parsed_events": len(parsed_df),
        "templates": len(templates),
        "deeplog_windows": len(results_df),
        "deeplog_anomalies": len(anomalies_df),
        "llm_gate_anomalies": len(investigation_anomalies_df),
        "top_anomalous_events": top_events,
        "validation_profile": validation_row.get("profile"),
        "validation_anomalies": validation_row.get("anomalies"),
        "validation_windows": validation_row.get("windows"),
        "validation_top_anomaly_actual_events": validation_row.get(
            "top_anomaly_actual_events"
        ),
    }
    live_enrichment = {
        "iocs_extracted_count": len(iocs),
        "internal_ioc_count": len(internal_iocs),
        "internal_iocs_sample": internal_iocs[:10],
        "tool_calls_count": len(tool_calls),
        "tool_results_count": len(tool_results),
        "tool_result_status_counts": summarize_dict_counts(compact_results, "status"),
        "tool_results_sample": compact_results[:20],
        "supporting_evidence_count": len(
            investigation_state.get("supporting_evidence") or []
        ),
        "investigation_status": investigation_state.get("investigation_status"),
        "investigation_confidence": investigation_state.get("investigation_confidence"),
        "confidence_factors": investigation_state.get("confidence_factors") or [],
    }

    state_summary = {
        "pipeline_evidence": pipeline_evidence,
        "live_enrichment": live_enrichment,
        "report_metadata": report.get("metadata", {}),
        "report_version": report.get("report_version"),
        "severity": report.get("metadata", {}).get("severity"),
        "limitations": report.get("limitations_confidence", {}),
    }
    state_path.write_text(
        json.dumps(state_summary, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )

    return {
        "case_id": case["case_id"],
        "tactic_folder": case["tactic_folder"],
        "relative_path": case["relative_path"],
        "repetition": repetition,
        "runtime_seconds": round(time.time() - start, 3),
        "report_json_path": str(json_path),
        "report_markdown_path": str(markdown_path),
        "state_summary_path": str(state_path),
        "stdout_path": str(stdout_path),
        "pipeline_evidence": pipeline_evidence,
        "live_enrichment": live_enrichment,
        "report": report,
        "markdown": markdown,
        "stdout_excerpt": stdout_buffer.getvalue()[-2000:],
    }


def summarize_results(
    cases: list[dict[str, Any]], run_results: list[dict[str, Any]]
) -> dict[str, Any]:
    output_results = [
        output for run in run_results for output in run.get("output_evaluations", [])
    ]
    by_mode: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_tactic: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for output in output_results:
        by_mode[output["output_mode"]].append(output)
    for run in run_results:
        for output in run.get("output_evaluations", []):
            by_tactic[run["tactic_folder"]].append(output)

    mode_summary = {}
    for mode, rows in by_mode.items():
        mode_summary[mode] = {
            "runs": len(rows),
            "mean_score": mean([row["score"] for row in rows]) if rows else 0.0,
            "pass_rate": sum(1 for row in rows if row["success"]) / len(rows)
            if rows
            else 0.0,
        }

    tactic_summary = {}
    for tactic, rows in by_tactic.items():
        tactic_summary[tactic] = {
            "runs": len(rows),
            "mean_score": mean([row["score"] for row in rows]) if rows else 0.0,
            "pass_rate": sum(1 for row in rows if row["success"]) / len(rows)
            if rows
            else 0.0,
        }

    case_stability = {}
    for case in cases:
        case_runs = [run for run in run_results if run["case_id"] == case["case_id"]]
        output_rows = [
            output for run in case_runs for output in run.get("output_evaluations", [])
        ]
        scores = [row["score"] for row in output_rows]
        hashes_by_mode: dict[str, set[str]] = defaultdict(set)
        for row in output_rows:
            hashes_by_mode[row["output_mode"]].add(row["output_sha256"])
        case_stability[case["case_id"]] = {
            "runs": len(case_runs),
            "mean_score": mean(scores) if scores else 0.0,
            "score_stddev": pstdev(scores) if len(scores) > 1 else 0.0,
            "pass_rate": sum(1 for row in output_rows if row["success"]) / len(output_rows)
            if output_rows
            else 0.0,
            "unique_output_hashes_by_mode": {
                mode: len(values) for mode, values in hashes_by_mode.items()
            },
        }

    total_case_runs = len(run_results)
    return {
        "total_cases": len(cases),
        "total_case_runs": total_case_runs,
        "repetitions_per_case": total_case_runs // len(cases) if cases else 0,
        "total_output_evaluations": len(output_results),
        "json_output_runs": len(by_mode.get("json", [])),
        "markdown_output_runs": len(by_mode.get("markdown", [])),
        "mean_geval_score": mean([row["score"] for row in output_results])
        if output_results
        else 0.0,
        "pass_rate": sum(1 for row in output_results if row["success"]) / len(output_results)
        if output_results
        else 0.0,
        "macro_average_by_tactic": tactic_summary,
        "output_mode_summary": mode_summary,
        "case_stability": case_stability,
    }


def run_report_geval_evaluation(
    *,
    repetitions: int = DEFAULT_REPETITIONS,
    threshold: float = DEFAULT_THRESHOLD,
    max_lines: int = DEFAULT_MAX_LINES,
    output_modes: tuple[str, ...] = DEFAULT_OUTPUT_MODES,
    results_path: Path = LATEST_RESULTS_PATH,
    runtime_root: Path = RUNTIME_DIR,
    case_limit: int | None = None,
) -> dict[str, Any]:
    load_runtime_env()
    ensure_backend_import_path()
    preflight = preflight_checks()
    if not preflight["ready"]:
        raise RuntimeError(
            "EVTX report G-Eval preflight failed: "
            + json.dumps(preflight, ensure_ascii=False, default=str)[:4000]
        )

    cases = load_cases()
    if case_limit is not None:
        cases = cases[:case_limit]
    validation_rows = load_runtime_validation_rows()
    judge_model = build_judge_model()

    run_results = []
    for case in cases:
        validation_row = runtime_like_validation_for_case(case, validation_rows)
        for repetition in range(1, repetitions + 1):
            run_record = run_pipeline_for_case(
                case=case,
                validation_row=validation_row,
                repetition=repetition,
                max_lines=max_lines,
                runtime_root=runtime_root,
            )
            output_evaluations = []
            for output_mode in output_modes:
                actual_output = output_for_mode(
                    run_record["report"], run_record["markdown"], output_mode
                )
                output_evaluations.append(
                    measure_output(
                        case=case,
                        validation_row=validation_row,
                        run_record=run_record,
                        output_mode=output_mode,
                        actual_output=actual_output,
                        judge_model=judge_model,
                        threshold=threshold,
                    )
                )
            run_record["output_evaluations"] = output_evaluations
            del run_record["report"]
            del run_record["markdown"]
            run_results.append(run_record)

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "runner_path": str(Path(__file__).resolve()),
        "test_entrypoint": str(TEST_ENTRYPOINT),
        "dataset_path": str(DATASET_PATH),
        "results_path": str(results_path),
        "runtime_dir": str(runtime_root),
        "config": {
            "subject_under_test": "FirstPrototype full EVTX report pipeline",
            "subject_llm_provider": "ollama",
            "subject_ollama_base_url": SUBJECT_BASE_URL,
            "subject_ollama_model": SUBJECT_MODEL,
            "judge_provider": "deepeval GPTModel with OpenAI-compatible endpoint",
            "judge_base_url": os.getenv("OPENAI_BASE_URL"),
            "judge_model": os.getenv("OPENAI_MODEL_NAME"),
            "threshold": threshold,
            "repetitions": repetitions,
            "max_lines": max_lines,
            "output_modes": list(output_modes),
            "selection_rule": SELECTION_RULE,
            "live_threat_intel_required": True,
        },
        "preflight": preflight,
        "cases": cases,
        "runs": run_results,
        "summary": summarize_results(cases, run_results),
    }
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Run EVTX report G-Eval benchmark.")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    parser.add_argument("--case-limit", type=int, default=None)
    parser.add_argument(
        "--output-modes",
        default=",".join(DEFAULT_OUTPUT_MODES),
        help="Comma-separated output modes: json,markdown",
    )
    args = parser.parse_args()

    if args.preflight:
        payload = preflight_checks()
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        if not payload["ready"]:
            raise SystemExit(1)
        return

    output_modes = tuple(
        item.strip() for item in args.output_modes.split(",") if item.strip()
    )
    payload = run_report_geval_evaluation(
        repetitions=args.repetitions,
        threshold=args.threshold,
        max_lines=args.max_lines,
        output_modes=output_modes,
        case_limit=args.case_limit,
    )
    print(json.dumps(payload["summary"], indent=2, ensure_ascii=False))
    print(f"Results written to {payload['results_path']}")


if __name__ == "__main__":
    main()
