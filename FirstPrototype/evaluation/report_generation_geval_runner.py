from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

from deepeval import assert_test
from deepeval.metrics import GEval
from deepeval.test_case import LLMTestCase, SingleTurnParams
from dotenv import load_dotenv

from report_geval_evtx_runner import (
    BACKEND_DIR,
    DATASET_PATH as EVTX_CASES_PATH,
    DEFAULT_MAX_LINES,
    DEFAULT_OUTPUT_MODES,
    DEFAULT_REPETITIONS,
    DEFAULT_THRESHOLD,
    EVALUATION_DIR,
    EXPECTED_CASE_COUNT,
    LATEST_RESULTS_PATH as FULL_PIPELINE_RESULTS_PATH,
    OllamaInvokeClient,
    SUBJECT_BASE_URL,
    SUBJECT_MODEL,
    TEST_ENTRYPOINT as FULL_PIPELINE_TEST_ENTRYPOINT,
    build_judge_model,
    case_path,
    compact_tool_result,
    ensure_backend_import_path,
    evtx_root,
    is_internal_ioc,
    judge_env_status,
    live_key_status,
    load_cases,
    load_runtime_env,
    load_runtime_validation_rows,
    ollama_status,
    output_for_mode,
    preflight_checks as full_pipeline_preflight_checks,
    runtime_like_validation_for_case,
    safe_int,
    summarize_dict_counts,
)


EVIDENCE_FIXTURE_PATH = (
    EVALUATION_DIR / "datasets" / "report_generation_evidence_cases.json"
)
RESULTS_DIR = EVALUATION_DIR / "results"
LATEST_RESULTS_PATH = RESULTS_DIR / "report_generation_geval_latest.json"
JUDGE_CACHE_PATH = RESULTS_DIR / "report_generation_geval_judge_cache.json"
RUNTIME_DIR = EVALUATION_DIR / "runtime" / "report_generation_geval"
CAPTURE_RUNTIME_DIR = EVALUATION_DIR / "runtime" / "report_generation_evidence"
TEST_ENTRYPOINT = EVALUATION_DIR / "tests" / "test_report_generation_geval.py"
DEFAULT_DETERMINISTIC_THRESHOLD = 0.75

REPORT_GENERATION_METRIC_NAMES = (
    "Evidence Groundedness",
    "Severity Calibration",
    "Tactic Alignment",
    "Recommendation Specificity",
    "Limitation Honesty",
)

REPORT_GENERATION_METRIC_PRESETS = {
    "smoke": (),
    "core": (
        "Evidence Groundedness",
        "Severity Calibration",
    ),
    "full": REPORT_GENERATION_METRIC_NAMES,
}

CLI_DEFAULT_OUTPUT_MODES_BY_PRESET = {
    "smoke": ("summary",),
    "core": ("summary",),
    "full": ("summary", "json", "markdown"),
}


STATE_KEYS_TO_FREEZE = (
    "anomalies",
    "iocs_extracted",
    "tool_calls",
    "tool_results",
    "reasoning_steps",
    "planning_steps",
    "planned_tool_calls",
    "reflection_steps",
    "post_correlation_follow_up_calls",
    "observation_assessment",
    "correlation_analysis",
    "normalized_evidence",
    "aggregated_ioc_evidence",
    "tool_selection_trace",
    "tool_validation_trace",
    "agent_trace",
    "investigation_status",
    "investigation_confidence",
    "confidence_factors",
    "supporting_evidence",
    "inconclusive_reason",
    "attack_timeline",
    "current_stage",
    "tool_execution_round",
    "max_tool_execution_rounds",
    "reflection_round",
    "max_reflection_rounds",
)


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except TypeError:
            pass
    if hasattr(value, "item"):
        try:
            return value.item()
        except (TypeError, ValueError):
            pass
    if hasattr(value, "tolist"):
        try:
            return value.tolist()
        except (TypeError, ValueError):
            pass
    return value


def validation_profile_to_backend_profile(profile_name: str) -> str:
    lowered = str(profile_name or "").lower()
    if lowered == "windows_apt":
        return "windows_evtx"
    if lowered == "sysmon":
        return "windows_sysmon"
    raise ValueError(f"Unsupported runtime-like validation profile: {profile_name}")


def parse_with_validation_profile(
    *,
    evtx_path: Path,
    validation_row: dict[str, Any],
    settings: Any,
    max_lines: int,
):
    from modules.parsing import parse_log_file
    from services.parsing_service import (
        apply_template_enrichment,
        build_model_profile,
    )

    profile = build_model_profile(
        validation_profile_to_backend_profile(validation_row.get("profile")),
        settings,
    )
    parsed_df, templates = parse_log_file(
        str(evtx_path),
        depth=settings.drain_depth,
        sim_threshold=settings.drain_sim_threshold,
        max_children=settings.drain_max_children,
        template_strategy=profile["template_strategy"],
        max_lines=max_lines,
    )
    parsed_df, templates = apply_template_enrichment(
        parsed_df,
        templates,
        profile.get("template_enrichment", "none"),
    )
    return parsed_df, templates, profile


def detect_with_profile(parsed_df, selected_profile: dict[str, Any], settings: Any):
    from modules.anomaly import detect_anomalies_in_logs

    return detect_anomalies_in_logs(
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


def freeze_investigation_state(state: dict[str, Any]) -> dict[str, Any]:
    frozen = {
        key: json_safe(state.get(key))
        for key in STATE_KEYS_TO_FREEZE
        if key in state
    }
    frozen["investigation_summary"] = ""
    frozen["recommendations"] = []
    frozen["completed"] = False
    frozen["current_stage"] = "frozen_evidence"
    return frozen


def build_live_enrichment_summary(state: dict[str, Any]) -> dict[str, Any]:
    iocs = list(state.get("iocs_extracted") or [])
    tool_calls = list(state.get("tool_calls") or [])
    tool_results = list(state.get("tool_results") or [])
    compact_results = [compact_tool_result(result) for result in tool_results]
    internal_iocs = [ioc for ioc in iocs if is_internal_ioc(ioc)]
    return {
        "iocs_extracted_count": len(iocs),
        "internal_ioc_count": len(internal_iocs),
        "internal_iocs_sample": json_safe(internal_iocs[:10]),
        "tool_calls_count": len(tool_calls),
        "tool_results_count": len(tool_results),
        "tool_result_status_counts": summarize_dict_counts(compact_results, "status"),
        "tool_results_sample": compact_results[:20],
        "supporting_evidence_count": len(state.get("supporting_evidence") or []),
        "investigation_status": state.get("investigation_status"),
        "investigation_confidence": state.get("investigation_confidence"),
        "confidence_factors": state.get("confidence_factors") or [],
    }


def capture_case_evidence(
    *,
    case: dict[str, Any],
    validation_row: dict[str, Any],
    max_lines: int,
    runtime_root: Path,
) -> dict[str, Any]:
    load_runtime_env()
    ensure_backend_import_path()

    from config import settings
    from modules.agent import DFIRAgent

    class EvidenceCaptureDFIRAgent(DFIRAgent):
        def generate_summary(self, state):  # type: ignore[override]
            reason = "Frozen evidence captured before report-generation replay."
            return {
                "investigation_summary": "",
                "recommendations": [],
                "investigation_status": state.get("investigation_status") or "completed",
                "investigation_confidence": float(
                    state.get("investigation_confidence") or 0.0
                ),
                "confidence_factors": state.get("confidence_factors") or [reason],
                "supporting_evidence": state.get("supporting_evidence") or [],
                "inconclusive_reason": state.get("inconclusive_reason") or "",
                "current_stage": "frozen_evidence_capture_complete",
                "completed": True,
                "reasoning_steps": [reason],
                "agent_trace": [
                    self._agent_trace_event(
                        "report_generator", "skipped_for_frozen_capture", reason
                    )
                ],
            }

    start = time.time()
    root = evtx_root()
    evtx_path = case_path(case, root)
    run_dir = runtime_root / case["case_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / "capture_stdout.txt"
    case_fixture_path = run_dir / "frozen_evidence.json"

    stdout_buffer = io.StringIO()
    with contextlib.redirect_stdout(stdout_buffer):
        parsed_df, templates, selected_profile = parse_with_validation_profile(
            evtx_path=evtx_path,
            validation_row=validation_row,
            settings=settings,
            max_lines=max_lines,
        )
        results_df, anomalies_df = detect_with_profile(parsed_df, selected_profile, settings)

        local_llm = OllamaInvokeClient()
        agent = EvidenceCaptureDFIRAgent(
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
            anomalies_df,
            parsed_df,
            session_id=f"capture-{case['case_id']}",
        )

    stdout_text = stdout_buffer.getvalue()
    stdout_path.write_text(stdout_text, encoding="utf-8")

    anomalies_records = anomalies_df.to_dict("records")
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
        "llm_gate_anomalies": len(anomalies_df),
        "top_anomalous_events": summarize_dict_counts(
            anomalies_records, "actual_event", limit=10
        ),
        "validation_profile": validation_row.get("profile"),
        "validation_anomalies": validation_row.get("anomalies"),
        "validation_windows": validation_row.get("windows"),
        "validation_top_anomaly_actual_events": validation_row.get(
            "top_anomaly_actual_events"
        ),
    }
    capture_summary = investigation_state.get("investigation_summary") or ""
    frozen_case = {
        "case_id": case["case_id"],
        "tactic_folder": case["tactic_folder"],
        "relative_path": case["relative_path"],
        "expected_size_bytes": case.get("expected_size_bytes"),
        "expected_profile": case.get("expected_profile"),
        "expected_runtime_detected": case.get("expected_runtime_detected"),
        "expected_runtime_anomalies": case.get("expected_runtime_anomalies"),
        "expected_focus": case.get("expected_focus", []),
        "runtime_validation": json_safe(validation_row),
        "pipeline_evidence": json_safe(pipeline_evidence),
        "live_enrichment": json_safe(build_live_enrichment_summary(investigation_state)),
        "frozen_state": freeze_investigation_state(investigation_state),
        "capture_provenance": {
            "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            "capture_runtime_seconds": round(time.time() - start, 3),
            "subject_ollama_base_url": SUBJECT_BASE_URL,
            "subject_ollama_model": SUBJECT_MODEL,
            "runtime_profile_source": "runtime_like_validation_row",
            "stdout_path": str(stdout_path),
            "capture_summary_sha256": hashlib.sha256(
                capture_summary.encode("utf-8")
            ).hexdigest(),
            "capture_summary_chars": len(capture_summary),
        },
    }
    case_fixture_path.write_text(
        json.dumps(frozen_case, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    return frozen_case


def capture_frozen_evidence(
    *,
    output_path: Path = EVIDENCE_FIXTURE_PATH,
    runtime_root: Path = CAPTURE_RUNTIME_DIR,
    max_lines: int = DEFAULT_MAX_LINES,
    case_limit: int | None = None,
    resume: bool = True,
) -> dict[str, Any]:
    load_runtime_env()
    ensure_backend_import_path()
    preflight = full_pipeline_preflight_checks()
    if not preflight["ready"]:
        raise RuntimeError(
            "Evidence capture preflight failed: "
            + json.dumps(preflight, ensure_ascii=False, default=str)[:4000]
        )

    cases = load_cases()
    if case_limit is not None:
        cases = cases[:case_limit]
    validation_rows = load_runtime_validation_rows()

    frozen_cases = []
    for index, case in enumerate(cases, 1):
        print(
            f"[capture] {index}/{len(cases)} {case['case_id']} "
            f"({case['relative_path']})",
            flush=True,
        )
        validation_row = runtime_like_validation_for_case(case, validation_rows)
        existing_case_path = runtime_root / case["case_id"] / "frozen_evidence.json"
        if resume and existing_case_path.exists():
            frozen_case = json.loads(existing_case_path.read_text(encoding="utf-8"))
            print(f"[capture] resume hit {case['case_id']}", flush=True)
        else:
            frozen_case = capture_case_evidence(
                case=case,
                validation_row=validation_row,
                max_lines=max_lines,
                runtime_root=runtime_root,
            )
        frozen_cases.append(frozen_case)
        partial_payload = {
            "schema_version": "report_generation_frozen_evidence.v1",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "capture_mode": "one_full_pipeline_run_per_case",
            "source_cases_path": str(EVTX_CASES_PATH),
            "capture_runtime_dir": str(runtime_root),
            "config": {
                "subject_ollama_base_url": SUBJECT_BASE_URL,
                "subject_ollama_model": SUBJECT_MODEL,
                "max_lines": max_lines,
                "case_limit": case_limit,
                "resume": resume,
                "runtime_profile_source": "runtime_like_validation_row",
                "full_pipeline_results_reference": str(FULL_PIPELINE_RESULTS_PATH),
                "capture_complete": len(frozen_cases) == len(cases),
            },
            "preflight": preflight,
            "cases": frozen_cases,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(partial_payload, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(
            f"[capture] done {case['case_id']} in "
            f"{frozen_case['capture_provenance']['capture_runtime_seconds']}s",
            flush=True,
        )

    payload = {
        "schema_version": "report_generation_frozen_evidence.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capture_mode": "one_full_pipeline_run_per_case",
        "source_cases_path": str(EVTX_CASES_PATH),
        "capture_runtime_dir": str(runtime_root),
        "config": {
            "subject_ollama_base_url": SUBJECT_BASE_URL,
            "subject_ollama_model": SUBJECT_MODEL,
            "max_lines": max_lines,
            "case_limit": case_limit,
            "resume": resume,
            "runtime_profile_source": "runtime_like_validation_row",
            "full_pipeline_results_reference": str(FULL_PIPELINE_RESULTS_PATH),
            "capture_complete": True,
        },
        "preflight": preflight,
        "cases": frozen_cases,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    return payload


def load_frozen_evidence_payload(path: Path = EVIDENCE_FIXTURE_PATH) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"Frozen evidence fixture is missing: {path}. "
            "Run `python report_generation_geval_runner.py --capture-evidence` first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def frozen_fixture_status(path: Path = EVIDENCE_FIXTURE_PATH) -> dict[str, Any]:
    if not path.exists():
        return {
            "exists": False,
            "path": str(path),
            "case_count": 0,
            "all_cases_have_frozen_state": False,
            "all_cases_have_tool_evidence": False,
            "error": "fixture_missing",
        }
    payload = load_frozen_evidence_payload(path)
    cases = payload.get("cases", [])
    return {
        "exists": True,
        "path": str(path),
        "schema_version": payload.get("schema_version"),
        "generated_at_utc": payload.get("generated_at_utc"),
        "capture_mode": payload.get("capture_mode"),
        "case_count": len(cases),
        "all_cases_have_frozen_state": all(
            bool(case.get("frozen_state")) for case in cases
        ),
        "all_cases_have_tool_evidence": all(
            bool((case.get("live_enrichment") or {}).get("tool_results_count", 0) >= 0)
            and "tool_results" in (case.get("frozen_state") or {})
            for case in cases
        ),
        "cases": [
            {
                "case_id": case.get("case_id"),
                "relative_path": case.get("relative_path"),
                "tool_results_count": (case.get("live_enrichment") or {}).get(
                    "tool_results_count"
                ),
                "deeplog_anomalies": (case.get("pipeline_evidence") or {}).get(
                    "deeplog_anomalies"
                ),
            }
            for case in cases
        ],
    }


def preflight_replay_checks(path: Path = EVIDENCE_FIXTURE_PATH) -> dict[str, Any]:
    load_runtime_env()
    ensure_backend_import_path()
    fixture = frozen_fixture_status(path)
    status = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "fixture": fixture,
        "ollama": ollama_status(),
        "judge": judge_env_status(),
    }
    status["ready"] = bool(
        fixture["exists"]
        and fixture["case_count"] == EXPECTED_CASE_COUNT
        and fixture["all_cases_have_frozen_state"]
        and fixture["all_cases_have_tool_evidence"]
        and status["ollama"]["reachable"]
        and status["ollama"]["model_available"]
        and status["judge"]["env_ready"]
    )
    return status


def _compact_scalar(value: Any, *, max_chars: int = 160) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > max_chars:
        return text[: max_chars - 3].rstrip() + "..."
    return text


def _event_identity_from_text(text: Any) -> tuple[str, str]:
    normalized = _compact_scalar(text, max_chars=500)
    event_match = re.search(r"EventID\s*=?\s*(\d+)", normalized, flags=re.I)
    provider_match = re.search(
        r"Provider\s+(.+?)(?:\s+Channel|\s+Task|\s+Level|$)",
        normalized,
        flags=re.I,
    )
    event_id = event_match.group(1) if event_match else ""
    provider = provider_match.group(1).strip() if provider_match else ""
    return event_id, provider


def _count_positive_tool_results(tool_results: list[dict[str, Any]]) -> tuple[int, int]:
    malicious = 0
    suspicious = 0
    for result in tool_results:
        malicious += safe_int(result.get("malicious")) or 0
        suspicious += safe_int(result.get("suspicious")) or 0
        classification = str(result.get("classification") or "").lower()
        status = str(result.get("status") or "").lower()
        if "malicious" in classification:
            malicious += 1
        elif "suspicious" in classification:
            suspicious += 1
        elif status in {"malicious", "suspicious"}:
            suspicious += 1
    return malicious, suspicious


def _artifact_fields_from_line(line: dict[str, Any]) -> dict[str, str]:
    params = line.get("parameters") or {}
    important = line.get("important_fields") or {}
    identity = line.get("event_identity") or {}
    event_text = (
        line.get("event_template")
        or line.get("line_summary")
        or line.get("raw_line")
        or ""
    )
    event_id, provider = _event_identity_from_text(event_text)

    def first(*keys: str) -> str:
        for key in keys:
            for source in (params, important, identity, line):
                value = source.get(key) if isinstance(source, dict) else None
                if value not in (None, ""):
                    return _compact_scalar(value, max_chars=140)
        return ""

    return {
        "event_id": first("EventID", "event_id") or event_id,
        "provider": first("Provider", "provider") or provider,
        "channel": first("Channel", "channel"),
        "host": first("Computer", "ComputerName", "host", "domain"),
        "user": first(
            "SubjectUserName",
            "TargetUserName",
            "AccountName",
            "User",
            "user",
            "subject_user",
        ),
        "process": first("Image", "ProcessName", "process", "ParentImage"),
        "command": first("CommandLine", "command_line"),
        "share": first("ShareName", "share_name"),
        "path": first(
            "RelativeTargetName",
            "TargetFilename",
            "TargetObject",
            "ObjectName",
            "ShareLocalPath",
            "relative_target_name",
        ),
        "ip": first(
            "IpAddress",
            "SourceAddress",
            "DestinationIp",
            "destination_ip",
            "ip_1",
        ),
        "registry": first("TargetObject", "ObjectName", "registry_key"),
        "raw_summary": first("line_summary", "event_template", "raw_line"),
    }


def _sample_anomaly_evidence(anomalies: list[dict[str, Any]], limit: int = 8) -> list[str]:
    rows = []
    seen = set()
    for anomaly in anomalies:
        candidate_lines = []
        if isinstance(anomaly.get("anomalous_line"), dict):
            candidate_lines.append(anomaly["anomalous_line"])
        candidate_lines.extend(
            line for line in (anomaly.get("lines") or []) if isinstance(line, dict)
        )
        if not candidate_lines:
            event_text = anomaly.get("actual_event") or anomaly.get("predicted_event")
            event_id, provider = _event_identity_from_text(event_text)
            key = (event_id, provider, _compact_scalar(event_text, max_chars=80))
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                "- EventID {event_id} provider {provider}; evidence={summary}".format(
                    event_id=event_id or "unknown",
                    provider=provider or "unknown",
                    summary=_compact_scalar(event_text, max_chars=180),
                )
            )
            if len(rows) >= limit:
                break
            continue

        for line in candidate_lines:
            fields = _artifact_fields_from_line(line)
            key = (
                fields.get("event_id"),
                fields.get("provider"),
                fields.get("user"),
                fields.get("share"),
                fields.get("path"),
                fields.get("process"),
                fields.get("registry"),
                fields.get("ip"),
            )
            if key in seen:
                continue
            seen.add(key)
            details = [
                ("provider", fields.get("provider")),
                ("channel", fields.get("channel")),
                ("host", fields.get("host")),
                ("user", fields.get("user")),
                ("process", fields.get("process")),
                ("command", fields.get("command")),
                ("share", fields.get("share")),
                ("path", fields.get("path")),
                ("registry", fields.get("registry")),
                ("ip", fields.get("ip")),
            ]
            detail_text = "; ".join(
                f"{name}={value}" for name, value in details if value
            )
            rows.append(
                "- EventID {event_id}{detail_text}".format(
                    event_id=fields.get("event_id") or "unknown",
                    detail_text=f"; {detail_text}" if detail_text else "",
                )
            )
            if len(rows) >= limit:
                return rows
    return rows


def _format_counts(counts: dict[str, Any]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def _tactic_generation_guidance(tactic_folder: str) -> list[str]:
    guidance = {
        "Command and Control": [
            "Use BITS/OpenVPN/network-tunnel evidence only when logs or tool results support it.",
            "Do not label traffic as confirmed C2 unless enrichment or event evidence supports that claim.",
        ],
        "Credential Access": [
            "Focus on RPC/EFSR/PetitPotam-style evidence and affected account/host fields when present.",
            "If parsing reached the line cap, disclose the cap and avoid claiming complete coverage.",
        ],
        "Defense Evasion": [
            "For EventID 1102 or cleared-log evidence, explain audit-log tampering risk.",
            "Do not claim malware execution or compromise from log-clearing evidence alone.",
        ],
        "Discovery": [
            "Tie conclusions to account, group, directory object, or enumeration EventID evidence.",
            "Recommendations should validate who enumerated what and whether access was authorized.",
        ],
        "Execution": [
            "For MSI/EventID 1040/1042 evidence, distinguish installer execution from confirmed malicious payload.",
            "Use process, product, URL, user, and timestamp evidence when present.",
        ],
        "Lateral Movement": [
            "EventID 5145 remote share/file access is central evidence for this tactic.",
            "Mention remote share, source/destination IP or host, user, share path, and target path when present.",
            "Treat private/internal IOC enrichment as context; do not call it malicious without tool evidence.",
        ],
        "Persistence": [
            "Focus on DACL, DCSync right, permission change, registry, or scheduled persistence evidence.",
            "Do not claim credential theft unless the log evidence specifically supports it.",
        ],
        "Privilege Escalation": [
            "For Sysmon/unquoted service path evidence, cite service path, process, parent process, and file evidence.",
            "Keep severity tied to exploitability evidence, not only anomaly volume.",
        ],
    }
    return guidance.get(
        tactic_folder,
        ["Tie conclusions and recommendations to the selected EVTX tactic evidence."],
    )


def _report_safe_focus_item(item: Any) -> str:
    text = str(item or "").strip()
    replacements = {
        "avoid confirmed c2 claims without supporting event or enrichment evidence": (
            "C2 claims require supporting event or enrichment evidence"
        ),
    }
    lowered = text.lower()
    for source, replacement in replacements.items():
        if source in lowered:
            return re.sub(re.escape(source), replacement, text, flags=re.I)
    return re.sub(r"\bconfirmed\s+C2\b", "C2", text, flags=re.I)


def build_evidence_brief(frozen_case: dict[str, Any], state: dict[str, Any]) -> str:
    """Build a compact evidence contract for report-generation replay."""
    pipeline = frozen_case.get("pipeline_evidence") or {}
    live = frozen_case.get("live_enrichment") or {}
    validation = frozen_case.get("runtime_validation") or {}
    anomalies = list(state.get("anomalies") or [])
    iocs = list(state.get("iocs_extracted") or [])
    tool_results = list(state.get("tool_results") or [])
    malicious_count, suspicious_count = _count_positive_tool_results(tool_results)
    internal_iocs = [ioc for ioc in iocs if is_internal_ioc(ioc)]
    top_events = pipeline.get("top_anomalous_events") or {}
    tactic = frozen_case.get("tactic_folder")

    lines = [
        "## Evaluation Evidence Brief",
        "",
        "This brief is the evidence boundary for final-report generation. Claims must be supported by this frozen evidence.",
        "",
        "### Case",
        f"- case_id: {frozen_case.get('case_id')}",
        f"- tactic_folder: {tactic}",
        f"- evtx_relative_path: {frozen_case.get('relative_path')}",
        f"- validation_profile: {pipeline.get('validation_profile') or validation.get('profile')}",
        f"- parsed_events: {pipeline.get('parsed_events')}",
        f"- deeplog_anomalies: {pipeline.get('deeplog_anomalies')}",
        f"- max_lines: {pipeline.get('max_lines')}",
        f"- max_lines_reached: {pipeline.get('max_lines_reached')}",
        "",
        "### Expected Focus",
    ]
    expected_focus = [
        _report_safe_focus_item(item)
        for item in list(frozen_case.get("expected_focus") or [])
        if str(item or "").strip()
    ]
    if expected_focus:
        lines.extend(f"- {item}" for item in expected_focus)
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
        "### Severity Calibration Rules",
        "- The anomaly count is not equal to compromise count.",
        "- High anomaly volume can indicate telemetry concentration, model surprise, or repeated similar events.",
        "- Private/internal IOC values must be treated as private/internal telemetry unless tool evidence says otherwise.",
        "- Tool status error/no_result is not malicious evidence.",
        "- Malware, C2, exfiltration, or compromise claims require log artifacts or positive enrichment.",
        "",
        "### Tactic-Specific Guidance",
        f"- Tactic lock: analyze this case as {tactic}. If an ATT&CK technique cannot be supported from evidence, say technique not assigned.",
        "- Do not switch tactic because generic process, registry, network, or command fields appear in the telemetry.",
        ]
    )
    lines.extend(
        f"- {_report_safe_focus_item(item)}"
        for item in _tactic_generation_guidance(str(tactic or ""))
    )
    lines.extend(
        [
            "",
            "### Runtime and Tool Evidence",
            f"- top_anomalous_events: {_format_counts(top_events)}",
            f"- extracted_iocs: {live.get('iocs_extracted_count', len(iocs))}",
            f"- private/internal_iocs: {live.get('internal_ioc_count', len(internal_iocs))}",
            f"- tool_results: {live.get('tool_results_count', len(tool_results))}",
            f"- tool_status_counts: {_format_counts(live.get('tool_result_status_counts') or {})}",
            f"- positive_tool_counts: malicious={malicious_count}, suspicious={suspicious_count}",
            "",
            "### Internal/Private IOC Sample",
        ]
    )
    if internal_iocs:
        for ioc in internal_iocs[:8]:
            lines.append(
                "- {value} ({ioc_type})".format(
                    value=_compact_scalar(ioc.get("value") or ioc.get("ioc")),
                    ioc_type=ioc.get("type") or ioc.get("ioc_type"),
                )
            )
    else:
        lines.append("- none")

    lines.extend(["", "### Representative Log Evidence"])
    evidence_rows = _sample_anomaly_evidence(anomalies)
    if evidence_rows:
        lines.extend(evidence_rows)
    else:
        lines.append("- No representative anomaly rows available in frozen state.")

    lines.extend(
        [
            "",
            "### Reporting Requirements",
            "- Cite EventID/provider/host/user/process/share/path/registry evidence where present.",
            "- Explain limitations for empty enrichment, enrichment errors, private IOC scope, and parser cap when applicable.",
            "- Make recommendations specific to the tactic and observed artifacts.",
            "- Do not output placeholders such as [Action item], [Mitigation measure], or generic bracketed instructions.",
            "- Keep the report concise enough for analyst review; prioritize evidence, limitations, and next actions.",
        ]
    )
    return "\n".join(lines)


def inject_evidence_brief_into_prompt(prompt: str, evidence_brief: str) -> str:
    injection = (
        "\n\n"
        "## HARD EVIDENCE CONTRACT FOR THIS EVALUATION\n"
        "Use the following frozen evidence brief as the primary boundary for the final report. "
        "Do not invent malware families, C2, exfiltration, credential theft, or compromise beyond this evidence. "
        "Do not include unsupported ATT&CK tactic mappings. Do not emit template placeholders.\n\n"
        f"{evidence_brief}\n"
    )
    markers = ("## OUTPUT REQUIREMENTS", "### OUTPUT REQUIREMENTS", "Output Requirements")
    for marker in markers:
        index = prompt.find(marker)
        if index >= 0:
            return prompt[:index].rstrip() + injection + "\n\n" + prompt[index:]
    return prompt.rstrip() + injection


def resolve_metric_names(
    metric_preset: str = "full",
    metric_names: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    if metric_names:
        selected = tuple(name.strip() for name in metric_names if name.strip())
    else:
        try:
            selected = REPORT_GENERATION_METRIC_PRESETS[metric_preset]
        except KeyError as exc:
            raise ValueError(f"Unsupported metric preset: {metric_preset}") from exc
    unknown = sorted(set(selected) - set(REPORT_GENERATION_METRIC_NAMES))
    if unknown:
        raise ValueError(f"Unsupported report-generation metric(s): {unknown}")
    return selected


def default_output_modes_for_preset(metric_preset: str) -> tuple[str, ...]:
    try:
        return CLI_DEFAULT_OUTPUT_MODES_BY_PRESET[metric_preset]
    except KeyError as exc:
        raise ValueError(f"Unsupported metric preset: {metric_preset}") from exc


def _first_event_id_from_case(case: dict[str, Any]) -> str:
    pipeline = case.get("pipeline_evidence") or {}
    top_events = pipeline.get("top_anomalous_events") or {}
    for event_text in top_events:
        event_id, _provider = _event_identity_from_text(event_text)
        if event_id:
            return event_id
    validation = case.get("runtime_validation") or {}
    event_text = validation.get("top_anomaly_actual_events") or ""
    event_id, _provider = _event_identity_from_text(event_text)
    return event_id


def _positive_tool_counts_from_case(case: dict[str, Any]) -> tuple[int, int]:
    state = case.get("frozen_state") or {}
    return _count_positive_tool_results(list(state.get("tool_results") or []))


def _tool_status_count(case: dict[str, Any], *statuses: str) -> int:
    live = case.get("live_enrichment") or {}
    counts = live.get("tool_result_status_counts") or {}
    wanted = {status.lower() for status in statuses}
    return sum(
        int(value or 0)
        for key, value in counts.items()
        if str(key).lower() in wanted
    )


def run_deterministic_report_checks(
    *,
    case: dict[str, Any],
    output_mode: str,
    actual_output: str,
    threshold: float = DEFAULT_DETERMINISTIC_THRESHOLD,
) -> dict[str, Any]:
    text = str(actual_output or "")
    lowered = text.lower()
    event_id = _first_event_id_from_case(case)
    tactic = str(case.get("tactic_folder") or "")
    live = case.get("live_enrichment") or {}
    malicious_count, suspicious_count = _positive_tool_counts_from_case(case)
    enrichment_has_limits = _tool_status_count(
        case, "error", "no_result", "hash_not_found"
    ) > 0
    has_internal_iocs = int(live.get("internal_ioc_count") or 0) > 0

    checks = [
        {
            "name": "non_empty_output",
            "success": len(text.strip()) >= 80,
            "reason": "Output should contain substantive report text.",
        },
        {
            "name": "no_template_placeholders",
            "success": not bool(
                re.search(
                    r"\[(?:action item|mitigation measure|specific steps|"
                    r"recommended action|placeholder|todo)[^\]]*\]",
                    lowered,
                    flags=re.I,
                )
            ),
            "reason": "Output should not contain bracketed template placeholders.",
        },
        {
            "name": "mentions_primary_event",
            "success": bool(
                not event_id
                or re.search(rf"eventid\s*=?\s*{re.escape(str(event_id))}\b", lowered)
            ),
            "reason": f"Output should cite primary EventID {event_id} when available.",
        },
        {
            "name": "mentions_tactic_or_artifact",
            "success": bool(
                tactic.lower() in lowered
                or (event_id and f"eventid {event_id}".lower() in lowered)
            ),
            "reason": "Output should mention the selected tactic or its primary artifact.",
        },
        {
            "name": "states_enrichment_limitations",
            "success": bool(
                not enrichment_has_limits
                or any(
                    token in lowered
                    for token in (
                        "limitation",
                        "limitations",
                        "keterbatasan",
                        "enrichment",
                        "tidak tersedia",
                        "no_result",
                        "no result",
                        "error",
                    )
                )
            ),
            "reason": "Output should disclose missing, empty, or error enrichment evidence.",
        },
        {
            "name": "calibrates_internal_iocs",
            "success": bool(
                not has_internal_iocs
                or any(
                    token in lowered
                    for token in ("private", "internal", "lokal", "local")
                )
            ),
            "reason": "Output should treat private/internal IOC values as local telemetry.",
        },
        {
            "name": "avoids_unsupported_confirmed_claims",
            "success": bool(
                malicious_count > 0
                or suspicious_count > 0
                or not re.search(
                    r"(confirmed|terkonfirmasi|terbukti).{0,40}"
                    r"(malware|c2|command and control|exfiltration|compromise|kompromi)",
                    lowered,
                    flags=re.I,
                )
            ),
            "reason": "Output should not make confirmed malicious/C2/exfiltration/compromise claims without positive evidence.",
        },
        {
            "name": "has_actionable_recommendation_evidence",
            "success": bool(
                any(
                    token in lowered
                    for token in (
                        "recommend",
                        "recommendation",
                        "rekomendasi",
                        "tindak lanjut",
                        "triage",
                        "triase",
                    )
                )
                and any(
                    token in lowered
                    for token in (
                        "eventid",
                        "user",
                        "process",
                        "registry",
                        "share",
                        "host",
                        "ip",
                    )
                )
            ),
            "reason": "Output should include recommendations tied to concrete evidence.",
        },
    ]
    passed = sum(1 for check in checks if check["success"])
    score = passed / len(checks) if checks else 0.0
    failed = [check for check in checks if not check["success"]]
    return {
        "mode": "deterministic_v1",
        "output_mode": output_mode,
        "score": score,
        "threshold": threshold,
        "success": score >= threshold,
        "checks": checks,
        "failed_checks": failed,
        "reason": "All deterministic checks passed."
        if not failed
        else "; ".join(check["name"] for check in failed),
    }


def build_report_generation_metrics(
    judge_model: Any,
    threshold: float,
    metric_names: tuple[str, ...] | None = None,
) -> list[GEval]:
    common_params = [
        SingleTurnParams.INPUT,
        SingleTurnParams.ACTUAL_OUTPUT,
        SingleTurnParams.EXPECTED_OUTPUT,
        SingleTurnParams.CONTEXT,
    ]
    specs = [
        (
            "Evidence Groundedness",
            [
                "Compare the report against the frozen EVTX evidence brief and context.",
                "Reward concrete references to EventID, provider, host, user, process, share, path, registry, timeline, or tool result evidence.",
                "Penalize unsupported claims, invented attack facts, and claims that exceed the provided evidence boundary.",
            ],
        ),
        (
            "Severity Calibration",
            [
                "Check whether severity and confidence are proportional to log evidence, positive enrichment, anomaly volume, and limitations.",
                "Penalize treating anomaly count as compromise count.",
                "Penalize treating private/internal IOCs, no_result, or error tool statuses as malicious evidence.",
            ],
        ),
        (
            "Tactic Alignment",
            [
                "Check whether the report aligns with the selected EVTX tactic folder and tactic-specific evidence.",
                "Reward correct use of tactic-relevant artifacts such as EventID 5145 for Lateral Movement or EventID 1102 for Defense Evasion.",
                "Penalize drifting into unrelated tactics without supporting evidence.",
            ],
        ),
        (
            "Recommendation Specificity",
            [
                "Evaluate whether recommendations are actionable and tied to observed artifacts, accounts, hosts, processes, shares, registry keys, or IOC evidence.",
                "Reward recommendations specific to the tactic and evidence.",
                "Penalize generic advice that could apply to any incident.",
            ],
        ),
        (
            "Limitation Honesty",
            [
                "Check whether the report explicitly states evidence limitations when enrichment is empty, errors occur, IOCs are private/internal, or parsing hits a cap.",
                "Reward clear uncertainty language and bounded conclusions.",
                "Penalize hiding missing evidence or presenting inconclusive enrichment as confirmed maliciousness.",
            ],
        ),
    ]
    selected_names = set(
        REPORT_GENERATION_METRIC_NAMES if metric_names is None else metric_names
    )
    return [
        GEval(
            name=name,
            evaluation_steps=steps,
            evaluation_params=common_params,
            model=judge_model,
            threshold=threshold,
            async_mode=False,
            verbose_mode=False,
        )
        for name, steps in specs
        if name in selected_names
    ]


def build_report_generation_expected_output(
    case: dict[str, Any],
    validation_row: dict[str, Any],
    evidence_brief: str,
) -> str:
    focus = "\n".join(f"- {item}" for item in case.get("expected_focus", []))
    guidance = "\n".join(
        f"- {item}" for item in _tactic_generation_guidance(case.get("tactic_folder") or "")
    )
    return f"""A correct FirstPrototype report for this EVTX report-generation replay should:
- Identify the selected tactic folder as {case['tactic_folder']}.
- Ground claims in the frozen evidence brief, EVTX log artifacts, runtime validation, and frozen tool evidence.
- Cite relevant EventID/provider/window/timeline/host/user/process/share/path/registry/tool evidence when available.
- Treat private IPs and internal domains as local telemetry unless positive enrichment supports a stronger claim.
- Treat the anomaly count as detection volume, not compromise count.
- Calibrate severity and confidence to evidence quality, live enrichment result, missing-data conditions, and parser cap.
- Provide specific DFIR recommendations for the tactic and observed artifacts.
- State limitations for empty/error enrichment, private/internal IOC scope, and capped parsing when applicable.

Expected focus:
{focus}

Tactic guidance:
{guidance}

Runtime-like validation baseline:
- profile: {validation_row.get('profile')}
- parsed events: {validation_row.get('parsed_events')}
- windows: {validation_row.get('windows')}
- anomalies: {validation_row.get('anomalies')}
- detected: {validation_row.get('detected')}

Evidence brief:
{evidence_brief}
"""


def build_report_generation_eval_context(
    case: dict[str, Any],
    validation_row: dict[str, Any],
    run_record: dict[str, Any],
    evidence_brief: str,
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
                    "parsed_events": validation_row.get("parsed_events"),
                    "windows": validation_row.get("windows"),
                    "anomalies": validation_row.get("anomalies"),
                    "top_anomaly_actual_events": validation_row.get(
                        "top_anomaly_actual_events"
                    ),
                },
                "pipeline_evidence": run_record["pipeline_evidence"],
                "live_enrichment": run_record["live_enrichment"],
                "evidence_brief": evidence_brief,
            },
            ensure_ascii=False,
        )
    ]


def output_for_report_generation_mode(
    run_record: dict[str, Any],
    output_mode: str,
) -> str:
    if output_mode == "summary":
        recommendations = run_record.get("llm_recommendations") or []
        recommendation_text = "\n".join(f"- {item}" for item in recommendations)
        return (
            f"{run_record.get('llm_summary') or ''}\n\n"
            "Extracted Recommendations:\n"
            f"{recommendation_text}"
        ).strip()
    return output_for_mode(run_record["report"], run_record["markdown"], output_mode)


def load_judge_cache(path: Path = JUDGE_CACHE_PATH) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_judge_cache(cache: dict[str, Any], path: Path = JUDGE_CACHE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(cache, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )


def judge_cache_key(
    *,
    case: dict[str, Any],
    output_mode: str,
    output_sha256: str,
    threshold: float,
    metric_names: tuple[str, ...],
) -> str:
    payload = {
        "schema": "report_generation_geval_judge_cache.v1",
        "case_id": case.get("case_id"),
        "relative_path": case.get("relative_path"),
        "output_mode": output_mode,
        "output_sha256": output_sha256,
        "threshold": threshold,
        "metric_names": list(metric_names),
        "judge_base_url": os.getenv("OPENAI_BASE_URL"),
        "judge_model": os.getenv("OPENAI_MODEL_NAME"),
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _deterministic_only_result(
    *,
    output_mode: str,
    actual_output: str,
    threshold: float,
    deterministic: dict[str, Any],
    skip_reason: str,
) -> dict[str, Any]:
    return {
        "output_mode": output_mode,
        "score": float(deterministic.get("score") or 0.0),
        "success": bool(deterministic.get("success")),
        "threshold": threshold,
        "reason": deterministic.get("reason") or skip_reason,
        "error": None,
        "assertion_error": None,
        "judge_error": False,
        "judge_skipped": True,
        "judge_skip_reason": skip_reason,
        "judge_cache_hit": False,
        "metric_mode": "deterministic_v1",
        "dimension_pass_rate": 0.0,
        "all_dimensions_successful": False,
        "metric_scores": [],
        "deterministic_checks": deterministic,
        "output_sha256": hashlib.sha256(actual_output.encode("utf-8")).hexdigest(),
        "output_chars": len(actual_output),
    }


def measure_output_with_dimensions(
    *,
    case: dict[str, Any],
    validation_row: dict[str, Any],
    run_record: dict[str, Any],
    output_mode: str,
    actual_output: str,
    judge_model: Any,
    threshold: float,
    metric_names: tuple[str, ...] | None = None,
    deterministic_threshold: float = DEFAULT_DETERMINISTIC_THRESHOLD,
    skip_judge_if_deterministic_fails: bool = False,
    judge_cache: dict[str, Any] | None = None,
    use_judge_cache: bool = True,
) -> dict[str, Any]:
    output_sha256 = hashlib.sha256(actual_output.encode("utf-8")).hexdigest()
    selected_metric_names = (
        REPORT_GENERATION_METRIC_NAMES if metric_names is None else metric_names
    )
    deterministic = run_deterministic_report_checks(
        case=case,
        output_mode=output_mode,
        actual_output=actual_output,
        threshold=deterministic_threshold,
    )
    if not selected_metric_names:
        return _deterministic_only_result(
            output_mode=output_mode,
            actual_output=actual_output,
            threshold=threshold,
            deterministic=deterministic,
            skip_reason="metric_preset_smoke",
        )
    if skip_judge_if_deterministic_fails and not deterministic["success"]:
        return _deterministic_only_result(
            output_mode=output_mode,
            actual_output=actual_output,
            threshold=threshold,
            deterministic=deterministic,
            skip_reason="deterministic_precheck_failed",
        )

    cache_key = judge_cache_key(
        case=case,
        output_mode=output_mode,
        output_sha256=output_sha256,
        threshold=threshold,
        metric_names=selected_metric_names,
    )
    if use_judge_cache and judge_cache is not None and cache_key in judge_cache:
        cached = copy.deepcopy(judge_cache[cache_key])
        cached["judge_cache_hit"] = True
        cached["deterministic_checks"] = deterministic
        cached["output_sha256"] = output_sha256
        cached["output_chars"] = len(actual_output)
        return cached

    evidence_brief = run_record.get("evidence_brief") or build_evidence_brief(
        case, case.get("frozen_state") or {}
    )
    test_case = LLMTestCase(
        name=f"{case['case_id']}::{output_mode}::run_{run_record['repetition']}",
        input=(
            "Evaluate the FirstPrototype final EVTX DFIR report. "
            f"Output mode: {output_mode}. "
            "Use the frozen evidence brief and context as the evidence boundary."
        ),
        actual_output=actual_output,
        expected_output=build_report_generation_expected_output(
            case, validation_row, evidence_brief
        ),
        context=build_report_generation_eval_context(
            case, validation_row, run_record, evidence_brief
        ),
        metadata={
            "case_id": case["case_id"],
            "tactic_folder": case["tactic_folder"],
            "relative_path": case["relative_path"],
            "output_mode": output_mode,
            "repetition": run_record["repetition"],
            "subject_model": SUBJECT_MODEL,
        },
    )

    metric_rows = []
    for metric in build_report_generation_metrics(
        judge_model, threshold, metric_names=selected_metric_names
    ):
        assertion_error = None
        try:
            assert_test(test_case, [metric], run_async=False)
        except AssertionError as exc:
            assertion_error = str(exc)
        except Exception as exc:
            metric.error = str(exc)
            assertion_error = str(exc)
        score = float(metric.score if metric.score is not None else 0.0)
        metric_rows.append(
            {
                "name": metric.name,
                "score": score,
                "success": bool(metric.is_successful())
                if metric.score is not None
                else False,
                "threshold": threshold,
                "reason": metric.reason,
                "error": getattr(metric, "error", None),
                "assertion_error": assertion_error,
            }
        )

    scores = [row["score"] for row in metric_rows]
    mean_score = mean(scores) if scores else 0.0
    judge_error = any(row.get("error") for row in metric_rows)
    weak_reasons = [
        f"{row['name']}: {row.get('reason') or row.get('error') or row.get('assertion_error')}"
        for row in metric_rows
        if row["score"] < threshold or row.get("error") or row.get("assertion_error")
    ]
    result = {
        "output_mode": output_mode,
        "score": float(mean_score),
        "success": bool(mean_score >= threshold)
        and not judge_error,
        "threshold": threshold,
        "reason": " | ".join(_compact_scalar(reason, max_chars=240) for reason in weak_reasons[:3])
        or "All report-generation dimensions met or exceeded threshold.",
        "error": None,
        "assertion_error": None,
        "judge_error": judge_error,
        "judge_skipped": False,
        "judge_skip_reason": "",
        "judge_cache_hit": False,
        "metric_mode": "dimensional_v1",
        "dimension_pass_rate": (
            sum(1 for row in metric_rows if row["success"]) / len(metric_rows)
            if metric_rows
            else 0.0
        ),
        "all_dimensions_successful": all(row["success"] for row in metric_rows)
        if metric_rows
        else False,
        "metric_scores": metric_rows,
        "deterministic_checks": deterministic,
        "output_sha256": output_sha256,
        "output_chars": len(actual_output),
    }
    if (
        use_judge_cache
        and judge_cache is not None
        and not result["judge_error"]
        and not result["judge_skipped"]
    ):
        judge_cache[cache_key] = copy.deepcopy(result)
    return result


def compact_case_for_results(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "tactic_folder": case.get("tactic_folder"),
        "relative_path": case.get("relative_path"),
        "expected_size_bytes": case.get("expected_size_bytes"),
        "expected_profile": case.get("expected_profile"),
        "expected_runtime_detected": case.get("expected_runtime_detected"),
        "expected_runtime_anomalies": case.get("expected_runtime_anomalies"),
        "expected_focus": case.get("expected_focus", []),
        "runtime_validation": case.get("runtime_validation"),
        "pipeline_evidence": case.get("pipeline_evidence"),
        "live_enrichment": case.get("live_enrichment"),
        "capture_provenance": case.get("capture_provenance"),
        "frozen_state_omitted": True,
    }


def filter_cases(
    cases: list[dict[str, Any]],
    selectors: tuple[str, ...] | None,
) -> list[dict[str, Any]]:
    if not selectors:
        return cases
    wanted = {selector.strip().lower() for selector in selectors if selector.strip()}
    selected = [
        case
        for case in cases
        if str(case.get("case_id") or "").lower() in wanted
        or str(case.get("tactic_folder") or "").lower() in wanted
        or str(case.get("relative_path") or "").lower() in wanted
    ]
    if not selected:
        raise ValueError(
            "No frozen evidence cases matched selectors: "
            + ", ".join(sorted(wanted))
        )
    return selected


def replay_generation_for_case(
    *,
    frozen_case: dict[str, Any],
    repetition: int,
    runtime_root: Path,
) -> dict[str, Any]:
    load_runtime_env()
    ensure_backend_import_path()

    from modules.agent import DFIRAgent
    from modules.report import ReportGenerator

    start = time.time()
    case_id = frozen_case["case_id"]
    run_dir = runtime_root / case_id / f"run_{repetition}"
    run_dir.mkdir(parents=True, exist_ok=True)

    evidence_brief = build_evidence_brief(
        frozen_case, frozen_case.get("frozen_state") or {}
    )
    evidence_brief_path = run_dir / "evidence_brief.md"
    evidence_brief_path.write_text(evidence_brief, encoding="utf-8")

    class EvidenceBriefDFIRAgent(DFIRAgent):
        def _create_report_prompt(self, state):  # type: ignore[override]
            base_prompt = super()._create_report_prompt(state)
            return inject_evidence_brief_into_prompt(base_prompt, evidence_brief)

    local_llm = OllamaInvokeClient(
        timeout_seconds=int(os.getenv("EVAL_REPORT_GENERATION_OLLAMA_TIMEOUT", "360"))
    )
    agent = EvidenceBriefDFIRAgent(
        ollama_base_url=SUBJECT_BASE_URL,
        ollama_model=SUBJECT_MODEL,
        threat_intel_api_keys={},
        llm=local_llm,
        provider_name="ollama",
    )
    agent.session_id = f"replay-{case_id}-run-{repetition}"

    state = copy.deepcopy(frozen_case["frozen_state"])
    state["investigation_summary"] = ""
    state["recommendations"] = []
    state["evaluation_evidence_brief"] = evidence_brief
    stdout_buffer = io.StringIO()
    with contextlib.redirect_stdout(stdout_buffer):
        summary_update = agent.generate_summary(state)
        replay_state = {**state, **summary_update}
        report_generator = ReportGenerator()
        report = report_generator.generate_report(
            f"replay-{case_id}-run-{repetition}",
            Path(frozen_case["relative_path"]).name,
            replay_state,
        )
        markdown = report_generator._to_markdown(report)

    json_path = run_dir / "report.json"
    markdown_path = run_dir / "report.md"
    state_path = run_dir / "replay_state_summary.json"
    stdout_path = run_dir / "stdout.txt"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    markdown_path.write_text(markdown, encoding="utf-8")
    stdout_path.write_text(stdout_buffer.getvalue(), encoding="utf-8")
    state_path.write_text(
        json.dumps(
            {
                "investigation_summary_chars": len(
                    replay_state.get("investigation_summary") or ""
                ),
                "recommendations_count": len(replay_state.get("recommendations") or []),
                "investigation_status": replay_state.get("investigation_status"),
                "investigation_confidence": replay_state.get(
                    "investigation_confidence"
                ),
                "evidence_brief_chars": len(evidence_brief),
                "evidence_brief_path": str(evidence_brief_path),
            },
            ensure_ascii=False,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    return {
        "case_id": case_id,
        "tactic_folder": frozen_case["tactic_folder"],
        "relative_path": frozen_case["relative_path"],
        "repetition": repetition,
        "runtime_seconds": round(time.time() - start, 3),
        "report_json_path": str(json_path),
        "report_markdown_path": str(markdown_path),
        "evidence_brief_path": str(evidence_brief_path),
        "state_summary_path": str(state_path),
        "stdout_path": str(stdout_path),
        "pipeline_evidence": frozen_case["pipeline_evidence"],
        "live_enrichment": frozen_case["live_enrichment"],
        "evidence_brief": evidence_brief,
        "llm_summary": summary_update.get("investigation_summary") or "",
        "llm_recommendations": summary_update.get("recommendations") or [],
        "report": report,
        "markdown": markdown,
        "stdout_excerpt": stdout_buffer.getvalue()[-2000:],
    }


def summarize_results(cases: list[dict[str, Any]], run_results: list[dict[str, Any]]):
    output_results = [
        output for run in run_results for output in run.get("output_evaluations", [])
    ]
    quality_output_results = [
        output for output in output_results if not output.get("judge_error")
    ]
    dimension_rows = [
        metric
        for output in output_results
        for metric in output.get("metric_scores", [])
    ]
    by_mode: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_tactic: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_dimension: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for output in output_results:
        by_mode[output["output_mode"]].append(output)
    for run in run_results:
        for output in run.get("output_evaluations", []):
            by_tactic[run["tactic_folder"]].append(output)
    for row in dimension_rows:
        by_dimension[row["name"]].append(row)

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

    dimension_summary = {}
    for dimension, rows in by_dimension.items():
        scores = [row["score"] for row in rows]
        dimension_summary[dimension] = {
            "runs": len(rows),
            "mean_score": mean(scores) if scores else 0.0,
            "score_stddev": pstdev(scores) if len(scores) > 1 else 0.0,
            "pass_rate": sum(1 for row in rows if row["success"]) / len(rows)
            if rows
            else 0.0,
            "min_score": min(scores) if scores else 0.0,
            "max_score": max(scores) if scores else 0.0,
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
            "pass_rate": sum(1 for row in output_rows if row["success"])
            / len(output_rows)
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
        "judge_error_output_evaluations": sum(
            1 for row in output_results if row.get("judge_error")
        ),
        "judge_skipped_output_evaluations": sum(
            1 for row in output_results if row.get("judge_skipped")
        ),
        "judge_cache_hit_output_evaluations": sum(
            1 for row in output_results if row.get("judge_cache_hit")
        ),
        "deterministic_failed_output_evaluations": sum(
            1
            for row in output_results
            if not (row.get("deterministic_checks") or {}).get("success", True)
        ),
        "quality_output_evaluations": len(quality_output_results),
        "json_output_runs": len(by_mode.get("json", [])),
        "markdown_output_runs": len(by_mode.get("markdown", [])),
        "mean_geval_score": mean([row["score"] for row in output_results])
        if output_results
        else 0.0,
        "mean_quality_geval_score": mean(
            [row["score"] for row in quality_output_results]
        )
        if quality_output_results
        else 0.0,
        "pass_rate": sum(1 for row in output_results if row["success"])
        / len(output_results)
        if output_results
        else 0.0,
        "quality_pass_rate": sum(
            1 for row in quality_output_results if row["success"]
        )
        / len(quality_output_results)
        if quality_output_results
        else 0.0,
        "macro_average_by_tactic": tactic_summary,
        "output_mode_summary": mode_summary,
        "metric_dimension_summary": dimension_summary,
        "case_stability": case_stability,
    }


def run_report_generation_geval_evaluation(
    *,
    fixture_path: Path = EVIDENCE_FIXTURE_PATH,
    repetitions: int = DEFAULT_REPETITIONS,
    threshold: float = DEFAULT_THRESHOLD,
    output_modes: tuple[str, ...] = DEFAULT_OUTPUT_MODES,
    results_path: Path = LATEST_RESULTS_PATH,
    runtime_root: Path = RUNTIME_DIR,
    case_limit: int | None = None,
    case_selectors: tuple[str, ...] | None = None,
    metric_preset: str = "full",
    metric_names: tuple[str, ...] | None = None,
    deterministic_threshold: float = DEFAULT_DETERMINISTIC_THRESHOLD,
    skip_judge_if_deterministic_fails: bool = False,
    use_judge_cache: bool = True,
    judge_cache_path: Path = JUDGE_CACHE_PATH,
) -> dict[str, Any]:
    load_runtime_env()
    ensure_backend_import_path()
    selected_metric_names = resolve_metric_names(metric_preset, metric_names)
    judge_required = bool(selected_metric_names)
    preflight = preflight_replay_checks(fixture_path)
    fixture_case_count = int((preflight.get("fixture") or {}).get("case_count") or 0)
    partial_fixture_allowed = case_limit is not None and fixture_case_count >= case_limit
    fixture_basic_ready = bool(
        (preflight.get("fixture") or {}).get("exists")
        and (preflight.get("fixture") or {}).get("all_cases_have_frozen_state")
        and (preflight.get("fixture") or {}).get("all_cases_have_tool_evidence")
        and preflight.get("ollama", {}).get("reachable")
        and preflight.get("ollama", {}).get("model_available")
        and (not judge_required or preflight.get("judge", {}).get("env_ready"))
    )
    preflight_ready = bool(
        preflight["ready"] or (not judge_required and fixture_basic_ready)
    )
    if not preflight_ready and not (partial_fixture_allowed and fixture_basic_ready):
        raise RuntimeError(
            "Report-generation replay preflight failed: "
            + json.dumps(preflight, ensure_ascii=False, default=str)[:4000]
        )

    fixture = load_frozen_evidence_payload(fixture_path)
    cases = filter_cases(fixture.get("cases", []), case_selectors)
    if case_limit is not None:
        cases = cases[:case_limit]
    result_cases = [compact_case_for_results(case) for case in cases]
    judge_model = build_judge_model() if judge_required else None
    judge_cache = load_judge_cache(judge_cache_path) if use_judge_cache else {}
    config = {
        "subject_under_test": "FirstPrototype report generation from frozen evidence",
        "evidence_mode": "frozen_replay",
        "prompt_strategy": "evidence_brief_tactic_guided_v1",
        "geval_metric_mode": "dimensional_v1"
        if selected_metric_names
        else "deterministic_v1",
        "metric_preset": metric_preset,
        "metric_dimensions": list(selected_metric_names),
        "deterministic_threshold": deterministic_threshold,
        "skip_judge_if_deterministic_fails": skip_judge_if_deterministic_fails,
        "judge_cache_enabled": use_judge_cache,
        "judge_cache_path": str(judge_cache_path),
        "capture_mode": fixture.get("capture_mode"),
        "fixture_generated_at_utc": fixture.get("generated_at_utc"),
        "subject_llm_provider": "ollama",
        "subject_ollama_base_url": SUBJECT_BASE_URL,
        "subject_ollama_model": SUBJECT_MODEL,
        "judge_provider": "deepeval GPTModel with OpenAI-compatible endpoint",
        "judge_base_url": os.getenv("OPENAI_BASE_URL"),
        "judge_model": os.getenv("OPENAI_MODEL_NAME"),
        "threshold": threshold,
        "repetitions": repetitions,
        "output_modes": list(output_modes),
        "case_selectors": list(case_selectors or []),
        "case_limit": case_limit,
        "live_threat_intel_per_replay": False,
        "results_case_payload": "compact_without_frozen_state",
    }

    run_results = []
    for case_index, frozen_case in enumerate(cases, 1):
        for repetition in range(1, repetitions + 1):
            print(
                f"[replay] case {case_index}/{len(cases)} "
                f"{frozen_case['case_id']} run {repetition}/{repetitions}",
                flush=True,
            )
            run_record = replay_generation_for_case(
                frozen_case=frozen_case,
                repetition=repetition,
                runtime_root=runtime_root,
            )
            output_evaluations = []
            for output_mode in output_modes:
                actual_output = output_for_report_generation_mode(
                    run_record, output_mode
                )
                output_evaluations.append(
                    measure_output_with_dimensions(
                        case=frozen_case,
                        validation_row=frozen_case["runtime_validation"],
                        run_record=run_record,
                        output_mode=output_mode,
                        actual_output=actual_output,
                        judge_model=judge_model,
                        threshold=threshold,
                        metric_names=selected_metric_names,
                        deterministic_threshold=deterministic_threshold,
                        skip_judge_if_deterministic_fails=(
                            skip_judge_if_deterministic_fails
                        ),
                        judge_cache=judge_cache,
                        use_judge_cache=use_judge_cache,
                    )
                )
            if use_judge_cache and judge_required:
                save_judge_cache(judge_cache, judge_cache_path)
            run_record["output_evaluations"] = output_evaluations
            del run_record["report"]
            del run_record["markdown"]
            del run_record["evidence_brief"]
            run_results.append(run_record)
            partial_payload = {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "partial": len(run_results) < (len(cases) * repetitions),
                "runner_path": str(Path(__file__).resolve()),
                "test_entrypoint": str(TEST_ENTRYPOINT),
                "fixture_path": str(fixture_path),
                "results_path": str(results_path),
                "runtime_dir": str(runtime_root),
                "config": config,
                "preflight": preflight,
                "cases": result_cases,
                "runs": run_results,
                "summary": summarize_results(result_cases, run_results),
            }
            results_path.parent.mkdir(parents=True, exist_ok=True)
            results_path.write_text(
                json.dumps(partial_payload, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            print(
                f"[replay] done {frozen_case['case_id']} run {repetition} "
                f"in {run_record['runtime_seconds']}s",
                flush=True,
            )

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "partial": False,
        "runner_path": str(Path(__file__).resolve()),
        "test_entrypoint": str(TEST_ENTRYPOINT),
        "fixture_path": str(fixture_path),
        "results_path": str(results_path),
        "runtime_dir": str(runtime_root),
        "config": config,
        "preflight": preflight,
        "cases": result_cases,
        "runs": run_results,
        "summary": summarize_results(result_cases, run_results),
    }
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture frozen evidence or run report-generation G-Eval replay."
    )
    parser.add_argument("--capture-evidence", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--fixture", type=Path, default=EVIDENCE_FIXTURE_PATH)
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument(
        "--metric-preset",
        choices=sorted(REPORT_GENERATION_METRIC_PRESETS),
        default="full",
        help="Budget preset: smoke=no judge, core=2 G-Eval dimensions, full=all dimensions.",
    )
    parser.add_argument(
        "--metric-dimensions",
        default=None,
        help="Optional comma-separated metric dimension override.",
    )
    parser.add_argument(
        "--deterministic-threshold",
        type=float,
        default=DEFAULT_DETERMINISTIC_THRESHOLD,
    )
    parser.add_argument(
        "--skip-judge-if-deterministic-fails",
        action="store_true",
        help="Do not call judge for outputs that fail deterministic prechecks.",
    )
    parser.add_argument(
        "--no-judge-cache",
        action="store_true",
        help="Disable judge-result cache.",
    )
    parser.add_argument("--judge-cache", type=Path, default=JUDGE_CACHE_PATH)
    parser.add_argument("--max-lines", type=int, default=DEFAULT_MAX_LINES)
    parser.add_argument("--case-limit", type=int, default=None)
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="Case id, tactic folder, or exact relative path to replay. Can be repeated.",
    )
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument(
        "--output-modes",
        default=None,
        help="Comma-separated output modes: summary,json,markdown",
    )
    args = parser.parse_args()

    if args.capture_evidence:
        payload = capture_frozen_evidence(
            output_path=args.fixture,
            max_lines=args.max_lines,
            case_limit=args.case_limit,
            resume=not args.no_resume,
        )
        print(
            json.dumps(
                {
                    "fixture_path": str(args.fixture),
                    "case_count": len(payload.get("cases", [])),
                    "capture_mode": payload.get("capture_mode"),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    if args.preflight:
        payload = preflight_replay_checks(args.fixture)
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        if not payload["ready"]:
            raise SystemExit(1)
        return

    output_modes = (
        tuple(item.strip() for item in args.output_modes.split(",") if item.strip())
        if args.output_modes
        else default_output_modes_for_preset(args.metric_preset)
    )
    metric_dimensions = (
        tuple(item.strip() for item in args.metric_dimensions.split(",") if item.strip())
        if args.metric_dimensions
        else None
    )
    payload = run_report_generation_geval_evaluation(
        fixture_path=args.fixture,
        repetitions=args.repetitions,
        threshold=args.threshold,
        output_modes=output_modes,
        case_limit=args.case_limit,
        case_selectors=tuple(args.case_id),
        metric_preset=args.metric_preset,
        metric_names=metric_dimensions,
        deterministic_threshold=args.deterministic_threshold,
        skip_judge_if_deterministic_fails=args.skip_judge_if_deterministic_fails,
        use_judge_cache=not args.no_judge_cache,
        judge_cache_path=args.judge_cache,
    )
    print(json.dumps(payload["summary"], indent=2, ensure_ascii=False))
    print(f"Results written to {payload['results_path']}")


if __name__ == "__main__":
    main()
