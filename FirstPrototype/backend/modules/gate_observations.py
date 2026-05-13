"""
Gate observation logging for calibrated fast-gate experiments.

This module is intentionally passive: it records current pipeline behavior without
changing which anomaly windows are routed to the investigation agent.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
import math
from pathlib import Path
from typing import Any


def append_gate_observations(
    output_path: str | Path,
    *,
    session_id: str,
    file_name: str,
    model_profile: str,
    initial_anomalies_df: Any,
    filtered_anomalies_df: Any,
    investigation_state: dict[str, Any],
    llm_provider: str | None = None,
    llm_model: str | None = None,
) -> int:
    """Append one JSONL observation per initial DeepLog anomaly window."""
    if initial_anomalies_df.empty:
        return 0

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    retained_window_ids = _window_id_set(filtered_anomalies_df)
    gate_policy = _first_non_empty(filtered_anomalies_df, "llm_gate_policy")
    gate_reason = _first_non_empty(filtered_anomalies_df, "llm_reason")
    gate_mode = _first_non_empty(filtered_anomalies_df, "llm_gate_mode")
    filtered_gate_rows = _records_by_window_id(filtered_anomalies_df)
    downstream_metrics = summarize_downstream_metrics(investigation_state)
    generated_at = datetime.now().isoformat()

    count = 0
    with open(path, "a", encoding="utf-8") as handle:
        for _, anomaly in initial_anomalies_df.iterrows():
            window_id = _safe_int(anomaly.get("window_id"))
            retained = window_id in retained_window_ids
            gate_row = filtered_gate_rows.get(window_id, {})
            record = {
                "schema_version": 1,
                "generated_at": generated_at,
                "session_id": session_id,
                "file_name": file_name,
                "model_profile": model_profile,
                "llm_provider": llm_provider,
                "llm_model": llm_model,
                "window_id": window_id,
                "start_idx": _safe_int(anomaly.get("start_idx")),
                "end_idx": _safe_int(anomaly.get("end_idx")),
                "anomaly_score": _safe_float(anomaly.get("anomaly_score")),
                "strict_is_anomaly": bool(anomaly.get("strict_is_anomaly", False)),
                "is_anomaly": bool(anomaly.get("is_anomaly", False)),
                "evaluation_status": str(anomaly.get("evaluation_status", "")),
                "unknown_ratio": _safe_float(anomaly.get("unknown_ratio")),
                "unknown_count": _safe_int(anomaly.get("unknown_count")),
                "actual_event": str(anomaly.get("actual_event", "")),
                "predicted_event": str(anomaly.get("predicted_event", "")),
                "expected_events": str(anomaly.get("expected_events", "")),
                "key_indicators": _json_safe(
                    anomaly.get("window_key_indicators") or {}
                ),
                "indicator_counts": _indicator_counts(
                    anomaly.get("window_key_indicators") or {}
                ),
                "current_llm_gate": {
                    "mode": gate_mode or "not_recorded",
                    "policy": gate_policy or "not_recorded",
                    "reason": gate_reason or "",
                    "priority": str(gate_row.get("llm_gate_priority") or "not_retained"),
                    "priority_rank": _safe_int(gate_row.get("llm_gate_priority_rank")),
                    "active": bool(gate_row.get("llm_gate_active", False)),
                    "confidence": _safe_float(gate_row.get("llm_gate_confidence")),
                    "requested_context": str(
                        gate_row.get("llm_gate_requested_context") or ""
                    ),
                    "prioritized_window_ids": _parse_window_id_json(
                        gate_row.get("llm_gate_prioritized_window_ids")
                    ),
                    "retained_for_investigation": retained,
                    "decision": "escalate_to_investigation"
                    if retained
                    else "drop_or_archive",
                },
                "investigation_result": downstream_metrics,
                "human_label": None,
            }
            handle.write(json.dumps(_json_safe(record), ensure_ascii=False) + "\n")
            count += 1

    return count


def summarize_downstream_metrics(
    investigation_state: dict[str, Any] | None,
) -> dict[str, Any]:
    """Summarize investigation output into gate-training utility signals."""
    state = investigation_state or {}
    anomalies = state.get("anomalies") or []
    iocs = state.get("iocs_extracted") or []
    tool_results = state.get("tool_results") or []
    timeline = state.get("attack_timeline") or []
    recommendations = state.get("recommendations") or []
    summary = str(state.get("investigation_summary") or "")

    malicious_hit_count = _count_unique_hits(tool_results, _is_malicious_result)
    suspicious_hit_count = _count_unique_hits(tool_results, _is_suspicious_result)

    return {
        "investigated_anomaly_count": len(anomalies),
        "ioc_count": len(iocs),
        "tool_result_count": len(tool_results),
        "malicious_hit_count": malicious_hit_count,
        "suspicious_hit_count": suspicious_hit_count,
        "timeline_event_count": len(timeline),
        "recommendation_count": len(recommendations),
        "summary_length": len(summary.strip()),
        "utility_label_hint": _utility_label_hint(
            iocs,
            malicious_hit_count,
            suspicious_hit_count,
            timeline,
            summary,
        ),
    }


def _utility_label_hint(
    iocs: list[Any],
    malicious_hit_count: int,
    suspicious_hit_count: int,
    timeline: list[Any],
    summary: str,
) -> str:
    if malicious_hit_count > 0 or suspicious_hit_count >= 2:
        return "high_value"
    if iocs or suspicious_hit_count == 1 or timeline:
        return "medium_value"
    if len(summary.strip()) >= 160:
        return "medium_value"
    return "low_value"


def _window_id_set(df: Any) -> set[int]:
    if df.empty or "window_id" not in df.columns:
        return set()
    return {_safe_int(value) for value in df["window_id"].tolist()}


def _first_non_empty(df: Any, column: str) -> str:
    if df.empty or column not in df.columns:
        return ""
    for value in df[column].tolist():
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _records_by_window_id(df: Any) -> dict[int, dict[str, Any]]:
    if df.empty or "window_id" not in df.columns:
        return {}

    records: dict[int, dict[str, Any]] = {}
    for _, row in df.iterrows():
        window_id = _safe_int(row.get("window_id"))
        if window_id:
            records[window_id] = row.to_dict()
    return records


def _parse_window_id_json(value: Any) -> list[int]:
    if isinstance(value, list):
        return [_safe_int(item) for item in value if _safe_int(item) > 0]
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [_safe_int(item) for item in parsed if _safe_int(item) > 0]


def _indicator_counts(indicators: Any) -> dict[str, int]:
    if not isinstance(indicators, dict):
        return {}
    counts: dict[str, int] = {}
    for key, value in indicators.items():
        if isinstance(value, list):
            counts[str(key)] = len([item for item in value if str(item).strip()])
        elif str(value).strip():
            counts[str(key)] = 1
        else:
            counts[str(key)] = 0
    return counts


def _count_unique_hits(tool_results: Iterable[Any], predicate) -> int:
    seen: set[str] = set()
    for result in tool_results:
        if not isinstance(result, dict) or not predicate(result):
            continue
        target = result.get("ioc") or result.get("ip") or result.get("url") or result.get("hash")
        key = str(target or id(result)).lower()
        seen.add(key)
    return len(seen)


def _is_malicious_result(result: dict[str, Any]) -> bool:
    classification = str(result.get("classification", "")).lower()
    if "malicious" in classification:
        return True
    if bool(result.get("malicious")):
        return True
    return bool(result.get("malware_family"))


def _is_suspicious_result(result: dict[str, Any]) -> bool:
    classification = str(result.get("classification", "")).lower()
    if "suspicious" in classification:
        return True
    return bool(result.get("suspicious"))


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if value is None:
        return None
    item_method = getattr(value, "item", None)
    if callable(item_method):
        try:
            return item_method()
        except (TypeError, ValueError):
            return str(value)
    if isinstance(value, float) and math.isnan(value):
        return None
    return value
