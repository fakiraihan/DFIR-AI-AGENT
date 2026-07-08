"""Parsed-log export artifacts for Kanban and Elasticsearch workflows."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import pandas as pd


EXPORT_DIR_NAME = "exports"
DEFAULT_ELASTIC_INDEX = "firstprototype-parsed-logs"


def build_export_artifacts(
    *,
    session_id: str,
    file_name: str,
    output_session_dir: Path,
    parsed_df: pd.DataFrame,
    results_df: pd.DataFrame,
    anomalies_df: pd.DataFrame,
    selected_profile: dict[str, Any],
) -> dict[str, Any]:
    """Write parsed-log export files and return manifest metadata."""
    export_dir = (Path(output_session_dir) / EXPORT_DIR_NAME).resolve()
    export_dir.mkdir(parents=True, exist_ok=True)

    records = _build_export_records(
        session_id=session_id,
        file_name=file_name,
        parsed_df=parsed_df,
        results_df=results_df,
        anomalies_df=anomalies_df,
        selected_profile=selected_profile,
    )
    generation_time = datetime.now(timezone.utc).isoformat()

    jsonl_path = export_dir / "parsed_logs.jsonl"
    ndjson_path = export_dir / "elastic_bulk.ndjson"
    csv_path = export_dir / "parsed_logs.csv"
    manifest_path = export_dir / "export_manifest.json"

    _write_jsonl(records, jsonl_path)
    _write_elastic_bulk_ndjson(records, ndjson_path)
    _write_csv(records, csv_path)

    anomaly_windows = _count_true_rows(results_df, "is_anomaly")
    retained_windows = _retained_window_ids(anomalies_df)

    manifest = {
        "session_id": session_id,
        "file_name": file_name,
        "generated_at": generation_time,
        "model_profile": selected_profile.get("name"),
        "parser_template_strategy": selected_profile.get("template_strategy"),
        "window_size": selected_profile.get("window_size"),
        "topk": selected_profile.get("topk"),
        "summary": {
            "parsed_lines": len(parsed_df),
            "window_count": len(results_df),
            "anomaly_window_count": anomaly_windows,
            "retained_anomaly_window_count": len(retained_windows),
        },
        "formats": {
            "jsonl": str(jsonl_path),
            "ndjson": str(ndjson_path),
            "csv": str(csv_path),
        },
    }

    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        "manifest": manifest,
        "manifest_path": str(manifest_path),
        "jsonl_path": str(jsonl_path),
        "ndjson_path": str(ndjson_path),
        "csv_path": str(csv_path),
    }


def _build_export_records(
    *,
    session_id: str,
    file_name: str,
    parsed_df: pd.DataFrame,
    results_df: pd.DataFrame,
    anomalies_df: pd.DataFrame,
    selected_profile: dict[str, Any],
) -> list[dict[str, Any]]:
    line_window_map = _line_window_map(results_df)
    retained_window_ids = _retained_window_ids(anomalies_df)
    flagged_window_ids = _window_ids_with_anomaly(results_df)

    records: list[dict[str, Any]] = []
    for row in parsed_df.to_dict("records"):
        line_number = _to_int(row.get("line_number"))
        windows = line_window_map.get(line_number, [])

        max_score = max((window["anomaly_score"] for window in windows), default=0.0)
        window_ids = [window["window_id"] for window in windows]
        flagged_for_anomaly = any(window["is_window_anomaly"] for window in windows)
        retained_for_investigation = bool(
            retained_window_ids and any(window_id in retained_window_ids for window_id in window_ids)
        )

        lane = "normal"
        if flagged_for_anomaly and retained_for_investigation:
            lane = "investigated"
        elif flagged_for_anomaly:
            lane = "triage"

        priority = "low"
        if max_score >= 0.9:
            priority = "critical"
        elif max_score >= 0.75:
            priority = "high"
        elif max_score >= 0.5:
            priority = "medium"

        event_timestamp = _to_text(row.get("timestamp")) or datetime.now(timezone.utc).isoformat()
        document_id = f"{session_id}-{line_number}"
        raw_line = _to_text(row.get("raw_line"))

        record = {
            "@timestamp": event_timestamp,
            "session_id": session_id,
            "file_name": file_name,
            "line_number": line_number,
            "event_id": _to_int(row.get("event_id")),
            "raw_line": raw_line,
            "message": raw_line,
            "event_template": _to_text(row.get("event_template")),
            "cluster_id": _to_text(row.get("cluster_id")),
            "parameter_array": _to_list(row.get("parameter_array")),
            "parameter_map": _to_dict(row.get("parameter_map")),
            "parser_profile": selected_profile.get("name", "general"),
            "deeplog": {
                "is_anomalous_line": any(window["is_anomalous_line"] for window in windows),
                "window_ids": window_ids,
                "max_anomaly_score": round(float(max_score), 6),
                "candidate_tiers": _unique_preserve_order(
                    [window["candidate_tier"] for window in windows if window["candidate_tier"]]
                ),
                "evaluation_statuses": _unique_preserve_order(
                    [window["evaluation_status"] for window in windows if window["evaluation_status"]]
                ),
                "flagged_window_count": sum(1 for window in windows if window["is_window_anomaly"]),
                "flagged_by_deeplog": flagged_for_anomaly,
                "retained_for_investigation": retained_for_investigation,
            },
            "kanban": {
                "lane": lane,
                "priority": priority,
            },
            "elastic": {
                "index": DEFAULT_ELASTIC_INDEX,
                "document_id": document_id,
            },
            "source": {
                "parser_template_strategy": selected_profile.get("template_strategy"),
                "window_size": selected_profile.get("window_size"),
                "topk": selected_profile.get("topk"),
                "line_in_flagged_window": any(window_id in flagged_window_ids for window_id in window_ids),
            },
        }
        records.append(record)

    return records


def _line_window_map(results_df: pd.DataFrame) -> dict[int, list[dict[str, Any]]]:
    mapping: dict[int, list[dict[str, Any]]] = {}
    if results_df.empty:
        return mapping

    for row in results_df.to_dict("records"):
        window_id = _to_int(row.get("window_id"))
        is_window_anomaly = bool(row.get("is_anomaly", False))
        candidate_tier = _to_text(row.get("candidate_tier"))
        evaluation_status = _to_text(row.get("evaluation_status"))
        anomaly_score = _to_float(row.get("anomaly_score"))
        line_items = row.get("lines") if isinstance(row.get("lines"), list) else []

        for item in line_items:
            if not isinstance(item, dict):
                continue
            line_number = _to_int(item.get("line_number"))
            entry = {
                "window_id": window_id,
                "is_window_anomaly": is_window_anomaly,
                "is_anomalous_line": bool(item.get("is_anomalous_line", False)),
                "candidate_tier": candidate_tier,
                "evaluation_status": evaluation_status,
                "anomaly_score": anomaly_score,
            }
            mapping.setdefault(line_number, []).append(entry)

    return mapping


def _retained_window_ids(anomalies_df: pd.DataFrame) -> set[int]:
    if anomalies_df.empty or "window_id" not in anomalies_df.columns:
        return set()
    return {int(value) for value in anomalies_df["window_id"].tolist()}


def _window_ids_with_anomaly(results_df: pd.DataFrame) -> set[int]:
    if results_df.empty or "window_id" not in results_df.columns:
        return set()
    if "is_anomaly" not in results_df.columns:
        return {int(value) for value in results_df["window_id"].tolist()}
    flagged = results_df[results_df["is_anomaly"] == True]  # noqa: E712
    return {int(value) for value in flagged["window_id"].tolist()}


def _count_true_rows(df: pd.DataFrame, column: str) -> int:
    if df.empty or column not in df.columns:
        return 0
    return int((df[column] == True).sum())  # noqa: E712


def _write_jsonl(records: list[dict[str, Any]], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8", newline="\n") as file_obj:
        for record in records:
            file_obj.write(json.dumps(record, ensure_ascii=False) + "\n")


def _write_elastic_bulk_ndjson(records: list[dict[str, Any]], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8", newline="\n") as file_obj:
        for record in records:
            elastic_meta = {
                "index": {
                    "_index": record["elastic"]["index"],
                    "_id": record["elastic"]["document_id"],
                }
            }
            document = dict(record)
            document.pop("elastic", None)
            file_obj.write(json.dumps(elastic_meta, ensure_ascii=False) + "\n")
            file_obj.write(json.dumps(document, ensure_ascii=False) + "\n")


def _write_csv(records: list[dict[str, Any]], output_path: Path) -> None:
    dataframe = pd.DataFrame(
        [
            {
                "timestamp": record.get("@timestamp"),
                "session_id": record.get("session_id"),
                "file_name": record.get("file_name"),
                "line_number": record.get("line_number"),
                "event_id": record.get("event_id"),
                "event_template": record.get("event_template"),
                "raw_line": record.get("raw_line"),
                "kanban_lane": _to_text(record.get("kanban", {}).get("lane")),
                "kanban_priority": _to_text(record.get("kanban", {}).get("priority")),
                "max_anomaly_score": _to_float(record.get("deeplog", {}).get("max_anomaly_score")),
                "is_anomalous_line": bool(record.get("deeplog", {}).get("is_anomalous_line")),
                "flagged_by_deeplog": bool(record.get("deeplog", {}).get("flagged_by_deeplog")),
                "retained_for_investigation": bool(
                    record.get("deeplog", {}).get("retained_for_investigation")
                ),
                "window_ids": "|".join(str(value) for value in _to_list(record.get("deeplog", {}).get("window_ids"))),
            }
            for record in records
        ]
    )
    dataframe.to_csv(output_path, index=False)


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _to_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _to_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
