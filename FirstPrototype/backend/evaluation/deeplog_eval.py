"""Formal DeepLog evaluation CLI for labelled datasets.

The evaluator intentionally measures raw DeepLogDetector output, before any
LLM anomaly filtering or downstream DFIR agent reasoning.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd
import torch


BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from config import settings  # noqa: E402
from evaluation.calibration import calibrate_score_threshold  # noqa: E402
from evaluation.cached_records import (  # noqa: E402
    DEFAULT_CACHED_CONFIG,
    DEFAULT_CACHED_TOPK_VALUES,
    CachedSession,
    build_cached_windows,
    compose_cached_run_dir,
    deduplicate_cached_sessions,
    expand_cached_predictions,
    load_cached_records,
    load_yaml_config,
)
from evaluation.promotion_gate import evaluate_promotion_gate  # noqa: E402
from modules.anomaly import DeepLogDetector  # noqa: E402
from services.parsing_service import (  # noqa: E402
    apply_template_enrichment,
    build_model_profile,
    parse_with_profile,
)


try:  # pragma: no cover - fallback is only for incomplete local environments.
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        balanced_accuracy_score,
        classification_report,
        confusion_matrix,
        f1_score,
        precision_recall_curve,
        precision_score,
        recall_score,
        roc_auc_score,
        roc_curve,
    )
except Exception:  # pragma: no cover
    accuracy_score = None
    average_precision_score = None
    balanced_accuracy_score = None
    classification_report = None
    confusion_matrix = None
    f1_score = None
    precision_recall_curve = None
    precision_score = None
    recall_score = None
    roc_auc_score = None
    roc_curve = None


LOGGER = logging.getLogger("deeplog_eval")

DEFAULT_LMD_INPUT = Path(
    r"D:\FAKI\NEWMLMODL\dataset\lmd2023_2_3m\lmd2023.log_structured.csv"
)
DEFAULT_OUTPUT_BASE = REPO_ROOT / "output" / "evaluation" / "deeplog"
DEFAULT_BASELINE_TOPK_VALUES = (3, 5, 9)

LABEL_CANDIDATES = (
    "Label",
    "label",
    "ground_truth",
    "y_true",
    "is_anomaly",
    "anomaly",
    "attack",
    "class",
    "target",
)
LINE_ID_CANDIDATES = (
    "line_number",
    "LineId",
    "line_id",
    "index",
    "row_id",
    "EventRecordID",
    "event_record_id",
)
TEMPLATE_COLUMNS = ("event_template", "EventTemplate")
RAW_COLUMNS = (
    "raw_line",
    "Content",
    "Message",
    "message",
    "_source.full_log",
    "_source.data.win.system.message",
)
TIMESTAMP_COLUMNS = (
    "timestamp",
    "Timestamp",
    "SystemTime",
    "UtcTime",
    "TimeGenerated",
    "_source.@timestamp",
)
EVENT_ID_COLUMNS = ("event_id", "EventID", "EventId", "_source.data.win.system.eventID")
SKIPPED_STATUSES = {
    "skipped_unknown_template",
    "unknown_template",
    "unknown_template_ratio_exceeded",
}

DEFAULT_POSITIVE_LABELS = {
    "1",
    "true",
    "yes",
    "anomaly",
    "anomalous",
    "attack",
    "malicious",
    "suspicious",
    "defaced",
    "abnormal",
    "eors",
    "eoht",
}
DEFAULT_NORMAL_LABELS = {
    "0",
    "false",
    "no",
    "normal",
    "benign",
    "clean",
    "not_anomaly",
    "not anomaly",
    "-",
}


@dataclass(frozen=True)
class DetectorRunConfig:
    eval_mode: str
    model_path: Path
    vocab_path: Path
    window_size: int
    step_size: int
    topk: int
    profile_name: str
    template_strategy: str
    template_enrichment: str = "none"
    use_bos_context: bool = False
    bos_token: str = "<BOS>"
    bos_count: int | None = None
    decision_policy: str = "topk"
    score_threshold: float | None = None
    medium_score_threshold: float = 0.70
    recall_floor: float = 0.80


@dataclass
class EvaluationResult:
    mode_name: str
    output_dir: Path
    report_path: Path
    metrics_by_mode: dict[str, dict[str, Any]]
    parsed_lines: int
    evaluated_windows: int
    skipped_windows: int
    warnings: list[str]


class GroundTruthMissingError(ValueError):
    """Raised when no usable ground-truth labels are available."""


def _json_default(value: Any) -> Any:
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        if not math.isfinite(float(value)):
            return None
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return str(value)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=_json_default),
        encoding="utf-8",
    )


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (np.bool_,)):
        return bool(value)
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "anomaly", "anomalous"}


def _clean_label_text(value: Any) -> str:
    return str(value).strip().lower()


def normalize_label(value: Any, positive_values: Iterable[str] | None = None) -> int:
    """Normalize common binary anomaly labels to 0/1.

    LMD-2023 defaults are built in: "-" is normal, while EoRS/EoHT are anomaly.
    """

    if value is None or (isinstance(value, float) and math.isnan(value)):
        raise ValueError("Label value is empty")
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, np.integer)) and int(value) in {0, 1}:
        return int(value)
    if isinstance(value, (float, np.floating)) and float(value) in {0.0, 1.0}:
        return int(value)

    text = _clean_label_text(value)
    positives = (
        {_clean_label_text(item) for item in positive_values}
        if positive_values
        else DEFAULT_POSITIVE_LABELS
    )
    if text in positives:
        return 1
    if text in DEFAULT_NORMAL_LABELS:
        return 0
    if not positive_values and text not in DEFAULT_POSITIVE_LABELS:
        raise ValueError(f"Unknown label value: {value!r}")
    return 0


def auto_detect_label_column(df: pd.DataFrame, label_column: str | None = None) -> str:
    if label_column:
        if label_column not in df.columns:
            raise ValueError(f"Label column not found: {label_column}")
        return label_column
    for candidate in LABEL_CANDIDATES:
        if candidate in df.columns:
            return candidate
    raise GroundTruthMissingError(
        "Ground truth label tidak ditemukan. Sediakan --label-file atau gunakan "
        "input CSV dengan kolom Label/label/ground_truth."
    )


def auto_detect_line_id_column(
    df: pd.DataFrame,
    line_id_column: str | None = None,
) -> str | None:
    if line_id_column:
        if line_id_column not in df.columns:
            raise ValueError(f"Line id column not found: {line_id_column}")
        return line_id_column
    for candidate in LINE_ID_CANDIDATES:
        if candidate in df.columns:
            return candidate
    return None


def validate_labels(y_true: Sequence[int]) -> None:
    if len(y_true) == 0:
        raise ValueError("Ground truth label kosong; metrik formal tidak dapat dihitung.")
    invalid_values = sorted({int(value) for value in y_true if int(value) not in {0, 1}})
    if invalid_values:
        raise ValueError(f"Ground truth label harus biner 0/1, ditemukan: {invalid_values}")


def _read_table(path: Path, max_rows: int | None = None) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path, nrows=max_rows, low_memory=False)
    if suffix == ".jsonl":
        return pd.read_json(path, lines=True, nrows=max_rows)
    if suffix == ".json":
        df = pd.read_json(path)
        return df.head(max_rows) if max_rows else df
    raise ValueError(f"Unsupported label/input table format: {path}")


def _parse_positive_values(raw_value: str | None) -> set[str] | None:
    if raw_value in (None, "", "auto"):
        return None
    return {_clean_label_text(part) for part in raw_value.split(",") if part.strip()}


def _coerce_line_id(value: Any, fallback: int) -> Any:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        text = str(value).strip()
        return text if text else fallback


def _normalize_labels_dataframe(
    source_df: pd.DataFrame,
    label_column: str | None,
    line_id_column: str | None,
    positive_values: set[str] | None,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    detected_label_column = auto_detect_label_column(source_df, label_column)
    detected_line_id_column = auto_detect_line_id_column(source_df, line_id_column)

    rows: list[dict[str, Any]] = []
    for idx, row in source_df.reset_index(drop=True).iterrows():
        line_id = (
            _coerce_line_id(row.get(detected_line_id_column), idx + 1)
            if detected_line_id_column
            else idx + 1
        )
        raw_label = row.get(detected_label_column)
        try:
            y_true = normalize_label(raw_label, positive_values)
        except ValueError as exc:
            raise ValueError(
                f"Cannot normalize label at row {idx + 1} "
                f"({detected_label_column}={raw_label!r}): {exc}"
            ) from exc
        rows.append(
            {
                "line_number": line_id,
                "line_id": line_id,
                "raw_label": raw_label,
                "y_true": y_true,
            }
        )

    labels_df = pd.DataFrame(rows)
    validate_labels(labels_df["y_true"].astype(int).tolist())
    metadata = {
        "label_column": detected_label_column,
        "line_id_column": detected_line_id_column or "(row_index)",
        "label_counts": {
            str(key): int(value)
            for key, value in labels_df["y_true"].value_counts().sort_index().to_dict().items()
        },
    }
    return labels_df, metadata


def load_ground_truth_labels(
    input_log: Path,
    label_file: Path | None = None,
    label_column: str | None = None,
    line_id_column: str | None = None,
    positive_label: str | None = None,
    max_lines: int | None = None,
    source_df: pd.DataFrame | None = None,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    positive_values = _parse_positive_values(positive_label)
    if label_file:
        labels_source = _read_table(label_file, max_rows=max_lines)
    elif source_df is not None:
        labels_source = source_df
    elif input_log.suffix.lower() == ".csv":
        labels_source = _read_table(input_log, max_rows=max_lines)
    else:
        raise GroundTruthMissingError(
            "Ground truth label tidak ditemukan. Sediakan --label-file atau gunakan "
            "input CSV dengan kolom Label/label/ground_truth."
        )
    return _normalize_labels_dataframe(
        labels_source,
        label_column=label_column,
        line_id_column=line_id_column,
        positive_values=positive_values,
    )


def write_label_template(output_dir: Path, rows: int = 20) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    template_path = output_dir / "labels_template.csv"
    template_rows = [{"line_number": idx, "label": ""} for idx in range(1, rows + 1)]
    pd.DataFrame(template_rows).to_csv(template_path, index=False)
    return template_path


def _first_existing_column(df: pd.DataFrame, candidates: Sequence[str]) -> str | None:
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    return None


def is_structured_input_dataframe(df: pd.DataFrame) -> bool:
    return _first_existing_column(df, TEMPLATE_COLUMNS) is not None


def build_parsed_df_from_structured_csv(source_df: pd.DataFrame) -> pd.DataFrame:
    template_column = _first_existing_column(source_df, TEMPLATE_COLUMNS)
    if template_column is None:
        raise ValueError("Structured input requires EventTemplate or event_template column")

    line_id_column = auto_detect_line_id_column(source_df)
    raw_column = _first_existing_column(source_df, RAW_COLUMNS)
    timestamp_column = _first_existing_column(source_df, TIMESTAMP_COLUMNS)
    event_id_column = _first_existing_column(source_df, EVENT_ID_COLUMNS)

    rows: list[dict[str, Any]] = []
    for idx, row in source_df.reset_index(drop=True).iterrows():
        line_number = (
            _coerce_line_id(row.get(line_id_column), idx + 1) if line_id_column else idx + 1
        )
        event_template = str(row.get(template_column, ""))
        raw_line = str(row.get(raw_column, event_template)) if raw_column else event_template
        timestamp = str(row.get(timestamp_column, "")) if timestamp_column else ""
        event_id = row.get(event_id_column, line_number) if event_id_column else line_number
        try:
            cluster_id = str(row.get("EventId", row.get("event_id", event_template)))
        except Exception:
            cluster_id = event_template

        output_row = {
            "line_number": line_number,
            "event_id": event_id,
            "timestamp": timestamp,
            "event_template": event_template,
            "EventTemplate": event_template,
            "parameter_array": [],
            "parameter_map": {},
            "parameters": "[]",
            "raw_line": raw_line,
            "cluster_id": cluster_id,
        }
        for passthrough in (
            "LineId",
            "EventRecordID",
            "event_record_id",
            "AgentName",
            "Computer",
            "SystemTime",
            "EventID",
            "EventId",
        ):
            if passthrough in source_df.columns:
                output_row[passthrough] = row.get(passthrough)
        rows.append(output_row)

    return pd.DataFrame(rows)


def _templates_from_parsed(parsed_df: pd.DataFrame) -> list[dict[str, Any]]:
    if parsed_df.empty or "event_template" not in parsed_df.columns:
        return []
    grouped = (
        parsed_df.groupby("event_template", dropna=False)
        .size()
        .reset_index(name="size")
        .sort_values("size", ascending=False)
    )
    return [
        {"cluster_id": str(row["event_template"]), "template": str(row["event_template"]), "size": int(row["size"])}
        for _, row in grouped.iterrows()
    ]


def _profile_from_name(profile_name: str) -> dict[str, Any]:
    if profile_name == "auto":
        return build_model_profile("general", settings)
    return build_model_profile(profile_name, settings)


def run_parser(
    input_log: Path,
    profile: str,
    max_lines: int | None,
    structured_input: bool,
    source_df: pd.DataFrame | None = None,
) -> tuple[pd.DataFrame, list[dict[str, Any]], dict[str, Any], pd.DataFrame | None]:
    if source_df is None and input_log.suffix.lower() == ".csv":
        header_df = pd.read_csv(input_log, nrows=0)
        auto_structured = is_structured_input_dataframe(header_df)
        if structured_input or auto_structured:
            source_df = _read_table(input_log, max_rows=max_lines)

    if source_df is not None and (structured_input or is_structured_input_dataframe(source_df)):
        parsed_df = build_parsed_df_from_structured_csv(source_df)
        selected_profile = _profile_from_name(profile)
        templates = _templates_from_parsed(parsed_df)
        parsed_df, templates = apply_template_enrichment(
            parsed_df,
            templates,
            selected_profile.get("template_enrichment", "none"),
        )
        return parsed_df, templates, selected_profile, source_df

    if profile == "auto":
        parsed_df, templates, selected_profile = parse_with_profile(
            str(input_log),
            settings,
            max_lines=max_lines,
        )
        return parsed_df, templates, selected_profile, None

    from modules.parsing import parse_log_file

    selected_profile = build_model_profile(profile, settings)
    parsed_df, templates = parse_log_file(
        str(input_log),
        depth=settings.drain_depth,
        sim_threshold=settings.drain_sim_threshold,
        max_children=settings.drain_max_children,
        template_strategy=selected_profile["template_strategy"],
        max_lines=max_lines,
    )
    parsed_df, templates = apply_template_enrichment(
        parsed_df,
        templates,
        selected_profile.get("template_enrichment", "none"),
    )
    return parsed_df, templates, selected_profile, None


def _resolve_path(value: Any) -> Path:
    path = Path(str(value))
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def build_detector_run_config(
    *,
    eval_mode: str,
    selected_profile: dict[str, Any],
    model_path: Path | None,
    vocab_path: Path | None,
    window_size: int | None,
    step_size: int | None,
    topk: int | None,
    decision_policy: str | None = None,
    score_threshold: float | None = None,
    medium_score_threshold: float | None = None,
    recall_floor: float | None = None,
) -> DetectorRunConfig:
    if eval_mode == "training_baseline":
        default_window_size = 20
        default_step_size = 20
        default_topk = 3
    else:
        default_window_size = int(selected_profile.get("window_size", settings.deeplog_window_size))
        default_step_size = int(settings.deeplog_step_size)
        default_topk = int(selected_profile.get("topk", settings.deeplog_topk))

    return DetectorRunConfig(
        eval_mode=eval_mode,
        model_path=_resolve_path(model_path or selected_profile["model_path"]),
        vocab_path=_resolve_path(vocab_path or selected_profile["vocab_path"]),
        window_size=int(window_size or default_window_size),
        step_size=int(step_size or default_step_size),
        topk=int(topk or default_topk),
        profile_name=str(selected_profile.get("name", "general")),
        template_strategy=str(selected_profile.get("template_strategy", "")),
        template_enrichment=str(selected_profile.get("template_enrichment", "none")),
        use_bos_context=bool(selected_profile.get("use_bos_context", False))
        if eval_mode != "training_baseline"
        else False,
        bos_token=str(selected_profile.get("bos_token", "<BOS>")),
        bos_count=selected_profile.get("bos_count"),
        decision_policy=str(decision_policy or settings.deeplog_decision_policy),
        score_threshold=(
            float(score_threshold)
            if score_threshold is not None
            else float(settings.deeplog_score_threshold)
        ),
        medium_score_threshold=float(
            medium_score_threshold
            if medium_score_threshold is not None
            else settings.deeplog_medium_score_threshold
        ),
        recall_floor=float(recall_floor if recall_floor is not None else settings.deeplog_target_recall),
    )


def run_deeplog(parsed_df: pd.DataFrame, config: DetectorRunConfig) -> pd.DataFrame:
    if not config.model_path.exists() or not config.vocab_path.exists():
        raise FileNotFoundError(
            f"DeepLog artifacts not found. model={config.model_path} vocab={config.vocab_path}"
        )
    detector = DeepLogDetector(
        str(config.model_path),
        str(config.vocab_path),
        window_size=config.window_size,
        step_size=config.step_size,
        topk=config.topk,
        skip_unknown_windows=settings.deeplog_skip_unknown_windows,
        max_unknown_ratio=settings.deeplog_max_unknown_ratio,
        unknown_template_mode=settings.deeplog_unknown_template_mode,
        evtx_sparse_fallback_enabled=settings.deeplog_evtx_sparse_fallback_enabled,
        evtx_sparse_fallback_threshold=settings.deeplog_evtx_sparse_fallback_threshold,
        template_similarity_enabled=settings.deeplog_template_similarity_enabled,
        template_similarity_threshold=settings.deeplog_template_similarity_threshold,
        use_bos_context=config.use_bos_context,
        bos_token=config.bos_token,
        bos_count=config.bos_count,
        decision_policy=config.decision_policy,
        score_threshold=config.score_threshold,
        medium_score_threshold=config.medium_score_threshold,
        recall_floor=config.recall_floor,
    )
    return detector.detect_anomalies(parsed_df)


def normalize_deeplog_results(results_df: pd.DataFrame) -> pd.DataFrame:
    output = results_df.copy()
    for column in ("is_anomaly", "strict_is_anomaly"):
        if column in output.columns:
            output[column] = output[column].map(_as_bool)
    for column in ("anomaly_score", "unknown_ratio"):
        if column in output.columns:
            output[column] = pd.to_numeric(output[column], errors="coerce")
    return output


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_json_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _safe_json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return []


def _lookup_label(label_map: dict[Any, int], line_number: Any) -> int | None:
    if line_number in label_map:
        return int(label_map[line_number])
    try:
        numeric = int(line_number)
        if numeric in label_map:
            return int(label_map[numeric])
    except (TypeError, ValueError):
        pass
    text = str(line_number)
    if text in label_map:
        return int(label_map[text])
    return None


def _target_line_from_payload(row: pd.Series) -> Any | None:
    anomalous_line = _safe_json_dict(row.get("anomalous_line"))
    if anomalous_line.get("line_number") not in (None, ""):
        return anomalous_line.get("line_number")
    lines = row.get("lines")
    if isinstance(lines, list) and lines:
        last_line = lines[-1]
        if isinstance(last_line, dict):
            return last_line.get("line_number")
    return None


def _parsed_row_at(parsed_df: pd.DataFrame, idx: int) -> pd.Series | None:
    if 0 <= idx < len(parsed_df):
        return parsed_df.iloc[idx]
    return None


def _line_numbers_for_window(row: pd.Series, parsed_df: pd.DataFrame) -> list[Any]:
    lines = row.get("lines")
    if isinstance(lines, list) and lines:
        output = []
        for item in lines:
            if isinstance(item, dict) and item.get("line_number") not in (None, ""):
                output.append(item.get("line_number"))
        if output:
            return output

    start_idx = max(0, _safe_int(row.get("start_idx"), 0))
    end_idx = min(len(parsed_df) - 1, _safe_int(row.get("end_idx"), start_idx))
    if end_idx < start_idx:
        start_idx, end_idx = end_idx, start_idx
    if parsed_df.empty:
        return []
    return parsed_df.iloc[start_idx : end_idx + 1]["line_number"].tolist()


def _label_for_window(
    row: pd.Series,
    parsed_df: pd.DataFrame,
    label_map: dict[Any, int],
    policy: str,
    threshold: float,
) -> tuple[int | None, str]:
    line_numbers = _line_numbers_for_window(row, parsed_df)
    labels = [
        label
        for label in (_lookup_label(label_map, line_number) for line_number in line_numbers)
        if label is not None
    ]
    if not labels:
        return None, policy

    if policy == "majority":
        return int(float(np.mean(labels)) >= 0.5), "majority"
    if policy == "ratio_threshold":
        return int(float(np.mean(labels)) >= threshold), "ratio_threshold"
    return int(any(labels)), "any_in_window"


def build_window_ground_truth(
    results_df: pd.DataFrame,
    parsed_df: pd.DataFrame,
    labels_df: pd.DataFrame,
    policy: str = "target_event",
    window_label_threshold: float = 0.1,
) -> pd.DataFrame:
    label_map = {
        row["line_number"]: int(row["y_true"])
        for _, row in labels_df[["line_number", "y_true"]].iterrows()
    }
    warnings: list[str] = []
    output_rows: list[dict[str, Any]] = []

    for _, row in results_df.iterrows():
        end_idx = _safe_int(row.get("end_idx"), -1)
        target_line_number = _target_line_from_payload(row)
        target_parsed_row = None
        if target_line_number is None:
            target_parsed_row = _parsed_row_at(parsed_df, end_idx)
            if target_parsed_row is not None:
                target_line_number = target_parsed_row.get("line_number")

        y_true = None
        label_policy_used = policy
        if policy == "target_event" and target_line_number is not None:
            y_true = _lookup_label(label_map, target_line_number)

        if y_true is None:
            y_true, label_policy_used = _label_for_window(
                row,
                parsed_df,
                label_map,
                "any_in_window" if policy == "target_event" else policy,
                window_label_threshold,
            )
            if policy == "target_event":
                warnings.append(
                    f"Fallback any_in_window for window_id={row.get('window_id')} "
                    f"because target label was not found."
                )

        if target_parsed_row is None and target_line_number is not None:
            matching = parsed_df[parsed_df["line_number"].astype(str) == str(target_line_number)]
            if not matching.empty:
                target_parsed_row = matching.iloc[0]
        if target_parsed_row is None:
            target_parsed_row = _parsed_row_at(parsed_df, end_idx)

        event_template = (
            str(target_parsed_row.get("event_template", ""))
            if target_parsed_row is not None
            else str(row.get("actual_event", ""))
        )
        raw_line = (
            str(target_parsed_row.get("raw_line", ""))
            if target_parsed_row is not None
            else ""
        )
        parameters = (
            target_parsed_row.get("parameters", "")
            if target_parsed_row is not None
            else ""
        )

        output_rows.append(
            {
                "window_id": row.get("window_id"),
                "start_idx": row.get("start_idx"),
                "end_idx": row.get("end_idx"),
                "target_line_number": target_line_number,
                "y_true": y_true,
                "y_pred_is_anomaly": _as_bool(row.get("is_anomaly", False)),
                "y_pred_strict_is_anomaly": _as_bool(row.get("strict_is_anomaly", False))
                if "strict_is_anomaly" in results_df.columns
                else None,
                "anomaly_score": row.get("anomaly_score"),
                "unknown_ratio": row.get("unknown_ratio"),
                "evaluation_status": row.get("evaluation_status"),
                "predicted_event": row.get("predicted_event"),
                "actual_event": row.get("actual_event"),
                "predicted_events": row.get("predicted_events"),
                "topk_probabilities": row.get("topk_probabilities"),
                "label_policy_used": label_policy_used,
                "event_template": event_template,
                "raw_line": raw_line,
                "parameters": parameters,
            }
        )

    output_df = pd.DataFrame(output_rows)
    if not output_df.empty:
        output_df = output_df[output_df["y_true"].notna()].copy()
        output_df["y_true"] = output_df["y_true"].astype(int)
    output_df.attrs["warnings"] = warnings
    return output_df


def _manual_confusion(y_true: np.ndarray, y_pred: np.ndarray) -> tuple[int, int, int, int]:
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    return tn, fp, fn, tp


def _safe_rate(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def compute_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int | bool],
    y_score: Sequence[float] | None = None,
    mode_name: str = "is_anomaly",
) -> dict[str, Any]:
    y_true_arr = np.asarray(y_true, dtype=int)
    y_pred_arr = np.asarray([int(_as_bool(value)) for value in y_pred], dtype=int)
    validate_labels(y_true_arr.tolist())

    if confusion_matrix is not None:
        matrix = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1])
        tn, fp, fn, tp = (int(matrix[0, 0]), int(matrix[0, 1]), int(matrix[1, 0]), int(matrix[1, 1]))
    else:  # pragma: no cover
        tn, fp, fn, tp = _manual_confusion(y_true_arr, y_pred_arr)

    if accuracy_score is not None:
        accuracy = float(accuracy_score(y_true_arr, y_pred_arr))
        precision = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
        recall = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
        f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))
        balanced_accuracy = float(balanced_accuracy_score(y_true_arr, y_pred_arr))
    else:  # pragma: no cover
        accuracy = _safe_rate(tp + tn, tp + tn + fp + fn)
        precision = _safe_rate(tp, tp + fp)
        recall = _safe_rate(tp, tp + fn)
        f1 = _safe_rate(2 * precision * recall, precision + recall)
        balanced_accuracy = (_safe_rate(tp, tp + fn) + _safe_rate(tn, tn + fp)) / 2

    if classification_report is not None:
        report = classification_report(
            y_true_arr,
            y_pred_arr,
            labels=[0, 1],
            target_names=["normal", "anomaly"],
            zero_division=0,
            output_dict=True,
        )
    else:  # pragma: no cover
        report = {}

    score_values = None
    roc_auc: float | str = "N/A"
    roc_auc_reason = "anomaly_score tidak tersedia"
    average_precision: float | str = "N/A"
    average_precision_reason = "anomaly_score tidak tersedia"
    if y_score is not None:
        score_values = pd.to_numeric(pd.Series(list(y_score)), errors="coerce")
        valid_mask = score_values.notna()
        if valid_mask.any():
            y_score_arr = score_values[valid_mask].astype(float).to_numpy()
            y_true_for_score = y_true_arr[valid_mask.to_numpy()]
            if len(set(y_true_for_score.tolist())) == 2:
                if roc_auc_score is not None:
                    roc_auc = float(roc_auc_score(y_true_for_score, y_score_arr))
                    roc_auc_reason = ""
                if average_precision_score is not None:
                    average_precision = float(
                        average_precision_score(y_true_for_score, y_score_arr)
                    )
                    average_precision_reason = ""
            else:
                roc_auc_reason = "ROC-AUC N/A karena y_true hanya memiliki satu kelas"
                average_precision_reason = "PR-AUC N/A karena y_true hanya memiliki satu kelas"

    return {
        "mode_name": mode_name,
        "sample_count": int(len(y_true_arr)),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "balanced_accuracy": balanced_accuracy,
        "specificity_tnr": _safe_rate(tn, tn + fp),
        "false_positive_rate": _safe_rate(fp, fp + tn),
        "false_negative_rate": _safe_rate(fn, fn + tp),
        "roc_auc": roc_auc,
        "roc_auc_reason": roc_auc_reason,
        "average_precision": average_precision,
        "average_precision_reason": average_precision_reason,
        "support_normal": int((y_true_arr == 0).sum()),
        "support_anomaly": int((y_true_arr == 1).sum()),
        "classification_report": report,
    }


def _metrics_summary_rows(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    keys = [
        "sample_count",
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "balanced_accuracy",
        "specificity_tnr",
        "false_positive_rate",
        "false_negative_rate",
        "roc_auc",
        "average_precision",
        "support_normal",
        "support_anomaly",
    ]
    return [{"metric": key, "value": metrics.get(key)} for key in keys]


def _write_classification_report_csv(path: Path, report: dict[str, Any]) -> None:
    rows = []
    for label, values in report.items():
        if isinstance(values, dict):
            row = {"label": label}
            row.update(values)
            rows.append(row)
        else:
            rows.append({"label": label, "value": values})
    pd.DataFrame(rows).to_csv(path, index=False)


def write_metrics_artifacts(
    output_dir: Path,
    metrics: dict[str, Any],
    mode_name: str,
    primary: bool = False,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = mode_name
    _write_json(output_dir / f"metrics_{suffix}.json", metrics)
    pd.DataFrame(_metrics_summary_rows(metrics)).to_csv(
        output_dir / f"metrics_{suffix}.csv",
        index=False,
    )
    cm = metrics["confusion_matrix"]
    pd.DataFrame(
        [
            {"actual": "normal", "predicted_normal": cm["tn"], "predicted_anomaly": cm["fp"]},
            {"actual": "anomaly", "predicted_normal": cm["fn"], "predicted_anomaly": cm["tp"]},
        ]
    ).to_csv(output_dir / f"confusion_matrix_{suffix}.csv", index=False)
    _write_json(
        output_dir / f"classification_report_{suffix}.json",
        metrics.get("classification_report", {}),
    )
    _write_classification_report_csv(
        output_dir / f"classification_report_{suffix}.csv",
        metrics.get("classification_report", {}),
    )

    if primary:
        _write_json(output_dir / "metrics_summary.json", metrics)
        pd.DataFrame(_metrics_summary_rows(metrics)).to_csv(
            output_dir / "metrics_summary.csv",
            index=False,
        )
        pd.DataFrame(
            [
                {"actual": "normal", "predicted_normal": cm["tn"], "predicted_anomaly": cm["fp"]},
                {"actual": "anomaly", "predicted_normal": cm["fn"], "predicted_anomaly": cm["tp"]},
            ]
        ).to_csv(output_dir / "confusion_matrix.csv", index=False)
        _write_json(output_dir / "classification_report.json", metrics.get("classification_report", {}))
        _write_classification_report_csv(
            output_dir / "classification_report.csv",
            metrics.get("classification_report", {}),
        )


def _prediction_mask(predictions_df: pd.DataFrame, include_skipped: bool) -> pd.Series:
    if include_skipped or "evaluation_status" not in predictions_df.columns:
        return pd.Series([True] * len(predictions_df), index=predictions_df.index)
    return ~predictions_df["evaluation_status"].astype(str).isin(SKIPPED_STATUSES)


def _score_series(predictions_df: pd.DataFrame) -> pd.Series | None:
    if "anomaly_score" not in predictions_df.columns:
        return None
    scores = pd.to_numeric(predictions_df["anomaly_score"], errors="coerce")
    return scores if scores.notna().any() else None


def compute_metrics_for_predictions(
    predictions_df: pd.DataFrame,
    include_skipped: bool,
) -> dict[str, dict[str, Any]]:
    mask = _prediction_mask(predictions_df, include_skipped)
    metric_df = predictions_df[mask].copy()
    metrics_by_mode: dict[str, dict[str, Any]] = {}
    if metric_df.empty:
        raise ValueError("Tidak ada window yang dapat dievaluasi setelah filtering skipped windows.")

    score_values = _score_series(metric_df)
    y_score = score_values.tolist() if score_values is not None else None
    metrics_by_mode["is_anomaly"] = compute_metrics(
        metric_df["y_true"].astype(int).tolist(),
        metric_df["y_pred_is_anomaly"].astype(bool).tolist(),
        y_score=y_score,
        mode_name="is_anomaly",
    )
    if "y_pred_strict_is_anomaly" in metric_df.columns and metric_df[
        "y_pred_strict_is_anomaly"
    ].notna().any():
        metrics_by_mode["strict_is_anomaly"] = compute_metrics(
            metric_df["y_true"].astype(int).tolist(),
            metric_df["y_pred_strict_is_anomaly"].astype(bool).tolist(),
            y_score=y_score,
            mode_name="strict_is_anomaly",
        )
    return metrics_by_mode


def run_threshold_sweep(
    predictions_df: pd.DataFrame,
    threshold_min: float,
    threshold_max: float,
    threshold_step: float,
) -> tuple[pd.DataFrame, dict[str, Any] | None]:
    scores = _score_series(predictions_df)
    if scores is None:
        return pd.DataFrame(), None

    rows = []
    thresholds = np.arange(threshold_min, threshold_max + threshold_step / 2, threshold_step)
    for threshold in thresholds:
        y_pred = (scores >= threshold).fillna(False).astype(int)
        metrics = compute_metrics(
            predictions_df["y_true"].astype(int).tolist(),
            y_pred.tolist(),
            mode_name="threshold",
        )
        rows.append(
            {
                "threshold": round(float(threshold), 6),
                "accuracy": metrics["accuracy"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1_score": metrics["f1_score"],
            }
        )
    sweep_df = pd.DataFrame(rows)
    if sweep_df.empty:
        return sweep_df, None
    best_row = sweep_df.sort_values(
        ["f1_score", "recall", "precision"],
        ascending=False,
    ).iloc[0]
    return sweep_df, best_row.to_dict()


def _quadrant(row: pd.Series, y_pred_column: str) -> str:
    y_true = int(row["y_true"])
    y_pred = int(_as_bool(row[y_pred_column]))
    if y_true == 0 and y_pred == 0:
        return "tn"
    if y_true == 0 and y_pred == 1:
        return "fp"
    if y_true == 1 and y_pred == 0:
        return "fn"
    return "tp"


def write_error_analysis(
    output_dir: Path,
    predictions_df: pd.DataFrame,
    y_pred_column: str = "y_pred_is_anomaly",
) -> dict[str, Any]:
    analysis_df = predictions_df.copy()
    analysis_df["quadrant"] = analysis_df.apply(
        lambda row: _quadrant(row, y_pred_column),
        axis=1,
    )
    fp = analysis_df[analysis_df["quadrant"] == "fp"].copy()
    fn = analysis_df[analysis_df["quadrant"] == "fn"].copy()
    tp = analysis_df[analysis_df["quadrant"] == "tp"].copy()
    tn = analysis_df[analysis_df["quadrant"] == "tn"].copy()

    fp.to_csv(output_dir / "false_positives.csv", index=False)
    fn.to_csv(output_dir / "false_negatives.csv", index=False)
    tp.head(50).to_csv(output_dir / "true_positives_sample.csv", index=False)
    tn.head(50).to_csv(output_dir / "true_negatives_sample.csv", index=False)

    score_means = {}
    if "anomaly_score" in analysis_df.columns:
        score_means = {
            quadrant: float(pd.to_numeric(group["anomaly_score"], errors="coerce").mean())
            for quadrant, group in analysis_df.groupby("quadrant")
        }

    status_counts = {}
    if "evaluation_status" in analysis_df.columns:
        status_counts = {
            str(key): int(value)
            for key, value in analysis_df["evaluation_status"].value_counts().to_dict().items()
        }

    error_summary = {
        "false_positive_count": int(len(fp)),
        "false_negative_count": int(len(fn)),
        "true_positive_count": int(len(tp)),
        "true_negative_count": int(len(tn)),
        "top_false_positive_event_templates": fp["event_template"].astype(str).value_counts().head(10).to_dict()
        if not fp.empty and "event_template" in fp.columns
        else {},
        "top_false_negative_event_templates": fn["event_template"].astype(str).value_counts().head(10).to_dict()
        if not fn.empty and "event_template" in fn.columns
        else {},
        "mean_anomaly_score_by_quadrant": score_means,
        "skipped_unknown_template_count": int(
            analysis_df["evaluation_status"].astype(str).isin(SKIPPED_STATUSES).sum()
        )
        if "evaluation_status" in analysis_df.columns
        else 0,
        "average_unknown_ratio": float(
            pd.to_numeric(analysis_df.get("unknown_ratio", pd.Series(dtype=float)), errors="coerce").mean()
        )
        if "unknown_ratio" in analysis_df.columns
        else None,
        "evaluation_status_counts": status_counts,
    }
    _write_json(output_dir / "error_analysis.json", error_summary)
    return error_summary


def _can_score_auc(metrics: dict[str, Any]) -> bool:
    return isinstance(metrics.get("roc_auc"), float)


def save_plots(
    output_dir: Path,
    predictions_df: pd.DataFrame,
    metrics: dict[str, Any],
    threshold_sweep_df: pd.DataFrame | None = None,
) -> list[str]:
    warnings: list[str] = []
    try:
        import matplotlib.pyplot as plt
    except Exception as exc:  # pragma: no cover
        return [f"Plot tidak dibuat karena matplotlib tidak tersedia: {exc}"]

    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    try:
        cm = metrics["confusion_matrix"]
        matrix = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.imshow(matrix, cmap="Blues")
        ax.set_xticks([0, 1], labels=["Normal", "Anomaly"])
        ax.set_yticks([0, 1], labels=["Normal", "Anomaly"])
        ax.set_xlabel("Prediksi")
        ax.set_ylabel("Aktual")
        for (row_idx, col_idx), value in np.ndenumerate(matrix):
            ax.text(col_idx, row_idx, str(value), ha="center", va="center")
        fig.tight_layout()
        fig.savefig(plots_dir / "confusion_matrix.png", dpi=150)
        plt.close(fig)
    except Exception as exc:
        warnings.append(f"confusion_matrix.png gagal dibuat: {exc}")

    scores = _score_series(predictions_df)
    if scores is not None:
        try:
            fig, ax = plt.subplots(figsize=(5, 3))
            for label, group in predictions_df.assign(score=scores).groupby("y_true"):
                ax.hist(group["score"].dropna(), bins=30, alpha=0.6, label=f"y={label}")
            ax.set_xlabel("Anomaly score")
            ax.set_ylabel("Jumlah window")
            ax.legend()
            fig.tight_layout()
            fig.savefig(plots_dir / "anomaly_score_distribution.png", dpi=150)
            plt.close(fig)
        except Exception as exc:
            warnings.append(f"anomaly_score_distribution.png gagal dibuat: {exc}")

        if roc_curve is not None and _can_score_auc(metrics):
            try:
                fpr_values, tpr_values, _ = roc_curve(
                    predictions_df["y_true"].astype(int),
                    scores.astype(float),
                )
                fig, ax = plt.subplots(figsize=(4, 3))
                ax.plot(fpr_values, tpr_values, label=f"ROC-AUC={metrics['roc_auc']:.4f}")
                ax.plot([0, 1], [0, 1], linestyle="--", color="gray")
                ax.set_xlabel("FPR")
                ax.set_ylabel("TPR")
                ax.legend()
                fig.tight_layout()
                fig.savefig(plots_dir / "roc_curve.png", dpi=150)
                plt.close(fig)
            except Exception as exc:
                warnings.append(f"roc_curve.png gagal dibuat: {exc}")

        if precision_recall_curve is not None:
            try:
                precision_values, recall_values, _ = precision_recall_curve(
                    predictions_df["y_true"].astype(int),
                    scores.astype(float),
                )
                fig, ax = plt.subplots(figsize=(4, 3))
                ax.plot(recall_values, precision_values)
                ax.set_xlabel("Recall")
                ax.set_ylabel("Precision")
                fig.tight_layout()
                fig.savefig(plots_dir / "precision_recall_curve.png", dpi=150)
                plt.close(fig)
            except Exception as exc:
                warnings.append(f"precision_recall_curve.png gagal dibuat: {exc}")

    if threshold_sweep_df is not None and not threshold_sweep_df.empty:
        try:
            fig, ax = plt.subplots(figsize=(5, 3))
            ax.plot(threshold_sweep_df["threshold"], threshold_sweep_df["f1_score"])
            ax.set_xlabel("Threshold")
            ax.set_ylabel("F1-score")
            fig.tight_layout()
            fig.savefig(plots_dir / "threshold_f1_curve.png", dpi=150)
            plt.close(fig)
        except Exception as exc:
            warnings.append(f"threshold_f1_curve.png gagal dibuat: {exc}")

    return warnings


def _format_metric(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _confusion_table(metrics: dict[str, Any]) -> str:
    cm = metrics["confusion_matrix"]
    return "\n".join(
        [
            "| Aktual \\ Prediksi | Normal | Anomaly |",
            "| --- | ---: | ---: |",
            f"| Normal | {cm['tn']} | {cm['fp']} |",
            f"| Anomaly | {cm['fn']} | {cm['tp']} |",
        ]
    )


def _metrics_table(metrics: dict[str, Any]) -> str:
    rows = [
        ("Accuracy", metrics.get("accuracy")),
        ("Precision", metrics.get("precision")),
        ("Recall", metrics.get("recall")),
        ("F1-score", metrics.get("f1_score")),
        ("ROC-AUC", metrics.get("roc_auc")),
        ("Balanced Accuracy", metrics.get("balanced_accuracy")),
        ("Support Normal", metrics.get("support_normal")),
        ("Support Anomaly", metrics.get("support_anomaly")),
    ]
    lines = ["| Metrik | Nilai |", "| --- | ---: |"]
    lines.extend(f"| {label} | {_format_metric(value)} |" for label, value in rows)
    return "\n".join(lines)


def render_report(
    *,
    output_dir: Path,
    input_log: Path,
    label_file: Path | None,
    label_metadata: dict[str, Any],
    config: DetectorRunConfig,
    parsed_df: pd.DataFrame,
    templates: list[dict[str, Any]],
    predictions_df: pd.DataFrame,
    metrics_by_mode: dict[str, dict[str, Any]],
    threshold_best: dict[str, Any] | None,
    threshold_sweep_df: pd.DataFrame | None,
    error_summary: dict[str, Any],
    promotion_decision: dict[str, Any],
    warnings: list[str],
    include_skipped: bool,
) -> Path:
    primary_metrics = metrics_by_mode["is_anomaly"]
    label_counts = predictions_df["y_true"].value_counts().to_dict() if not predictions_df.empty else {}
    skipped_windows = int(
        predictions_df["evaluation_status"].astype(str).isin(SKIPPED_STATUSES).sum()
    ) if "evaluation_status" in predictions_df.columns else 0
    evaluated_windows = len(predictions_df) if include_skipped else len(predictions_df[_prediction_mask(predictions_df, False)])

    lines = [
        "# Laporan Evaluasi Kinerja DeepLog",
        "",
        "## 1. Ringkasan Eksekusi",
        "",
        (
            "Pengujian dilakukan untuk menilai kinerja DeepLogDetector dalam "
            "membedakan window log normal dan anomali. Evaluasi dilakukan "
            f"terhadap {evaluated_windows} window yang berhasil dipetakan dengan "
            f"label ground truth menggunakan kebijakan pelabelan "
            f"{predictions_df['label_policy_used'].mode().iloc[0] if not predictions_df.empty else 'N/A'}. "
            f"Mode is_anomaly memperoleh accuracy {_format_metric(primary_metrics['accuracy'])}, "
            f"precision {_format_metric(primary_metrics['precision'])}, recall "
            f"{_format_metric(primary_metrics['recall'])}, F1-score "
            f"{_format_metric(primary_metrics['f1_score'])}, dan ROC-AUC "
            f"{_format_metric(primary_metrics['roc_auc'])}."
        ),
        "",
        "## 2. Tujuan Evaluasi",
        "",
        (
            "Evaluasi ini bertujuan mengukur performa deteksi anomali log berbasis "
            "Deep Learning pada DeepLogDetector menggunakan metrik klasifikasi "
            "formal berbasis ground truth."
        ),
        "",
        "## 3. Dataset dan Ground Truth",
        "",
        f"- Path input log: `{input_log}`",
        f"- Path label file: `{label_file or input_log}`",
        f"- Label column: `{label_metadata.get('label_column')}`",
        f"- Line id column: `{label_metadata.get('line_id_column')}`",
        f"- Jumlah parsed log: `{len(parsed_df)}`",
        f"- Jumlah label normal: `{int(label_counts.get(0, 0))}`",
        f"- Jumlah label anomaly: `{int(label_counts.get(1, 0))}`",
        "- Normalisasi label: `-`, `0`, `normal`, `benign` menjadi 0; "
        "`EoRS`, `EoHT`, `1`, `anomaly`, `attack` menjadi 1.",
        "",
        (
            "Catatan dataset: LMD-2023 2.3M dipilih sebagai default karena "
            "memiliki label event-level dan event template yang selaras dengan "
            "artifact DeepLog runtime. HDFS memiliki label block-level, Windows-APT "
            "2025 menyediakan metadata skenario yang bersifat weak label, dan "
            "COMISET berukuran sangat besar sehingga tidak dijadikan default."
        ),
        "",
        "## 4. Konfigurasi DeepLog",
        "",
        f"- Eval mode: `{config.eval_mode}`",
        f"- Model path: `{config.model_path}`",
        f"- Vocab path: `{config.vocab_path}`",
        f"- Window size: `{config.window_size}`",
        f"- Step size: `{config.step_size}`",
        f"- Top-k: `{config.topk}`",
        f"- Parser profile: `{config.profile_name}`",
        f"- Template strategy: `{config.template_strategy}`",
        f"- Template enrichment: `{config.template_enrichment}`",
        f"- Template count: `{len(templates)}`",
        f"- Window evaluated: `{evaluated_windows}`",
        f"- Window skipped/unknown: `{skipped_windows}`",
        f"- Include skipped: `{include_skipped}`",
        "",
        "## 5. Metodologi Evaluasi",
        "",
        (
            "Log diparsing atau dibaca sebagai structured log, kemudian kolom "
            "event_template dipakai sebagai sequence DeepLog. DeepLog melakukan "
            "prediksi next-event berbasis sliding window. Hasil prediksi window "
            "dibandingkan dengan ground truth menggunakan label target event "
            "berdasarkan `end_idx`; jika target tidak dapat dipetakan, evaluator "
            "fallback ke kebijakan `any_in_window` dan mencatat warning."
        ),
        "",
        "- TP: window anomaly yang diprediksi anomaly.",
        "- TN: window normal yang diprediksi normal.",
        "- FP: window normal yang diprediksi anomaly.",
        "- FN: window anomaly yang diprediksi normal.",
        "",
        "Accuracy = (TP + TN) / (TP + TN + FP + FN)",
        "",
        "Precision = TP / (TP + FP)",
        "",
        "Recall = TP / (TP + FN)",
        "",
        "F1-score = 2 * Precision * Recall / (Precision + Recall)",
        "",
        "ROC-AUC hanya dihitung jika anomaly_score tersedia dan y_true memiliki dua kelas.",
        "",
        "## 6. Hasil Pengujian Utama",
        "",
    ]

    for mode_name, metrics in metrics_by_mode.items():
        title = "6.1 Mode is_anomaly" if mode_name == "is_anomaly" else "6.2 Mode strict_is_anomaly"
        lines.extend([f"### {title}", "", _metrics_table(metrics), "", _confusion_table(metrics), ""])
        if metrics.get("roc_auc") == "N/A":
            lines.append(f"ROC-AUC N/A: {metrics.get('roc_auc_reason')}")
            lines.append("")

    if "strict_is_anomaly" in metrics_by_mode:
        strict_metrics = metrics_by_mode["strict_is_anomaly"]
        lines.extend(
            [
                "### 6.3 Perbandingan Mode",
                "",
                "| Mode | Accuracy | Precision | Recall | F1-score | ROC-AUC |",
                "| --- | ---: | ---: | ---: | ---: | ---: |",
                (
                    f"| is_anomaly | {_format_metric(primary_metrics['accuracy'])} | "
                    f"{_format_metric(primary_metrics['precision'])} | "
                    f"{_format_metric(primary_metrics['recall'])} | "
                    f"{_format_metric(primary_metrics['f1_score'])} | "
                    f"{_format_metric(primary_metrics['roc_auc'])} |"
                ),
                (
                    f"| strict_is_anomaly | {_format_metric(strict_metrics['accuracy'])} | "
                    f"{_format_metric(strict_metrics['precision'])} | "
                    f"{_format_metric(strict_metrics['recall'])} | "
                    f"{_format_metric(strict_metrics['f1_score'])} | "
                    f"{_format_metric(strict_metrics['roc_auc'])} |"
                ),
                "",
            ]
        )

    gate_status = "PASS" if promotion_decision.get("passed") else "FAIL"
    failed_criteria = promotion_decision.get("failed_criteria") or []
    gate_metrics = promotion_decision.get("metrics", {})
    gate_criteria = promotion_decision.get("criteria", {})
    lines.extend(
        [
            "## 7. Promotion Gate Natural Eval",
            "",
            f"Status: **{gate_status}**",
            "",
            "| Kriteria | Nilai | Batas | Status |",
            "| --- | ---: | ---: | --- |",
            (
                f"| Recall | {_format_metric(gate_metrics.get('recall'))} | "
                f">= {_format_metric(gate_criteria.get('recall_min'))} | "
                f"{'FAIL' if 'recall' in failed_criteria else 'PASS'} |"
            ),
            (
                f"| F1-score | {_format_metric(gate_metrics.get('f1_score'))} | "
                f"> {_format_metric(gate_criteria.get('f1_score_gt'))} | "
                f"{'FAIL' if 'f1_score' in failed_criteria else 'PASS'} |"
            ),
            (
                f"| Precision | {_format_metric(gate_metrics.get('precision'))} | "
                f">= {_format_metric(gate_criteria.get('precision_min'))} | "
                f"{'FAIL' if 'precision' in failed_criteria else 'PASS'} |"
            ),
            (
                f"| FPR | {_format_metric(gate_metrics.get('false_positive_rate'))} | "
                f"<= {_format_metric(gate_criteria.get('false_positive_rate_max'))} | "
                f"{'FAIL' if 'false_positive_rate' in failed_criteria else 'PASS'} |"
            ),
            (
                f"| Precision-recall gap | {_format_metric(gate_metrics.get('precision_recall_gap'))} | "
                f"<= {_format_metric(gate_criteria.get('precision_recall_gap_max'))} | "
                f"{'FAIL' if 'precision_recall_gap' in failed_criteria else 'PASS'} |"
            ),
            "",
            (
                "Model baru hanya layak dipromosikan ke runtime jika gate ini PASS "
                "pada natural evaluation. Balanced evaluation tetap dilaporkan sebagai "
                "pembanding, bukan metrik utama."
            ),
            "",
        ]
    )

    lines.extend(["## 8. Analisis Threshold", ""])
    if threshold_best:
        lines.extend(
            [
                (
                    f"Threshold terbaik berdasarkan F1 adalah "
                    f"`{_format_metric(threshold_best.get('threshold'))}` dengan "
                    f"F1-score `{_format_metric(threshold_best.get('f1_score'))}`."
                ),
                "",
                "Threshold rendah cenderung meningkatkan recall, tetapi dapat menaikkan false positive. "
                "Threshold tinggi dapat menurunkan false positive, tetapi berisiko menaikkan false negative.",
                "",
            ]
        )
        if threshold_sweep_df is not None and not threshold_sweep_df.empty:
            lines.extend(["| Threshold | Accuracy | Precision | Recall | F1-score |", "| ---: | ---: | ---: | ---: | ---: |"])
            for _, row in threshold_sweep_df.sort_values("f1_score", ascending=False).head(5).iterrows():
                lines.append(
                    f"| {_format_metric(row['threshold'])} | {_format_metric(row['accuracy'])} | "
                    f"{_format_metric(row['precision'])} | {_format_metric(row['recall'])} | "
                    f"{_format_metric(row['f1_score'])} |"
                )
            lines.append("")
    else:
        lines.append("Threshold analysis tidak dilakukan karena --threshold-sweep tidak diaktifkan atau anomaly_score tidak tersedia.")
        lines.append("")

    lines.extend(
        [
            "## 9. Analisis Kesalahan",
            "",
            f"- False positive: `{error_summary.get('false_positive_count', 0)}`",
            f"- False negative: `{error_summary.get('false_negative_count', 0)}`",
            f"- True positive: `{error_summary.get('true_positive_count', 0)}`",
            f"- True negative: `{error_summary.get('true_negative_count', 0)}`",
            "",
            "Top event_template pada FP:",
            "",
        ]
    )
    fp_events = error_summary.get("top_false_positive_event_templates", {})
    if fp_events:
        lines.extend([f"- `{event}`: {count}" for event, count in fp_events.items()])
    else:
        lines.append("- Tidak ada FP.")
    lines.extend(["", "Top event_template pada FN:", ""])
    fn_events = error_summary.get("top_false_negative_event_templates", {})
    if fn_events:
        lines.extend([f"- `{event}`: {count}" for event, count in fn_events.items()])
    else:
        lines.append("- Tidak ada FN.")
    lines.extend(
        [
            "",
            (
                "Indikasi awal FP/FN dapat disebabkan oleh perbedaan distribusi "
                "template, perubahan urutan event, atau mapping label line-level "
                "ke window-level. Interpretasi ini perlu validasi lebih lanjut "
                "dengan inspeksi sampel FP/FN."
            ),
            "",
            "## 10. Artefak Output",
            "",
        ]
    )
    artifact_names = sorted(path.name for path in output_dir.glob("*") if path.is_file())
    if "deeplog_evaluation_report.md" not in artifact_names:
        artifact_names.append("deeplog_evaluation_report.md")
    for artifact in artifact_names:
        lines.append(f"- `{artifact}`")
    if (output_dir / "plots").exists() and any((output_dir / "plots").glob("*.png")):
        lines.append("- `plots/*.png`")
    lines.extend(
        [
            "",
            "## 11. Keterbatasan Evaluasi",
            "",
            "- Hasil sangat bergantung pada kualitas ground truth label.",
            "- Mapping line-level label ke window-level label dapat mempengaruhi hasil.",
            "- Dataset berbeda format dapat mempengaruhi hasil parsing dan vocabulary matching.",
            "- Status skipped/unknown template tidak selalu berarti normal atau anomaly.",
            "- Jika model artifact berasal dari training eksternal, evaluasi ini hanya menguji runtime model yang tersedia dan bukan mereproduksi training.",
            "",
            "## 12. Kesimpulan",
            "",
            (
                f"Berdasarkan nilai F1-score sebesar {_format_metric(primary_metrics['f1_score'])}, "
                "model menunjukkan kemampuan deteksi yang harus dibaca bersama precision "
                f"{_format_metric(primary_metrics['precision'])} dan recall "
                f"{_format_metric(primary_metrics['recall'])}. Nilai precision menunjukkan "
                "proporsi prediksi anomaly yang benar, sedangkan recall menunjukkan proporsi "
                "window anomaly ground truth yang berhasil ditemukan."
            ),
            "",
        ]
    )
    if warnings:
        lines.extend(["## Lampiran Warning", ""])
        lines.extend(f"- {warning}" for warning in warnings[:100])
        if len(warnings) > 100:
            lines.append(f"- ... {len(warnings) - 100} warning lain disimpan di artefak runtime.")
        lines.append("")

    report_path = output_dir / "deeplog_evaluation_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def _serialize_complex_columns(df: pd.DataFrame) -> pd.DataFrame:
    output = df.copy()
    for column in output.columns:
        if output[column].map(lambda value: isinstance(value, (list, dict))).any():
            output[column] = output[column].map(
                lambda value: json.dumps(value, default=_json_default)
                if isinstance(value, (list, dict))
                else value
            )
    return output


def _records_label(records_path: Path) -> str:
    name = records_path.name
    if name.endswith(".records.gz"):
        return name[: -len(".records.gz")]
    if name.endswith(".gz"):
        name = name[:-3]
    return Path(name).stem


def _session_prediction_rows(
    sessions: Sequence[CachedSession],
    session_scores: Sequence[float],
    predictions_by_topk: dict[int, Sequence[int | bool]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for session_idx, session in enumerate(sessions):
        row = {
            "session_idx": session_idx,
            "y_true": int(session.label),
            "session_count": int(session.count),
            "sequence_length": len(session.sequence),
            "anomaly_score": float(session_scores[session_idx]),
            "event_template_sequence": " | ".join(session.sequence),
        }
        for topk_value, predictions in predictions_by_topk.items():
            row[f"y_pred_topk_{topk_value}"] = int(bool(predictions[session_idx]))
        rows.append(row)
    return rows


def _expanded_prediction_df(
    *,
    sessions: Sequence[CachedSession],
    session_predictions: Sequence[int | bool],
    session_scores: Sequence[float],
    topk_value: int,
) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for session_idx, session in enumerate(sessions):
        for repeat_idx in range(max(0, int(session.count))):
            rows.append(
                {
                    "row_id": len(rows),
                    "session_idx": session_idx,
                    "session_repeat_idx": repeat_idx,
                    "topk": topk_value,
                    "y_true": int(session.label),
                    "y_pred_is_anomaly": int(bool(session_predictions[session_idx])),
                    "anomaly_score": float(session_scores[session_idx]),
                    "session_count": int(session.count),
                    "sequence_length": len(session.sequence),
                    "event_template": session.sequence[-1] if session.sequence else "",
                    "event_template_sequence": " | ".join(session.sequence),
                }
            )
    return pd.DataFrame(rows)


def _write_cached_error_files(
    *,
    output_dir: Path,
    session_rows_df: pd.DataFrame,
    topk_value: int,
    primary: bool,
) -> dict[str, Any]:
    analysis_df = session_rows_df.copy()
    prediction_column = f"y_pred_topk_{topk_value}"
    analysis_df["quadrant"] = analysis_df.apply(
        lambda row: _quadrant(
            pd.Series(
                {
                    "y_true": row["y_true"],
                    "y_pred_is_anomaly": row[prediction_column],
                }
            ),
            "y_pred_is_anomaly",
        ),
        axis=1,
    )

    fp = analysis_df[analysis_df["quadrant"] == "fp"].copy()
    fn = analysis_df[analysis_df["quadrant"] == "fn"].copy()
    tp = analysis_df[analysis_df["quadrant"] == "tp"].copy()
    tn = analysis_df[analysis_df["quadrant"] == "tn"].copy()

    fp_path = output_dir / f"false_positives_topk_{topk_value}.csv"
    fn_path = output_dir / f"false_negatives_topk_{topk_value}.csv"
    fp.to_csv(fp_path, index=False)
    fn.to_csv(fn_path, index=False)
    tp.head(50).to_csv(output_dir / f"true_positives_sample_topk_{topk_value}.csv", index=False)
    tn.head(50).to_csv(output_dir / f"true_negatives_sample_topk_{topk_value}.csv", index=False)
    if primary:
        fp.to_csv(output_dir / "false_positives.csv", index=False)
        fn.to_csv(output_dir / "false_negatives.csv", index=False)

    return {
        "topk": topk_value,
        "false_positive_unique_sessions": int(len(fp)),
        "false_negative_unique_sessions": int(len(fn)),
        "true_positive_unique_sessions": int(len(tp)),
        "true_negative_unique_sessions": int(len(tn)),
        "false_positive_expanded_count": int(fp["session_count"].sum()) if not fp.empty else 0,
        "false_negative_expanded_count": int(fn["session_count"].sum()) if not fn.empty else 0,
    }


def _predict_cached_sessions(
    *,
    detector: DeepLogDetector,
    sessions: Sequence[CachedSession],
    topk_values: Sequence[int],
    history_size: int,
    batch_size: int,
) -> tuple[dict[int, list[int]], list[float], int]:
    if not topk_values:
        raise ValueError("At least one top-k value is required for cached evaluation.")
    max_topk = max(topk_values)
    model_vocab_size = int(getattr(detector.model, "vocab_size", len(detector.vocab)))
    if max_topk > model_vocab_size:
        raise ValueError(
            f"topk={max_topk} exceeds DeepLog output vocabulary size {model_vocab_size}."
        )

    windows = build_cached_windows(
        sessions,
        history_size=history_size,
        pad_token=str(getattr(detector.vocab, "pad_token", "padding")),
    )
    predictions_by_topk = {
        int(topk_value): [0 for _ in sessions] for topk_value in sorted(topk_values)
    }
    session_scores = [0.0 for _ in sessions]
    if not windows:
        return predictions_by_topk, session_scores, 0

    encoded_histories: list[list[int]] = []
    target_indices: list[int] = []
    unsupported_history: list[bool] = []
    for window in windows:
        history_indices = [detector._event_to_index(template) for template in window.history]
        target_idx = detector._event_to_index(window.target)
        encoded_histories.append(history_indices)
        target_indices.append(target_idx)
        unsupported_history.append(any(index >= model_vocab_size for index in history_indices))

    device = torch.device(detector.device)
    detector.model.eval()
    with torch.no_grad():
        for start in range(0, len(windows), max(1, batch_size)):
            end = min(start + max(1, batch_size), len(windows))
            batch_tensor = torch.tensor(
                encoded_histories[start:end],
                dtype=torch.long,
                device=device,
            )
            probabilities = detector.model(
                {"sequential": batch_tensor},
                device=detector.device,
            ).probabilities
            topk_indices = torch.topk(probabilities, k=max_topk, dim=1).indices.cpu().tolist()
            probabilities_cpu = probabilities.cpu()

            for local_idx, predicted_indices in enumerate(topk_indices):
                window_idx = start + local_idx
                window = windows[window_idx]
                target_idx = int(target_indices[window_idx])
                if 0 <= target_idx < probabilities_cpu.shape[1]:
                    actual_prob = float(probabilities_cpu[local_idx, target_idx].item())
                else:
                    actual_prob = 0.0
                session_scores[window.session_idx] = max(
                    session_scores[window.session_idx],
                    float(max(0.0, 1.0 - actual_prob)),
                )

                for topk_value in predictions_by_topk:
                    miss = target_idx not in predicted_indices[:topk_value]
                    if unsupported_history[window_idx] or miss:
                        predictions_by_topk[topk_value][window.session_idx] = 1

    return predictions_by_topk, session_scores, len(windows)


def render_cached_records_report(
    *,
    output_dir: Path,
    records_path: Path,
    cached_config: Path | None,
    model_path: Path,
    vocab_path: Path,
    raw_session_count: int,
    deduped_session_count: int,
    cached_window_count: int,
    metrics_by_topk: dict[int, dict[str, Any]],
    error_summaries: dict[int, dict[str, Any]],
    promotion_decisions_by_topk: dict[int, dict[str, Any]] | None = None,
    calibrations_by_topk: dict[int, dict[str, Any]] | None = None,
    decision_policy: str = "topk",
) -> Path:
    label = _records_label(records_path)
    lines = [
        f"# DeepLog Cached-Records Evaluation ({label})",
        "",
        "Evaluasi ini memakai `.records.gz` yang sama dengan pipeline training DeepLog, "
        "termasuk deduplikasi sequence dan ekspansi kembali berdasarkan jumlah sesi asli. "
        "Mode ini dipakai untuk membandingkan evaluator backend dengan baseline training lama secara apple-to-apple.",
        "",
        "## Input",
        "",
        f"- Records: `{records_path}`",
        f"- Config: `{cached_config}`" if cached_config else "- Config: direct records path",
        f"- Model: `{model_path}`",
        f"- Vocab: `{vocab_path}`",
        f"- Raw sessions: {raw_session_count}",
        f"- Deduped sessions: {deduped_session_count}",
        f"- Cached DeepLog windows: {cached_window_count}",
        f"- Decision policy: `{decision_policy}`",
        "",
        "## Metrics",
        "",
        "| top-k | threshold | promotion | total | normal | anomaly | TN | FP | FN | TP | accuracy | precision | recall | F1 | specificity | FPR | FNR | balanced accuracy |",
        "| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    calibrations_by_topk = calibrations_by_topk or {}
    promotion_decisions_by_topk = promotion_decisions_by_topk or {}
    for topk_value in sorted(metrics_by_topk):
        metrics = metrics_by_topk[topk_value]
        cm = metrics["confusion_matrix"]
        threshold = calibrations_by_topk.get(topk_value, {}).get("recommended_threshold", "")
        promotion = promotion_decisions_by_topk.get(topk_value, {})
        promotion_status = "PASS" if promotion.get("passed") else "FAIL"
        lines.append(
            f"| {topk_value} | {_format_metric(threshold)} | {promotion_status} | "
            f"{metrics['sample_count']} | {metrics['support_normal']} | "
            f"{metrics['support_anomaly']} | {cm['tn']} | {cm['fp']} | {cm['fn']} | {cm['tp']} | "
            f"{_format_metric(metrics['accuracy'])} | {_format_metric(metrics['precision'])} | "
            f"{_format_metric(metrics['recall'])} | {_format_metric(metrics['f1_score'])} | "
            f"{_format_metric(metrics['specificity_tnr'])} | "
            f"{_format_metric(metrics['false_positive_rate'])} | "
            f"{_format_metric(metrics['false_negative_rate'])} | "
            f"{_format_metric(metrics['balanced_accuracy'])} |"
        )

    lines.extend(["", "## Promotion Gate", ""])
    for topk_value in sorted(metrics_by_topk):
        decision = promotion_decisions_by_topk.get(topk_value, {})
        failed = decision.get("failed_criteria") or []
        status = "PASS" if decision.get("passed") else "FAIL"
        failed_text = ", ".join(failed) if failed else "-"
        lines.append(f"- top-k {topk_value}: {status}; failed criteria: {failed_text}")
    lines.extend(
        [
            "",
            "Gate PASS berarti natural eval memenuhi recall, F1 baseline, precision, FPR, "
            "dan precision-recall gap. Balanced eval tidak boleh menjadi dasar promosi.",
            "",
        ]
    )

    lines.extend(["## Error Summary", ""])
    for topk_value in sorted(error_summaries):
        summary = error_summaries[topk_value]
        lines.append(
            f"- top-k {topk_value}: FP unique={summary['false_positive_unique_sessions']} "
            f"(expanded={summary['false_positive_expanded_count']}), "
            f"FN unique={summary['false_negative_unique_sessions']} "
            f"(expanded={summary['false_negative_expanded_count']})"
        )
    lines.append("")

    report_path = output_dir / f"deeplog_cached_{label}_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def run_cached_records_evaluation(
    *,
    records_path: Path,
    output_dir: Path,
    cached_config: Path | None,
    model_path: Path,
    vocab_path: Path,
    topk_values: Sequence[int],
    history_size: int,
    batch_size: int,
    decision_policy: str = "topk",
    target_recall: float = 0.80,
    score_threshold: float | None = None,
    calibrate_score_threshold_flag: bool = False,
    min_precision: float = 0.0,
    max_fpr: float = 1.0,
    max_precision_recall_gap: float = 1.0,
    require_healthy_threshold: bool = False,
) -> list[EvaluationResult]:
    if not records_path.exists():
        raise FileNotFoundError(f"Cached records not found: {records_path}")
    if not model_path.exists() or not vocab_path.exists():
        raise FileNotFoundError(
            f"DeepLog cached artifacts not found. model={model_path} vocab={vocab_path}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    raw_records = load_cached_records(records_path)
    sessions = deduplicate_cached_sessions(raw_records)
    detector = DeepLogDetector(
        str(model_path),
        str(vocab_path),
        window_size=history_size,
        step_size=1,
        topk=max(topk_values),
        skip_unknown_windows=False,
        unknown_template_mode="anomaly",
        template_similarity_enabled=False,
    )

    predictions_by_topk, session_scores, cached_window_count = _predict_cached_sessions(
        detector=detector,
        sessions=sessions,
        topk_values=topk_values,
        history_size=history_size,
        batch_size=batch_size,
    )
    session_rows_df = pd.DataFrame(
        _session_prediction_rows(sessions, session_scores, predictions_by_topk)
    )
    session_rows_df.to_csv(output_dir / "cached_session_predictions.csv", index=False)

    metrics_by_topk: dict[int, dict[str, Any]] = {}
    calibrations_by_topk: dict[int, dict[str, Any]] = {}
    promotion_decisions_by_topk: dict[int, dict[str, Any]] = {}
    error_summaries: dict[int, dict[str, Any]] = {}
    summary_rows: list[dict[str, Any]] = []
    results: list[EvaluationResult] = []
    label = _records_label(records_path)

    for index, topk_value in enumerate(sorted(predictions_by_topk)):
        session_predictions = predictions_by_topk[topk_value]
        y_true, y_pred, y_score = expand_cached_predictions(
            sessions=sessions,
            session_predictions=session_predictions,
            session_scores=session_scores,
        )
        selected_threshold = score_threshold
        effective_session_predictions = list(session_predictions)
        if decision_policy == "f1_constrained_recall":
            if calibrate_score_threshold_flag:
                calibration = calibrate_score_threshold(
                    y_true=y_true,
                    y_score=y_score or [],
                    base_pred=y_pred,
                    target_recall=target_recall,
                    min_precision=min_precision,
                    max_fpr=max_fpr,
                    max_precision_recall_gap=max_precision_recall_gap,
                    require_healthy_threshold=require_healthy_threshold,
                )
                selected_threshold = float(calibration["recommended_threshold"])
                calibrations_by_topk[topk_value] = calibration
                pd.DataFrame(calibration["pareto_rows"]).to_csv(
                    output_dir / f"threshold_pareto_topk_{topk_value}.csv",
                    index=False,
                )
                _write_json(
                    output_dir / f"threshold_calibration_topk_{topk_value}.json",
                    calibration,
                )
                if index == 0:
                    _write_json(output_dir / "threshold_calibration.json", calibration)
            if selected_threshold is None:
                raise ValueError(
                    "score_threshold harus disediakan saat decision_policy=f1_constrained_recall "
                    "dan --calibrate-score-threshold tidak aktif."
                )
            y_pred = [
                int(_as_bool(base_value) or float(score_value) >= float(selected_threshold))
                for base_value, score_value in zip(y_pred, y_score or [])
            ]
            effective_session_predictions = [
                int(_as_bool(base_value) or float(score_value) >= float(selected_threshold))
                for base_value, score_value in zip(session_predictions, session_scores)
            ]
        metrics = compute_metrics(
            y_true=y_true,
            y_pred=y_pred,
            y_score=y_score,
            mode_name=decision_policy if decision_policy != "topk" else "is_anomaly",
        )
        metrics_by_topk[topk_value] = metrics
        promotion_decision = evaluate_promotion_gate(metrics)
        promotion_decisions_by_topk[topk_value] = promotion_decision
        _write_json(output_dir / f"promotion_gate_topk_{topk_value}.json", promotion_decision)
        if index == 0:
            _write_json(output_dir / "promotion_gate.json", promotion_decision)
        write_metrics_artifacts(
            output_dir,
            metrics,
            mode_name=f"cached_{label}_topk_{topk_value}",
            primary=index == 0,
        )

        predictions_df = _expanded_prediction_df(
            sessions=sessions,
            session_predictions=session_predictions,
            session_scores=session_scores,
            topk_value=topk_value,
        )
        if decision_policy == "f1_constrained_recall":
            predictions_df["score_threshold"] = selected_threshold
            predictions_df["decision_policy"] = decision_policy
            predictions_df["recall_floor"] = target_recall
            predictions_df["y_pred_topk_only"] = predictions_df["y_pred_is_anomaly"]
            predictions_df["y_pred_is_anomaly"] = y_pred
            predictions_df["candidate_tier"] = predictions_df.apply(
                lambda row: "high"
                if bool(row["y_pred_topk_only"])
                else (
                    "medium"
                    if float(row["anomaly_score"]) >= float(settings.deeplog_medium_score_threshold)
                    else ("low" if bool(row["y_pred_is_anomaly"]) else "none")
                ),
                axis=1,
            )
            predictions_df["candidate_reasons"] = predictions_df.apply(
                lambda row: ["topk_miss"]
                if bool(row["y_pred_topk_only"])
                else (["score_threshold"] if bool(row["y_pred_is_anomaly"]) else []),
                axis=1,
            )
            tier_rows = (
                predictions_df.groupby(["candidate_tier", "y_true"])
                .size()
                .reset_index(name="count")
            )
            tier_rows.to_csv(output_dir / f"candidate_tier_metrics_topk_{topk_value}.csv", index=False)
            if index == 0:
                tier_rows.to_csv(output_dir / "candidate_tier_metrics.csv", index=False)
        predictions_df.to_csv(output_dir / f"window_predictions_topk_{topk_value}.csv", index=False)
        if index == 0:
            predictions_df.to_csv(output_dir / "window_predictions.csv", index=False)

        error_session_rows_df = session_rows_df.copy()
        error_session_rows_df[f"y_pred_topk_{topk_value}"] = effective_session_predictions
        error_summaries[topk_value] = _write_cached_error_files(
            output_dir=output_dir,
            session_rows_df=error_session_rows_df,
            topk_value=topk_value,
            primary=index == 0,
        )
        cm = metrics["confusion_matrix"]
        summary_rows.append(
            {
                "topk": topk_value,
                "total": metrics["sample_count"],
                "normal": metrics["support_normal"],
                "abnormal": metrics["support_anomaly"],
                "tn": cm["tn"],
                "fp": cm["fp"],
                "fn": cm["fn"],
                "tp": cm["tp"],
                "accuracy": metrics["accuracy"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1_score"],
                "specificity": metrics["specificity_tnr"],
                "fpr": metrics["false_positive_rate"],
                "fnr": metrics["false_negative_rate"],
                "balanced_accuracy": metrics["balanced_accuracy"],
                "roc_auc": metrics["roc_auc"],
                "average_precision": metrics["average_precision"],
                "promotion_passed": promotion_decision["passed"],
                "promotion_failed_criteria": "|".join(promotion_decision["failed_criteria"]),
                "decision_policy": decision_policy,
                "score_threshold": selected_threshold,
                "target_recall": target_recall if decision_policy == "f1_constrained_recall" else None,
            }
        )

    pd.DataFrame(summary_rows).to_csv(output_dir / f"cached_topk_summary_{label}.csv", index=False)
    _write_json(output_dir / f"cached_topk_summary_{label}.json", summary_rows)
    _write_json(output_dir / "error_analysis.json", error_summaries)
    _write_json(
        output_dir / "run_metadata.json",
        {
            "generated_at": datetime.now().isoformat(),
            "records_path": records_path,
            "cached_config": cached_config,
            "model_path": model_path,
            "vocab_path": vocab_path,
            "history_size": history_size,
            "topk_values": list(sorted(topk_values)),
            "decision_policy": decision_policy,
            "score_threshold": score_threshold,
            "target_recall": target_recall,
            "calibrate_score_threshold": calibrate_score_threshold_flag,
            "min_precision": min_precision,
            "max_fpr": max_fpr,
            "max_precision_recall_gap": max_precision_recall_gap,
            "require_healthy_threshold": require_healthy_threshold,
            "promotion_decisions": promotion_decisions_by_topk,
            "raw_session_count": len(raw_records),
            "deduped_session_count": len(sessions),
            "cached_window_count": cached_window_count,
            "expanded_session_count": int(sum(session.count for session in sessions)),
        },
    )

    report_path = render_cached_records_report(
        output_dir=output_dir,
        records_path=records_path,
        cached_config=cached_config,
        model_path=model_path,
        vocab_path=vocab_path,
        raw_session_count=len(raw_records),
        deduped_session_count=len(sessions),
        cached_window_count=cached_window_count,
        metrics_by_topk=metrics_by_topk,
        error_summaries=error_summaries,
        promotion_decisions_by_topk=promotion_decisions_by_topk,
        calibrations_by_topk=calibrations_by_topk,
        decision_policy=decision_policy,
    )

    for topk_value in sorted(metrics_by_topk):
        results.append(
            EvaluationResult(
                mode_name=f"cached_{label}_topk_{topk_value}",
                output_dir=output_dir,
                report_path=report_path,
                metrics_by_mode={"is_anomaly": metrics_by_topk[topk_value]},
                parsed_lines=len(raw_records),
                evaluated_windows=metrics_by_topk[topk_value]["sample_count"],
                skipped_windows=0,
                warnings=[],
            )
        )
    return results


def run_single_evaluation(
    *,
    input_log: Path,
    label_file: Path | None,
    label_column: str | None,
    line_id_column: str | None,
    positive_label: str | None,
    profile: str,
    max_lines: int | None,
    output_dir: Path,
    model_path: Path | None,
    vocab_path: Path | None,
    window_label_policy: str,
    window_label_threshold: float,
    include_skipped: bool,
    threshold_sweep: bool,
    threshold_min: float,
    threshold_max: float,
    threshold_step: float,
    save_plot_files: bool,
    random_seed: int,
    eval_mode: str,
    window_size: int | None,
    step_size: int | None,
    topk: int | None,
    structured_input: bool,
    decision_policy: str | None,
    score_threshold: float | None,
    medium_score_threshold: float | None,
    target_recall: float | None,
) -> EvaluationResult:
    np.random.seed(random_seed)
    output_dir.mkdir(parents=True, exist_ok=True)

    parsed_df, templates, selected_profile, source_df = run_parser(
        input_log=input_log,
        profile=profile,
        max_lines=max_lines,
        structured_input=structured_input,
    )
    labels_df, label_metadata = load_ground_truth_labels(
        input_log=input_log,
        label_file=label_file,
        label_column=label_column,
        line_id_column=line_id_column,
        positive_label=positive_label,
        max_lines=max_lines,
        source_df=source_df,
    )
    labels_df.to_csv(output_dir / "normalized_labels.csv", index=False)
    _serialize_complex_columns(parsed_df).to_csv(output_dir / "parsed_logs.csv", index=False)

    config = build_detector_run_config(
        eval_mode=eval_mode,
        selected_profile=selected_profile,
        model_path=model_path,
        vocab_path=vocab_path,
        window_size=window_size,
        step_size=step_size,
        topk=topk,
        decision_policy=decision_policy,
        score_threshold=score_threshold,
        medium_score_threshold=medium_score_threshold,
        recall_floor=target_recall,
    )
    results_df = normalize_deeplog_results(run_deeplog(parsed_df, config))
    _serialize_complex_columns(results_df).to_csv(output_dir / "deeplog_raw_results.csv", index=False)

    predictions_df = build_window_ground_truth(
        results_df=results_df,
        parsed_df=parsed_df,
        labels_df=labels_df,
        policy=window_label_policy,
        window_label_threshold=window_label_threshold,
    )
    warnings = list(predictions_df.attrs.get("warnings", []))
    if predictions_df.empty:
        raise ValueError("Tidak ada window DeepLog yang berhasil dipetakan ke ground truth.")

    _serialize_complex_columns(predictions_df).to_csv(output_dir / "window_predictions.csv", index=False)
    metric_df = predictions_df[_prediction_mask(predictions_df, include_skipped)].copy()
    metrics_by_mode = compute_metrics_for_predictions(predictions_df, include_skipped)
    for index, (mode_name, metrics) in enumerate(metrics_by_mode.items()):
        write_metrics_artifacts(output_dir, metrics, mode_name, primary=index == 0)
    promotion_decision = evaluate_promotion_gate(metrics_by_mode["is_anomaly"])
    _write_json(output_dir / "promotion_gate.json", promotion_decision)

    threshold_sweep_df = pd.DataFrame()
    threshold_best = None
    if threshold_sweep:
        threshold_sweep_df, threshold_best = run_threshold_sweep(
            metric_df,
            threshold_min=threshold_min,
            threshold_max=threshold_max,
            threshold_step=threshold_step,
        )
        if not threshold_sweep_df.empty:
            threshold_sweep_df.to_csv(output_dir / "threshold_sweep.csv", index=False)
        if threshold_best:
            _write_json(output_dir / "threshold_best.json", threshold_best)

    error_summary = write_error_analysis(output_dir, metric_df)
    if save_plot_files:
        warnings.extend(
            save_plots(
                output_dir,
                metric_df,
                metrics_by_mode["is_anomaly"],
                threshold_sweep_df=threshold_sweep_df,
            )
        )

    run_metadata = {
        "generated_at": datetime.now().isoformat(),
        "input_log": str(input_log),
        "label_file": str(label_file or input_log),
        "max_lines": max_lines,
        "config": config.__dict__,
        "label_metadata": label_metadata,
        "parsed_lines": len(parsed_df),
        "template_count": len(templates),
        "raw_window_count": len(results_df),
        "mapped_window_count": len(predictions_df),
        "metric_window_count": len(metric_df),
        "warnings": warnings,
        "promotion_decision": promotion_decision,
    }
    _write_json(output_dir / "run_metadata.json", run_metadata)
    report_path = render_report(
        output_dir=output_dir,
        input_log=input_log,
        label_file=label_file,
        label_metadata=label_metadata,
        config=config,
        parsed_df=parsed_df,
        templates=templates,
        predictions_df=predictions_df,
        metrics_by_mode=metrics_by_mode,
        threshold_best=threshold_best,
        threshold_sweep_df=threshold_sweep_df,
        error_summary=error_summary,
        promotion_decision=promotion_decision,
        warnings=warnings,
        include_skipped=include_skipped,
    )
    return EvaluationResult(
        mode_name=output_dir.name,
        output_dir=output_dir,
        report_path=report_path,
        metrics_by_mode=metrics_by_mode,
        parsed_lines=len(parsed_df),
        evaluated_windows=len(metric_df),
        skipped_windows=len(predictions_df) - len(metric_df),
        warnings=warnings,
    )


def _parse_int_list(value: str) -> list[int]:
    output = []
    for part in str(value).split(","):
        part = part.strip()
        if not part:
            continue
        parsed = int(part)
        if parsed <= 0:
            raise argparse.ArgumentTypeError("topk values must be positive integers")
        output.append(parsed)
    if not output:
        raise argparse.ArgumentTypeError("at least one topk value is required")
    return sorted(dict.fromkeys(output))


def render_comparison_report(output_dir: Path, results: list[EvaluationResult]) -> Path:
    lines = [
        "# Perbandingan Evaluasi DeepLog",
        "",
        "| Run | Parsed Lines | Evaluated Windows | Skipped Windows | Accuracy | Precision | Recall | F1-score | ROC-AUC | Report |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for result in results:
        metrics = result.metrics_by_mode["is_anomaly"]
        relative_report = result.report_path.relative_to(output_dir)
        lines.append(
            f"| {result.mode_name} | {result.parsed_lines} | {result.evaluated_windows} | "
            f"{result.skipped_windows} | {_format_metric(metrics['accuracy'])} | "
            f"{_format_metric(metrics['precision'])} | {_format_metric(metrics['recall'])} | "
            f"{_format_metric(metrics['f1_score'])} | {_format_metric(metrics['roc_auc'])} | "
            f"`{relative_report}` |"
        )
    lines.extend(
        [
            "",
            "Runtime memakai konfigurasi backend aktif. Training baseline memakai window/step/top-k "
            "yang mengikuti baseline LMD sehingga dapat dibandingkan dengan laporan training lama, "
            "tetapi angka resmi BAB IV sebaiknya berasal dari run aktual terbaru.",
            "",
        ]
    )
    path = output_dir / "deeplog_evaluation_comparison.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _default_output_dir() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return DEFAULT_OUTPUT_BASE / timestamp


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-log", type=Path, default=DEFAULT_LMD_INPUT)
    parser.add_argument("--label-file", type=Path, default=None)
    parser.add_argument("--label-column", default=None)
    parser.add_argument("--line-id-column", default=None)
    parser.add_argument("--positive-label", default="auto")
    parser.add_argument(
        "--profile",
        choices=(
            "auto",
            "general",
            "windows_sysmon",
            "windows_evtx",
            "lmd_enriched",
            "linux_log",
        ),
        default="auto",
    )
    parser.add_argument("--max-lines", type=int, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--model-path", type=Path, default=None)
    parser.add_argument("--vocab-path", type=Path, default=None)
    parser.add_argument(
        "--window-label-policy",
        choices=("target_event", "any_in_window", "majority", "ratio_threshold"),
        default="target_event",
    )
    parser.add_argument("--window-label-threshold", type=float, default=0.1)
    parser.add_argument("--include-skipped", action="store_true")
    parser.add_argument("--threshold-sweep", action="store_true")
    parser.add_argument("--threshold-min", type=float, default=0.0)
    parser.add_argument("--threshold-max", type=float, default=1.0)
    parser.add_argument("--threshold-step", type=float, default=0.01)
    parser.add_argument("--save-plots", action="store_true")
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument(
        "--eval-mode",
        choices=(
            "runtime",
            "training_baseline",
            "both",
            "cached_eval",
            "cached_balanced",
            "cached_both",
            "all",
        ),
        default="runtime",
    )
    parser.add_argument("--window-size", type=int, default=None)
    parser.add_argument("--step-size", type=int, default=None)
    parser.add_argument("--topk", type=int, default=None)
    parser.add_argument(
        "--decision-policy",
        choices=("topk", "f1_constrained_recall"),
        default=settings.deeplog_decision_policy,
    )
    parser.add_argument("--score-threshold", type=float, default=None)
    parser.add_argument(
        "--medium-score-threshold",
        type=float,
        default=settings.deeplog_medium_score_threshold,
    )
    parser.add_argument("--target-recall", type=float, default=settings.deeplog_target_recall)
    parser.add_argument("--calibrate-score-threshold", action="store_true")
    parser.add_argument(
        "--min-precision",
        type=float,
        default=settings.deeplog_calibration_min_precision,
    )
    parser.add_argument("--max-fpr", type=float, default=settings.deeplog_calibration_max_fpr)
    parser.add_argument(
        "--max-precision-recall-gap",
        type=float,
        default=settings.deeplog_calibration_max_precision_recall_gap,
    )
    parser.add_argument(
        "--allow-unhealthy-threshold",
        action="store_true",
        help="Allow recall-only threshold selection even when precision/FPR health constraints fail.",
    )
    parser.add_argument(
        "--baseline-topk-values",
        type=_parse_int_list,
        default=list(DEFAULT_BASELINE_TOPK_VALUES),
    )
    parser.add_argument("--cached-records", type=Path, default=None)
    parser.add_argument("--cached-config", type=Path, default=DEFAULT_CACHED_CONFIG)
    parser.add_argument(
        "--cached-topk-values",
        type=_parse_int_list,
        default=list(DEFAULT_CACHED_TOPK_VALUES),
    )
    parser.add_argument("--cached-history-size", type=int, default=None)
    parser.add_argument("--cached-batch-size", type=int, default=None)
    parser.add_argument("--structured-input", action="store_true")
    return parser


def _run_or_template(args: argparse.Namespace) -> int:
    output_dir = (args.output_dir or _default_output_dir()).resolve()
    standard_modes: list[str] = []
    if args.eval_mode in {"runtime", "training_baseline"}:
        standard_modes = [args.eval_mode]
    elif args.eval_mode == "both":
        standard_modes = ["runtime", "training_baseline"]
    elif args.eval_mode == "all":
        standard_modes = ["runtime", "training_baseline"]

    input_log = args.input_log.resolve()
    if standard_modes and not input_log.exists():
        raise FileNotFoundError(f"Input log not found: {input_log}")

    common_kwargs = {
        "input_log": input_log,
        "label_file": args.label_file.resolve() if args.label_file else None,
        "label_column": args.label_column,
        "line_id_column": args.line_id_column,
        "positive_label": args.positive_label,
        "profile": args.profile,
        "max_lines": args.max_lines,
        "model_path": args.model_path.resolve() if args.model_path else None,
        "vocab_path": args.vocab_path.resolve() if args.vocab_path else None,
        "window_label_policy": args.window_label_policy,
        "window_label_threshold": args.window_label_threshold,
        "include_skipped": args.include_skipped,
        "threshold_sweep": args.threshold_sweep,
        "threshold_min": args.threshold_min,
        "threshold_max": args.threshold_max,
        "threshold_step": args.threshold_step,
        "save_plot_files": args.save_plots,
        "random_seed": args.random_seed,
        "structured_input": args.structured_input,
        "decision_policy": args.decision_policy,
        "score_threshold": (
            args.score_threshold
            if args.score_threshold is not None
            else settings.deeplog_score_threshold
        ),
        "medium_score_threshold": args.medium_score_threshold,
        "target_recall": args.target_recall,
    }
    results: list[EvaluationResult] = []

    try:
        for mode in standard_modes:
            if mode == "runtime":
                runtime_dir = output_dir if args.eval_mode == "runtime" else output_dir / "runtime"
                results.append(
                    run_single_evaluation(
                        **common_kwargs,
                        output_dir=runtime_dir,
                        eval_mode="runtime",
                        window_size=args.window_size,
                        step_size=args.step_size,
                        topk=args.topk,
                    )
                )
            else:
                baseline_root = (
                    output_dir
                    if args.eval_mode == "training_baseline"
                    else output_dir / "training_baseline"
                )
                for topk_value in args.baseline_topk_values:
                    results.append(
                        run_single_evaluation(
                            **common_kwargs,
                            output_dir=baseline_root / f"topk_{topk_value}",
                            eval_mode="training_baseline",
                            window_size=args.window_size,
                            step_size=args.step_size,
                            topk=topk_value,
                        )
                    )

        cached_modes: list[str] = []
        if args.eval_mode == "cached_eval":
            cached_modes = ["eval.records.gz"]
        elif args.eval_mode == "cached_balanced":
            cached_modes = ["balanced_eval.records.gz"]
        elif args.eval_mode in {"cached_both", "all"}:
            cached_modes = ["eval.records.gz", "balanced_eval.records.gz"]

        if cached_modes:
            cached_config = args.cached_config.resolve()
            config = load_yaml_config(cached_config)
            run_dir = compose_cached_run_dir(config, config_path=cached_config)
            cached_model_path = (
                args.model_path.resolve()
                if args.model_path
                else run_dir / "models" / "DeepLog.pt"
            )
            cached_vocab_path = (
                args.vocab_path.resolve()
                if args.vocab_path
                else run_dir / "vocabs" / "DeepLog.pkl"
            )
            history_size = int(
                args.cached_history_size
                or config.get("history_size")
                or args.window_size
                or settings.deeplog_window_size
            )
            batch_size = int(args.cached_batch_size or config.get("batch_size") or 128)

            if args.cached_records:
                records_targets = [args.cached_records.resolve()]
            else:
                records_targets = [run_dir / records_name for records_name in cached_modes]

            for records_path in records_targets:
                cache_label = _records_label(records_path)
                if args.eval_mode in {"cached_eval", "cached_balanced"} and not args.cached_records:
                    cache_dir = output_dir
                elif args.eval_mode in {"cached_eval", "cached_balanced"} and args.cached_records:
                    cache_dir = output_dir
                else:
                    cache_dir = output_dir / f"cached_{cache_label}"
                results.extend(
                    run_cached_records_evaluation(
                        records_path=records_path,
                        output_dir=cache_dir,
                        cached_config=cached_config,
                        model_path=cached_model_path,
                        vocab_path=cached_vocab_path,
                        topk_values=args.cached_topk_values,
                        history_size=history_size,
                        batch_size=batch_size,
                        decision_policy=args.decision_policy,
                        target_recall=args.target_recall,
                        score_threshold=(
                            args.score_threshold
                            if args.score_threshold is not None
                            else settings.deeplog_score_threshold
                        ),
                        calibrate_score_threshold_flag=args.calibrate_score_threshold,
                        min_precision=args.min_precision,
                        max_fpr=args.max_fpr,
                        max_precision_recall_gap=args.max_precision_recall_gap,
                        require_healthy_threshold=not args.allow_unhealthy_threshold,
                    )
                )
        if len(results) > 1:
            comparison_path = render_comparison_report(output_dir, results)
            print(f"comparison_report={comparison_path}")
    except GroundTruthMissingError as exc:
        template_path = write_label_template(output_dir)
        message = (
            f"{exc}\nTemplate label dibuat di: {template_path}\n"
            "Metrik formal tidak dihitung karena ground truth belum tersedia."
        )
        (output_dir / "ground_truth_missing.md").write_text(message, encoding="utf-8")
        print(message)
        return 2

    for result in results:
        print(f"report={result.report_path}")
        print(
            "mode={mode} windows={windows} f1={f1}".format(
                mode=result.mode_name,
                windows=result.evaluated_windows,
                f1=_format_metric(result.metrics_by_mode["is_anomaly"]["f1_score"]),
            )
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_arg_parser().parse_args(argv)
    return _run_or_template(args)


if __name__ == "__main__":
    raise SystemExit(main())
