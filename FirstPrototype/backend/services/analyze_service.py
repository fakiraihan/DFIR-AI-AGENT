"""Quick analysis service for parsing and DeepLog-only triage."""

from typing import Any

from fastapi import HTTPException, UploadFile

from app_context import DATA_DIR, settings
from services.parsing_service import parse_with_profile
from services.storage_service import (
    generate_session_id,
    save_upload_file,
    sanitize_uploaded_filename,
    validate_upload_extension,
)


ANOMALY_STATUS_KEYS = (
    "unknown_template",
    "unknown_template_ratio_exceeded",
    "evtx_sparse_fallback",
    "deeplog_topk_miss",
)
SKIPPED_EVALUATION_STATUSES = {
    "unknown_template",
    "unknown_template_ratio_exceeded",
}


def _validate_positive_int(value: int, field_name: str) -> None:
    if value <= 0:
        raise HTTPException(status_code=400, detail=f"{field_name} must be > 0")


def _count_evaluation_statuses(all_results_df: Any) -> dict[str, int]:
    status_counts = {status: 0 for status in ANOMALY_STATUS_KEYS}
    if all_results_df.empty or "evaluation_status" not in all_results_df.columns:
        return status_counts

    counts = all_results_df["evaluation_status"].value_counts().to_dict()
    return {status: int(counts.get(status, 0)) for status in ANOMALY_STATUS_KEYS}


def _summarize_anomaly_results(all_results_df: Any) -> tuple[int, int, float, dict[str, int]]:
    skipped_windows = 0
    strict_anomaly_count = 0
    avg_unknown_ratio = 0.0
    evaluation_status_counts = _count_evaluation_statuses(all_results_df)

    if all_results_df.empty:
        return skipped_windows, strict_anomaly_count, avg_unknown_ratio, evaluation_status_counts

    if "evaluation_status" in all_results_df.columns:
        skipped_windows = int(
            all_results_df["evaluation_status"].isin(SKIPPED_EVALUATION_STATUSES).sum()
        )

    if "strict_is_anomaly" in all_results_df.columns:
        strict_anomaly_count = int(all_results_df["strict_is_anomaly"].sum())

    if "unknown_ratio" in all_results_df.columns:
        avg_unknown_ratio = float(all_results_df["unknown_ratio"].mean())

    return skipped_windows, strict_anomaly_count, avg_unknown_ratio, evaluation_status_counts


async def run_quick_analysis(
    file: UploadFile,
    *,
    max_lines: int,
    sample_step: int,
    anomaly_limit: int,
) -> dict[str, Any]:
    """Run upload, parsing, optional sampling, and DeepLog anomaly detection."""
    from modules.anomaly import detect_anomalies_in_logs

    safe_file_name = sanitize_uploaded_filename(file.filename)
    validate_upload_extension(safe_file_name)

    _validate_positive_int(max_lines, "max_lines")
    _validate_positive_int(sample_step, "sample_step")
    _validate_positive_int(anomaly_limit, "anomaly_limit")

    session_id = generate_session_id("analyze")
    session_dir = DATA_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=False)

    file_path = session_dir / safe_file_name
    await save_upload_file(file, file_path)

    parsed_df, templates, selected_profile = parse_with_profile(
        str(file_path),
        settings,
        max_lines=max_lines,
    )

    effective_sample_step = sample_step
    sampling_applied = False
    if sample_step > 1 and not parsed_df.empty:
        sampled_df = parsed_df.iloc[::sample_step].reset_index(drop=True)
        if len(sampled_df) > selected_profile["window_size"]:
            parsed_df = sampled_df
            parsed_df["line_number"] = range(1, len(parsed_df) + 1)
            parsed_df["event_id"] = range(1, len(parsed_df) + 1)
            sampling_applied = True
        else:
            effective_sample_step = 1

    model_path = selected_profile["model_path"]
    vocab_path = selected_profile["vocab_path"]

    if not model_path.exists() or not vocab_path.exists():
        raise HTTPException(
            status_code=500,
            detail=f"DeepLog artifacts not found. model={model_path} vocab={vocab_path}",
        )

    all_results_df, anomalies_df = detect_anomalies_in_logs(
        parsed_df,
        str(model_path),
        str(vocab_path),
        window_size=selected_profile["window_size"],
        step_size=settings.deeplog_step_size,
        topk=settings.deeplog_topk,
        skip_unknown_windows=settings.deeplog_skip_unknown_windows,
        max_unknown_ratio=settings.deeplog_max_unknown_ratio,
        unknown_template_mode=settings.deeplog_unknown_template_mode,
        evtx_sparse_fallback_enabled=settings.deeplog_evtx_sparse_fallback_enabled,
        evtx_sparse_fallback_threshold=settings.deeplog_evtx_sparse_fallback_threshold,
    )

    (
        skipped_windows,
        strict_anomaly_count,
        avg_unknown_ratio,
        evaluation_status_counts,
    ) = _summarize_anomaly_results(all_results_df)

    anomaly_records = anomalies_df.to_dict("records")
    truncated = len(anomaly_records) > anomaly_limit
    if truncated:
        anomaly_records = anomaly_records[:anomaly_limit]

    return {
        "session_id": session_id,
        "file_name": safe_file_name,
        "debug": {
            "max_lines": max_lines,
            "sample_step": sample_step,
            "effective_sample_step": effective_sample_step,
            "sampling_applied": sampling_applied,
            "anomaly_limit": anomaly_limit,
            "skip_unknown_windows": settings.deeplog_skip_unknown_windows,
            "max_unknown_ratio": settings.deeplog_max_unknown_ratio,
            "model_profile": selected_profile["name"],
            "window_size": selected_profile["window_size"],
            "parser_template_strategy": selected_profile["template_strategy"],
            "result_truncated": truncated,
        },
        "summary": {
            "parsed_lines": len(parsed_df),
            "template_count": len(templates),
            "window_count": len(all_results_df),
            "anomaly_count": len(anomalies_df),
            "strict_anomaly_count": strict_anomaly_count,
            "skipped_windows": skipped_windows,
            "avg_unknown_ratio": round(avg_unknown_ratio, 4),
            "evaluation_status_counts": evaluation_status_counts,
        },
        "anomaly_results": anomaly_records,
    }
