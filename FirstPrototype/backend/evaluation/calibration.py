"""Threshold calibration utilities for formal DeepLog evaluation."""

from __future__ import annotations

import math
from typing import Any, Sequence

import numpy as np
import pandas as pd


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "anomaly", "anomalous"}


def _manual_confusion(y_true: np.ndarray, y_pred: np.ndarray) -> tuple[int, int, int, int]:
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    return tn, fp, fn, tp


def _safe_rate(numerator: int | float, denominator: int | float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _metrics_from_counts(
    *,
    sample_count: int,
    tn: int,
    fp: int,
    fn: int,
    tp: int,
) -> dict[str, Any]:
    accuracy = _safe_rate(tp + tn, sample_count)
    precision = _safe_rate(tp, tp + fp)
    recall = _safe_rate(tp, tp + fn)
    f1 = _safe_rate(2 * precision * recall, precision + recall)
    specificity = _safe_rate(tn, tn + fp)
    fpr = _safe_rate(fp, fp + tn)
    fnr = _safe_rate(fn, fn + tp)
    return {
        "sample_count": int(sample_count),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "balanced_accuracy": (recall + specificity) / 2,
        "specificity_tnr": specificity,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def _row_from_metrics(threshold: float, metrics: dict[str, Any]) -> dict[str, Any]:
    cm = metrics["confusion_matrix"]
    return {
        "threshold": threshold,
        "sample_count": metrics["sample_count"],
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1_score": metrics["f1_score"],
        "balanced_accuracy": metrics["balanced_accuracy"],
        "specificity_tnr": metrics["specificity_tnr"],
        "false_positive_rate": metrics["false_positive_rate"],
        "false_negative_rate": metrics["false_negative_rate"],
        "tn": cm["tn"],
        "fp": cm["fp"],
        "fn": cm["fn"],
        "tp": cm["tp"],
    }


def _passes_health(
    row: dict[str, Any],
    *,
    min_precision: float,
    max_fpr: float,
    max_precision_recall_gap: float,
) -> bool:
    return (
        float(row["precision"]) >= min_precision
        and float(row["false_positive_rate"]) <= max_fpr
        and abs(float(row["precision"]) - float(row["recall"])) <= max_precision_recall_gap
    )


def calibrate_score_threshold(
    *,
    y_true: Sequence[int],
    y_score: Sequence[float],
    base_pred: Sequence[int | bool] | None = None,
    target_recall: float = 0.80,
    min_precision: float = 0.0,
    max_fpr: float = 1.0,
    max_precision_recall_gap: float = 1.0,
    require_healthy_threshold: bool = False,
) -> dict[str, Any]:
    y_true_arr = np.asarray(y_true, dtype=int)
    score_series = pd.to_numeric(pd.Series(list(y_score)), errors="coerce")
    if score_series.isna().all():
        raise ValueError("Tidak ada anomaly_score valid untuk kalibrasi threshold.")

    scores = score_series.fillna(float("-inf")).astype(float).to_numpy()
    if base_pred is None:
        base_pred_arr = np.zeros(len(y_true_arr), dtype=int)
    else:
        base_pred_arr = np.asarray([int(_as_bool(value)) for value in base_pred], dtype=int)
    if len(y_true_arr) != len(scores) or len(y_true_arr) != len(base_pred_arr):
        raise ValueError("Panjang y_true, y_score, dan base_pred harus sama.")

    rows: list[dict[str, Any]] = []
    thresholds = sorted(
        {float(score) for score in scores if math.isfinite(float(score))},
        reverse=True,
    )
    for threshold in thresholds:
        threshold_pred = ((scores >= threshold) | (base_pred_arr == 1)).astype(int)
        tn, fp, fn, tp = _manual_confusion(y_true_arr, threshold_pred)
        metrics = _metrics_from_counts(
            sample_count=len(y_true_arr),
            tn=tn,
            fp=fp,
            fn=fn,
            tp=tp,
        )
        row = _row_from_metrics(threshold, metrics)
        row["precision_recall_gap"] = abs(float(row["precision"]) - float(row["recall"]))
        row["passes_health"] = _passes_health(
            row,
            min_precision=min_precision,
            max_fpr=max_fpr,
            max_precision_recall_gap=max_precision_recall_gap,
        )
        rows.append(row)

    recall_eligible = [row for row in rows if float(row["recall"]) >= float(target_recall)]
    if not recall_eligible:
        raise ValueError(
            f"Tidak ada score threshold yang memenuhi target recall >= {target_recall}."
        )

    healthy_eligible = [row for row in recall_eligible if bool(row["passes_health"])]
    if require_healthy_threshold and not healthy_eligible:
        best_recall_only = sorted(
            recall_eligible,
            key=lambda row: (
                float(row["f1_score"]),
                float(row["precision"]),
                -int(row["fp"]),
                float(row["threshold"]),
            ),
            reverse=True,
        )[0]
        raise ValueError(
            "Tidak ada threshold sehat yang memenuhi target recall. "
            f"Best recall-only: threshold={best_recall_only['threshold']} "
            f"precision={best_recall_only['precision']:.4f} "
            f"recall={best_recall_only['recall']:.4f} "
            f"f1={best_recall_only['f1_score']:.4f} "
            f"fpr={best_recall_only['false_positive_rate']:.4f}."
        )

    candidate_rows = healthy_eligible or recall_eligible
    best = sorted(
        candidate_rows,
        key=lambda row: (
            float(row["f1_score"]),
            float(row["precision"]),
            -int(row["fp"]),
            float(row["threshold"]),
        ),
        reverse=True,
    )[0]
    recommended_threshold = float(best["threshold"])
    recommended_pred = ((scores >= recommended_threshold) | (base_pred_arr == 1)).astype(int)
    tn, fp, fn, tp = _manual_confusion(y_true_arr, recommended_pred)
    recommended_metrics = _metrics_from_counts(
        sample_count=len(y_true_arr),
        tn=tn,
        fp=fp,
        fn=fn,
        tp=tp,
    )
    return {
        "target_recall": float(target_recall),
        "min_precision": float(min_precision),
        "max_fpr": float(max_fpr),
        "max_precision_recall_gap": float(max_precision_recall_gap),
        "require_healthy_threshold": bool(require_healthy_threshold),
        "healthy_threshold_found": bool(healthy_eligible),
        "recommended_threshold": recommended_threshold,
        "recommended_metrics": recommended_metrics,
        "pareto_rows": rows,
    }
