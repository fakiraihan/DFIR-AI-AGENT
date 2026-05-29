"""Promotion gate for deciding whether a DeepLog retrain is runtime-worthy."""

from __future__ import annotations

from typing import Any


DEFAULT_BASELINE_F1 = 0.5347
DEFAULT_TARGET_RECALL = 0.80
DEFAULT_MIN_PRECISION = 0.65
DEFAULT_MAX_FPR = 0.50
DEFAULT_MAX_PRECISION_RECALL_GAP = 0.30


def _metric(metrics: dict[str, Any], key: str) -> float:
    value = metrics.get(key)
    if value in (None, "N/A", ""):
        return 0.0
    return float(value)


def evaluate_promotion_gate(
    metrics: dict[str, Any],
    *,
    baseline_f1: float = DEFAULT_BASELINE_F1,
    target_recall: float = DEFAULT_TARGET_RECALL,
    min_precision: float = DEFAULT_MIN_PRECISION,
    max_fpr: float = DEFAULT_MAX_FPR,
    max_precision_recall_gap: float = DEFAULT_MAX_PRECISION_RECALL_GAP,
) -> dict[str, Any]:
    precision = _metric(metrics, "precision")
    recall = _metric(metrics, "recall")
    f1_score = _metric(metrics, "f1_score")
    fpr = _metric(metrics, "false_positive_rate")
    precision_recall_gap = abs(precision - recall)

    checks = {
        "recall": recall >= target_recall,
        "f1_score": f1_score > baseline_f1,
        "precision": precision >= min_precision,
        "false_positive_rate": fpr <= max_fpr,
        "precision_recall_gap": precision_recall_gap <= max_precision_recall_gap,
    }
    failed = [name for name, passed in checks.items() if not passed]
    return {
        "passed": not failed,
        "failed_criteria": failed,
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "false_positive_rate": fpr,
            "precision_recall_gap": precision_recall_gap,
        },
        "criteria": {
            "recall_min": target_recall,
            "f1_score_gt": baseline_f1,
            "precision_min": min_precision,
            "false_positive_rate_max": max_fpr,
            "precision_recall_gap_max": max_precision_recall_gap,
        },
    }
