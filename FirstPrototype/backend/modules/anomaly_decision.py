"""Decision policy helpers for DeepLog window outputs."""

from __future__ import annotations

from typing import List, Tuple


def resolve_decision_policy(decision_policy: str | None) -> str:
    policy = str(decision_policy or "topk").strip().lower()
    if policy in {"strict", "topk_miss", "deeplog_topk"}:
        return "topk"
    if policy not in {"topk", "f1_constrained_recall"}:
        raise ValueError("decision_policy must be one of: topk, f1_constrained_recall")
    return policy


def apply_decision_policy(
    *,
    decision_policy: str,
    is_anomaly: bool,
    strict_is_anomaly: bool,
    anomaly_score: float,
    evaluation_status: str,
    score_threshold: float | None,
) -> tuple[bool, str]:
    if decision_policy != "f1_constrained_recall":
        return bool(is_anomaly), evaluation_status
    if is_anomaly or strict_is_anomaly:
        return bool(is_anomaly), evaluation_status
    if evaluation_status != "evaluated" or score_threshold is None:
        return bool(is_anomaly), evaluation_status
    if float(anomaly_score) >= float(score_threshold):
        return True, "score_threshold_exceeded"
    return bool(is_anomaly), evaluation_status


def candidate_metadata(
    *,
    is_anomaly: bool,
    strict_is_anomaly: bool,
    anomaly_score: float,
    evaluation_status: str,
    medium_score_threshold: float = 0.70,
    fallback_reasons: List[str] | None = None,
    unknown_reason: str = "",
) -> Tuple[str, List[str]]:
    if not is_anomaly:
        return "none", []

    reasons: List[str] = []
    if strict_is_anomaly:
        reasons.append("topk_miss")
    if evaluation_status == "score_threshold_exceeded":
        reasons.append("score_threshold")
    if unknown_reason and evaluation_status == unknown_reason:
        reasons.append(unknown_reason)
    if evaluation_status in {"evtx_heuristic_boost", "evtx_sparse_fallback"}:
        reasons.append(evaluation_status)
    for reason in fallback_reasons or []:
        reason_text = str(reason)
        if reason_text and reason_text not in reasons:
            reasons.append(reason_text)

    if strict_is_anomaly or evaluation_status in {
        "deeplog_topk_miss",
        "unknown_template",
        "unknown_template_ratio_exceeded",
        "evtx_heuristic_boost",
        "evtx_sparse_fallback",
    }:
        tier = "high"
    elif float(anomaly_score) >= float(medium_score_threshold):
        tier = "medium"
    else:
        tier = "low"

    return tier, reasons
