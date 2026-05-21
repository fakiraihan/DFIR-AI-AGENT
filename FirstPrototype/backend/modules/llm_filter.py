"""
LLM-based anomaly gate.

Uses a single coarse LLM pass over the anomaly batch, then applies a fast
local keep/drop policy without evaluating each window individually.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

import pandas as pd
from langchain_community.llms import Ollama


class LLMAnomalyFilter:
    """Fast second-gate for DeepLog anomalies."""

    GATE_MODE = "batch_sanity"
    MAX_BATCH_SUMMARY_SAMPLES = 20
    LOW_CONFIDENCE_THRESHOLD = 0.4
    ALLOWED_POLICIES = {
        "keep_all",
        "keep_high_confidence_only",
        "prioritize_critical",
        "request_more_context",
        "skip_low_signal_with_note",
    }

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        ollama_model: str = "sec-foundation:8b-gpu",
        llm: Optional[Any] = None,
        provider_name: str = "ollama",
    ):
        self.provider_name = provider_name
        self.model_name = ollama_model
        self.llm = llm or Ollama(
            base_url=ollama_base_url,
            model=ollama_model,
            temperature=0.2,
            top_p=0.9,
            top_k=40,
        )

    def filter_anomalies(
        self, anomalies_df: pd.DataFrame, parsed_logs_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Apply one batch-level LLM sanity gate to anomaly candidates."""
        del parsed_logs_df  # retained for compatibility with current call sites

        print("\n" + "=" * 60)
        print("LLM ANOMALY GATE (Batch Sanity Check)")
        print("=" * 60)

        if len(anomalies_df) == 0:
            print("No anomalies to gate")
            return anomalies_df

        print(f"\nDeepLog detected: {len(anomalies_df)} anomalies")
        print("Running one coarse LLM sanity gate for the batch...\n")

        summaries = self._build_batch_summaries(anomalies_df)
        decision = self._evaluate_batch(anomalies_df, summaries)
        if (
            str(decision.get("policy")) != "keep_all"
            and float(decision.get("confidence") or 0.0) < self.LOW_CONFIDENCE_THRESHOLD
        ):
            decision["reason"] = (
                f"Low-confidence gate decision ({decision.get('confidence')}); "
                "fallback to keep_all"
            )
            decision["policy"] = "keep_all"
            decision["priority_window_ids"] = []
        policy = str(decision["policy"])
        filtered_df = self._apply_gate_policy(
            anomalies_df, policy, decision["priority_window_ids"]
        )

        if filtered_df.empty:
            print("[WARN] Batch gate removed all anomalies, fail-open to original set")
            filtered_df = anomalies_df.copy()
            policy = "keep_all"
            decision["policy"] = policy
            decision["reason"] = (
                "Batch gate would drop all anomalies, fallback to original set"
            )

        filtered_df = self._annotate_gate_decision(filtered_df, decision)

        print(f"\n{'=' * 60}")
        print("LLM Batch Gate Results:")
        print(f"  Input: {len(anomalies_df)} anomalies")
        print(f"  Policy: {policy}")
        print(f"  Output: {len(filtered_df)} anomalies")
        print(f"  Reason: {str(decision['reason'])[:160]}")
        print(f"{'=' * 60}\n")

        return filtered_df

    def _build_batch_summaries(
        self, anomalies_df: pd.DataFrame
    ) -> List[Dict[str, Any]]:
        ranked_df = anomalies_df.copy()
        if "anomaly_score" in ranked_df.columns:
            ranked_df = ranked_df.sort_values(by="anomaly_score", ascending=False)

        summaries: List[Dict[str, Any]] = []
        for _, anomaly in ranked_df.head(self.MAX_BATCH_SUMMARY_SAMPLES).iterrows():
            summaries.append(
                {
                    "window_id": int(anomaly.get("window_id", 0) or 0),
                    "actual_event": str(anomaly.get("actual_event", "")),
                    "predicted_event": str(anomaly.get("predicted_event", "")),
                    "anomaly_score": round(
                        float(anomaly.get("anomaly_score", 0.0) or 0.0), 4
                    ),
                    "strict_is_anomaly": bool(anomaly.get("strict_is_anomaly", False)),
                    "unknown_ratio": round(
                        float(anomaly.get("unknown_ratio", 0.0) or 0.0), 4
                    ),
                    "key_indicators": self._summarize_indicators(
                        anomaly.get("window_key_indicators") or {}
                    ),
                }
            )
        return summaries

    def _evaluate_batch(
        self, anomalies_df: pd.DataFrame, summaries: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        prompt = self._build_batch_prompt(anomalies_df, summaries)

        try:
            response = self.llm.invoke(prompt)
            return self._parse_batch_decision(response)
        except Exception as first_exc:
            try:
                retry_response = self.llm.invoke(self._build_retry_prompt(anomalies_df))
                decision = self._parse_batch_decision(retry_response)
                decision["reason"] = (
                    f"Retry gate decision after parse failure: {decision['reason']}"
                )
                return decision
            except Exception as exc:
                return {
                    "policy": "keep_all",
                    "reason": f"Batch gate fallback: {first_exc}; retry failed: {exc}",
                    "priority_window_ids": [],
                    "requested_context": "",
                    "confidence": 0.0,
                    "confidence_provided": False,
                }

    def _parse_batch_decision(self, response: str) -> Dict[str, Any]:
        if "```json" in response:
            response = response.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in response:
            response = response.split("```", 1)[1].split("```", 1)[0].strip()
        else:
            response = self._extract_json_object(response)

        result = json.loads(response)
        policy = self._normalize_policy(result.get("recommended_action"))
        priority_window_ids = self._normalize_window_ids(
            result.get("priority_window_ids")
            or result.get("prioritized_window_ids")
            or []
        )

        reason = str(result.get("reason", "Batch sanity gate completed"))
        return {
            "policy": policy,
            "reason": reason,
            "priority_window_ids": priority_window_ids,
            "requested_context": self._normalize_requested_context(
                result.get("requested_context")
                or result.get("additional_context_needed")
                or ""
            ),
            "confidence": self._normalize_confidence(result.get("confidence")),
            "confidence_provided": "confidence" in result,
        }

    def _build_retry_prompt(self, anomalies_df: pd.DataFrame) -> str:
        return f"""Return JSON only for this DFIR anomaly batch.

total_anomalies: {len(anomalies_df)}

Allowed recommended_action values:
- keep_all
- keep_high_confidence_only
- prioritize_critical
- request_more_context
- skip_low_signal_with_note

Return exactly:
{{"recommended_action":"keep_all","priority_window_ids":[],"confidence":0.5,"reason":"brief reason"}}"""

    def _score_distribution(self, anomalies_df: pd.DataFrame) -> str:
        if "anomaly_score" not in anomalies_df.columns or anomalies_df.empty:
            return "unavailable"

        scores = anomalies_df["anomaly_score"].fillna(0).astype(float)
        high = int((scores >= 0.85).sum())
        medium = int(((scores >= 0.5) & (scores < 0.85)).sum())
        low = int((scores < 0.5).sum())
        max_score = float(scores.max()) if not scores.empty else 0.0
        return (
            f"high>=0.85:{high}, medium=0.50-0.84:{medium}, "
            f"low<0.50:{low}, max_score:{max_score:.4f}"
        )

    def _build_batch_prompt(
        self, anomalies_df: pd.DataFrame, summaries: List[Dict[str, Any]]
    ) -> str:
        strict_count = int(
            anomalies_df.get("strict_is_anomaly", pd.Series(dtype=bool)).sum()
        )
        avg_score = 0.0
        if "anomaly_score" in anomalies_df.columns and not anomalies_df.empty:
            avg_score = float(anomalies_df["anomaly_score"].fillna(0).mean())

        summary_lines = []
        for item in summaries:
            summary_lines.append(
                "- window={window_id} score={anomaly_score} strict={strict_is_anomaly} "
                "unknown_ratio={unknown_ratio} actual={actual_event} predicted={predicted_event} indicators={key_indicators}".format(
                    **item
                )
            )

        joined = "\n".join(summary_lines) if summary_lines else "- no sample anomalies"

        return f"""You are a cybersecurity reviewer for a DFIR anomaly triage pipeline.

DeepLog has already detected anomaly windows. Your task is NOT to review each window in depth.
Your task is only to decide the fastest safe batch policy for this anomaly set.

        Batch summary:
        - total_anomalies: {len(anomalies_df)}
        - strict_anomalies: {strict_count}
        - average_anomaly_score: {avg_score:.4f}
        - score_distribution: {self._score_distribution(anomalies_df)}

Top anomaly samples:
{joined}

Choose one policy only:
- keep_all = retain all anomaly windows for investigation
- keep_high_confidence_only = keep only strongest anomalies locally
- prioritize_critical = keep the most critical window IDs you list in priority_window_ids
- request_more_context = keep all windows but ask downstream agent/report to note missing context
- skip_low_signal_with_note = drop low-signal windows locally, while recording why they were low signal

Return JSON only:
{{
  "recommended_action": "keep_all" | "keep_high_confidence_only" | "prioritize_critical" | "request_more_context" | "skip_low_signal_with_note",
  "priority_window_ids": [1, 2],
  "requested_context": "Brief missing-context note, or empty string",
  "confidence": 0.0,
  "reason": "Brief explanation, prefer English, max 40 words"
}}"""

    def _apply_gate_policy(
        self, anomalies_df: pd.DataFrame, policy: str, priority_window_ids: List[int]
    ) -> pd.DataFrame:
        if policy == "keep_high_confidence_only":
            mask = anomalies_df.apply(self._is_high_confidence, axis=1)
            filtered = anomalies_df[mask].copy()
            if not filtered.empty:
                return filtered
        if policy == "prioritize_critical":
            priority_ids = set(priority_window_ids)
            if priority_ids and "window_id" in anomalies_df.columns:
                filtered = anomalies_df[
                    anomalies_df["window_id"].apply(
                        lambda value: self._safe_int(value) in priority_ids
                    )
                ].copy()
                if not filtered.empty:
                    return filtered
            mask = anomalies_df.apply(self._is_high_confidence, axis=1)
            filtered = anomalies_df[mask].copy()
            if not filtered.empty:
                return filtered
        if policy == "skip_low_signal_with_note":
            mask = anomalies_df.apply(self._is_high_confidence, axis=1)
            filtered = anomalies_df[mask].copy()
            if not filtered.empty:
                return filtered
        if policy == "request_more_context":
            return anomalies_df.copy()
        return anomalies_df.copy()

    def _annotate_gate_decision(
        self, filtered_df: pd.DataFrame, decision: Dict[str, Any]
    ) -> pd.DataFrame:
        annotated_df = filtered_df.copy()
        policy = str(decision["policy"])
        priority_window_ids = decision["priority_window_ids"]
        priority_set = set(priority_window_ids)

        annotated_df["llm_filtered"] = True
        annotated_df["llm_reason"] = str(decision["reason"])
        annotated_df["llm_gate_mode"] = self.GATE_MODE
        annotated_df["llm_gate_policy"] = policy
        annotated_df["llm_gate_requested_context"] = str(
            decision.get("requested_context") or ""
        )
        annotated_df["llm_gate_confidence"] = float(decision.get("confidence") or 0.0)
        annotated_df["llm_gate_prioritized_window_ids"] = json.dumps(
            priority_window_ids
        )
        annotated_df["llm_gate_active"] = True
        annotated_df["llm_gate_priority"] = annotated_df.apply(
            lambda row: self._gate_priority_label(row, policy, priority_set), axis=1
        )
        annotated_df["llm_gate_priority_rank"] = annotated_df.apply(
            lambda row: self._gate_priority_rank(row, policy, priority_set), axis=1
        )
        return annotated_df

    def _normalize_policy(self, value: Any) -> str:
        policy = str(value or "keep_all").strip()
        if policy not in self.ALLOWED_POLICIES:
            return "keep_all"
        return policy

    def _normalize_window_ids(self, value: Any) -> List[int]:
        if not isinstance(value, list):
            return []
        window_ids = []
        seen = set()
        for item in value:
            window_id = self._safe_int(item)
            if window_id <= 0 or window_id in seen:
                continue
            window_ids.append(window_id)
            seen.add(window_id)
        return window_ids

    def _normalize_requested_context(self, value: Any) -> str:
        if isinstance(value, list):
            return "; ".join(str(item).strip() for item in value if str(item).strip())
        return str(value or "").strip()

    def _normalize_confidence(self, value: Any) -> float:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.0
        return min(max(confidence, 0.0), 1.0)

    def _safe_int(self, value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _gate_priority_label(
        self, anomaly: pd.Series, policy: str, priority_window_ids: set[int]
    ) -> str:
        window_id = int(anomaly.get("window_id", 0) or 0)
        if window_id in priority_window_ids:
            return "critical_priority"
        if policy == "request_more_context":
            return "needs_more_context"
        if self._is_high_confidence(anomaly):
            return "high_confidence"
        if policy == "skip_low_signal_with_note":
            return "low_signal_retained"
        return "standard"

    def _gate_priority_rank(
        self, anomaly: pd.Series, policy: str, priority_window_ids: set[int]
    ) -> int:
        label = self._gate_priority_label(anomaly, policy, priority_window_ids)
        return {
            "critical_priority": 1,
            "high_confidence": 2,
            "needs_more_context": 3,
            "standard": 4,
            "low_signal_retained": 5,
        }.get(label, 9)

    def _is_high_confidence(self, anomaly: pd.Series) -> bool:
        score = float(anomaly.get("anomaly_score", 0.0) or 0.0)
        strict = bool(anomaly.get("strict_is_anomaly", False))
        unknown_ratio = float(anomaly.get("unknown_ratio", 0.0) or 0.0)
        has_indicators = self._has_meaningful_indicators(
            anomaly.get("window_key_indicators") or {}
        )

        if score >= 0.85:
            return True
        if strict and unknown_ratio <= 0.25 and score >= 0.5:
            return True
        if has_indicators and score >= 0.35 and unknown_ratio <= 0.4:
            return True
        return False

    def _has_meaningful_indicators(self, indicators: Dict[str, Any]) -> bool:
        if not isinstance(indicators, dict):
            return False
        for values in indicators.values():
            if isinstance(values, list) and any(str(v).strip() for v in values):
                return True
            if isinstance(values, str) and values.strip():
                return True
        return False

    def _summarize_indicators(self, indicators: Dict[str, Any]) -> str:
        if not isinstance(indicators, dict) or not indicators:
            return "none"

        parts: List[str] = []
        for key, values in indicators.items():
            if isinstance(values, list):
                clean_values = [str(v) for v in values if str(v).strip()]
                if clean_values:
                    parts.append(f"{key}={','.join(clean_values[:2])}")
            elif str(values).strip():
                parts.append(f"{key}={values}")
            if len(parts) >= 4:
                break

        return "; ".join(parts) if parts else "none"

    def _extract_json_object(self, response: str) -> str:
        match = re.search(r"\{.*\}", response, flags=re.DOTALL)
        if match:
            return match.group(0).strip()
        return response.strip()


if __name__ == "__main__":
    anomaly_filter = LLMAnomalyFilter()
    print("LLM Anomaly Filter initialized successfully")
    print(f"Model: {anomaly_filter.llm.model}")
