"""
LLM-based anomaly gate.

Uses a single coarse LLM pass over the anomaly batch, then applies a fast
local keep/drop policy without evaluating each window individually.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from langchain_community.llms import Ollama


class LLMAnomalyFilter:
    """Fast second-gate for DeepLog anomalies."""

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
        policy, reason = self._evaluate_batch(anomalies_df, summaries)
        filtered_df = self._apply_gate_policy(anomalies_df, policy)

        if filtered_df.empty:
            print("⚠ Batch gate removed all anomalies, fail-open to original set")
            filtered_df = anomalies_df.copy()
            policy = "keep_all"
            reason = "Batch gate would drop all anomalies, fallback to original set"

        filtered_df = filtered_df.copy()
        filtered_df["llm_filtered"] = True
        filtered_df["llm_reason"] = reason
        filtered_df["llm_gate_mode"] = "batch_sanity"
        filtered_df["llm_gate_policy"] = policy

        print(f"\n{'=' * 60}")
        print("LLM Batch Gate Results:")
        print(f"  Input: {len(anomalies_df)} anomalies")
        print(f"  Policy: {policy}")
        print(f"  Output: {len(filtered_df)} anomalies")
        print(f"  Reason: {reason[:160]}")
        print(f"{'=' * 60}\n")

        return filtered_df

    def _build_batch_summaries(
        self, anomalies_df: pd.DataFrame
    ) -> List[Dict[str, Any]]:
        ranked_df = anomalies_df.copy()
        if "anomaly_score" in ranked_df.columns:
            ranked_df = ranked_df.sort_values(by="anomaly_score", ascending=False)

        summaries: List[Dict[str, Any]] = []
        for _, anomaly in ranked_df.head(12).iterrows():
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
    ) -> Tuple[str, str]:
        prompt = self._build_batch_prompt(anomalies_df, summaries)

        try:
            response = self.llm.invoke(prompt)

            if "```json" in response:
                response = response.split("```json", 1)[1].split("```", 1)[0].strip()
            elif "```" in response:
                response = response.split("```", 1)[1].split("```", 1)[0].strip()
            else:
                response = self._extract_json_object(response)

            result = json.loads(response)
            policy = str(result.get("recommended_action", "keep_all")).strip()
            if policy not in {"keep_all", "keep_high_confidence_only"}:
                policy = "keep_all"

            reason = str(result.get("reason", "Batch sanity gate completed"))
            return policy, reason

        except Exception as exc:
            return "keep_all", f"Batch gate fallback: {exc}"

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

Top anomaly samples:
{joined}

Choose one policy only:
- keep_all = the anomaly batch looks valid enough, do not spend more time filtering
- keep_high_confidence_only = keep only the strongest anomalies locally

Return JSON only:
{{
  "recommended_action": "keep_all" | "keep_high_confidence_only",
  "reason": "Brief Indonesian explanation, max 40 words"
}}"""

    def _apply_gate_policy(
        self, anomalies_df: pd.DataFrame, policy: str
    ) -> pd.DataFrame:
        if policy == "keep_high_confidence_only":
            mask = anomalies_df.apply(self._is_high_confidence, axis=1)
            filtered = anomalies_df[mask].copy()
            if not filtered.empty:
                return filtered
        return anomalies_df.copy()

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
