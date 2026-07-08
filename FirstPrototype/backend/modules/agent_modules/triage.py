"""Semantic anomaly triage node for the DFIR agent graph.

Single LLM call that reads actual log content from anomaly windows
and labels each as suspicious / uncertain / noise.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

import pandas as pd


MAX_TRIAGE_WINDOWS = 20
MAX_LOG_LINES_PER_WINDOW = 10


def triage_anomalies(state: Dict[str, Any], llm: Any) -> Dict[str, Any]:
    """Label anomaly windows semantically using actual log content.

    Reads real log lines from each window, sends a single LLM call, and
    drops windows labeled as noise. Suspicious and uncertain windows pass
    through to the extractor node.
    """
    anomalies: List[Dict[str, Any]] = state.get("anomalies") or []
    parsed_logs: pd.DataFrame = state.get("parsed_logs", pd.DataFrame())

    if not anomalies:
        return {"anomalies": [], "triage_labels": {}}

    print(f"\n=== ANOMALY TRIAGE: {len(anomalies)} windows ===")

    scored = sorted(
        anomalies,
        key=lambda a: float(a.get("anomaly_score") or 0.0),
        reverse=True,
    )
    candidates = scored[:MAX_TRIAGE_WINDOWS]
    remainder = scored[MAX_TRIAGE_WINDOWS:]

    enriched = _enrich_with_log_content(candidates, parsed_logs)
    prompt = _build_triage_prompt(enriched)

    try:
        response = llm.invoke(prompt)
        labels = _parse_triage_response(response)
    except Exception as exc:
        print(f"[WARN] Triage LLM call failed: {exc} — keeping all anomalies")
        labels = {
            str(a.get("window_id", i)): "uncertain"
            for i, a in enumerate(candidates)
        }

    triaged = [
        a for a in candidates
        if labels.get(str(a.get("window_id")), "uncertain") != "noise"
    ]
    all_filtered = triaged + remainder

    dropped = len(anomalies) - len(all_filtered)
    print(f"Triage: {len(anomalies)} → {len(all_filtered)} kept, {dropped} dropped as noise")

    return {"anomalies": all_filtered, "triage_labels": labels}


def _enrich_with_log_content(
    anomalies: List[Dict[str, Any]], parsed_logs: pd.DataFrame
) -> List[Dict[str, Any]]:
    enriched = []
    for anomaly in anomalies:
        start = int(anomaly.get("start_idx") or 0)
        end = int(anomaly.get("end_idx") or start)
        enriched.append(
            {
                "window_id": anomaly.get("window_id"),
                "anomaly_score": round(float(anomaly.get("anomaly_score") or 0.0), 4),
                "actual_event": str(anomaly.get("actual_event") or ""),
                "predicted_event": str(anomaly.get("predicted_event") or ""),
                "log_lines": _get_log_lines(parsed_logs, start, end),
            }
        )
    return enriched


def _get_log_lines(
    parsed_logs: pd.DataFrame, start_idx: int, end_idx: int
) -> List[str]:
    if parsed_logs.empty:
        return []

    if "line_number" in parsed_logs.columns:
        mask = (parsed_logs["line_number"] >= start_idx) & (
            parsed_logs["line_number"] <= end_idx
        )
        window_df = parsed_logs[mask]
    else:
        window_df = parsed_logs.iloc[start_idx : end_idx + 1]

    lines = []
    for _, row in window_df.head(MAX_LOG_LINES_PER_WINDOW).iterrows():
        raw = str(row.get("raw_line") or row.get("event_template") or "").strip()
        if raw:
            lines.append(raw)
    return lines


def _build_triage_prompt(enriched: List[Dict[str, Any]]) -> str:
    window_blocks = []
    for item in enriched:
        log_content = (
            "\n".join(f"  {line}" for line in item["log_lines"])
            or "  (no log lines available)"
        )
        window_blocks.append(
            f"window_id={item['window_id']} score={item['anomaly_score']}\n"
            f"  actual={item['actual_event']} predicted={item['predicted_event']}\n"
            f"  log_lines:\n{log_content}"
        )
    windows_text = "\n\n".join(window_blocks)

    return f"""You are a DFIR analyst performing anomaly triage.

DeepLog flagged the following log windows as anomalous. Read the actual log content and classify each window.

{windows_text}

For each window, decide:
- "suspicious": likely malicious or worth investigating
- "uncertain": ambiguous, keep for investigation to be safe
- "noise": clearly benign or a false positive, safe to drop

Return a JSON array only — no other text:
[
  {{"window_id": <id>, "verdict": "suspicious" | "uncertain" | "noise", "reason": "<max 20 words>"}},
  ...
]"""


def _parse_triage_response(response: str) -> Dict[str, str]:
    text = response
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()
    else:
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            text = match.group(0)

    items = json.loads(text)
    if not isinstance(items, list):
        return {}

    labels: Dict[str, str] = {}
    for item in items:
        window_id = str(item.get("window_id", ""))
        verdict = str(item.get("verdict", "uncertain")).lower().strip()
        if verdict not in ("suspicious", "uncertain", "noise"):
            verdict = "uncertain"
        if window_id:
            labels[window_id] = verdict
    return labels
