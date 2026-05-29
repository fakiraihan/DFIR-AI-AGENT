"""Timeline and anomaly formatting helpers for the DFIR agent."""

from typing import Any, Dict, List, Optional, Mapping

import pandas as pd


def build_timeline_description(anomaly: Dict[str, Any]) -> str:
    """Build a compact description for an anomalous timeline event."""
    detail_summary = summarize_anomaly_details(anomaly)
    if detail_summary:
        return (
            f"Anomalous event detected: {anomaly.get('actual_event', 'unknown')} | "
            f"{detail_summary}"
        )
    return f"Anomalous event detected: {anomaly.get('actual_event', 'unknown')}"


def timeline_interpretation(threat_evidence: List[Dict[str, Any]]) -> str:
    """Summarize how threat-intel evidence relates to a timeline item."""
    if not threat_evidence:
        return "Log anomaly requires manual review; no supporting IOC enrichment is linked to this timeline item."
    verdicts = {str(item.get("verdict") or "unknown") for item in threat_evidence}
    if "malicious" in verdicts:
        return "Log anomaly is linked to malicious IOC enrichment evidence."
    if "suspicious" in verdicts:
        return "Log anomaly is linked to suspicious IOC enrichment evidence."
    if "benign" in verdicts:
        return "Linked IOC enrichment did not show a threat signal; keep as contextual evidence."
    return "Linked IOC enrichment is available but inconclusive."


def summarize_anomaly_details(anomaly: Dict[str, Any]) -> str:
    """Extract high-signal fields from anomaly payloads for concise text."""
    key_fields = []

    anomalous_line = anomaly.get("anomalous_line") or {}
    if isinstance(anomalous_line, dict):
        fields = anomalous_line.get("important_fields") or {}
        if isinstance(fields, dict):
            for key in [
                "image",
                "command_line",
                "parent_image",
                "target_object",
                "destination_ip",
                "destination_port",
                "query_name",
                "user",
            ]:
                value = fields.get(key)
                if value:
                    key_fields.append(f"{key}={value}")
                if len(key_fields) >= 4:
                    break

    if not key_fields:
        indicators = anomaly.get("window_key_indicators") or {}
        if isinstance(indicators, dict):
            for key in [
                "image",
                "command_line",
                "target_object",
                "destination_ip",
                "query_name",
                "user",
            ]:
                values = indicators.get(key) or []
                if values:
                    key_fields.append(f"{key}={values[0]}")
                if len(key_fields) >= 4:
                    break

    return " | ".join(key_fields)


def resolve_timeline_timestamp(
    log_entry: Mapping[str, Any], anomaly: Dict[str, Any]
) -> Optional[str]:
    """Prefer parsed log timestamp and fall back to the anomaly payload timestamp."""
    log_timestamp = str(log_entry.get("timestamp") or "").strip()
    if log_timestamp:
        return log_timestamp

    anomalous_line = anomaly.get("anomalous_line") or {}
    if isinstance(anomalous_line, dict):
        anomaly_timestamp = str(anomalous_line.get("timestamp") or "").strip()
        if anomaly_timestamp:
            return anomaly_timestamp

    return None


def build_attack_timeline(state: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Build attack timeline items from anomalies and supporting IOC evidence."""
    anomalies = state["anomalies"]
    parsed_logs: pd.DataFrame = state["parsed_logs"]

    timeline = []
    supporting_by_ioc = {
        (str(item.get("ioc_type") or "").lower(), str(item.get("ioc") or "")): item
        for item in state.get("supporting_evidence", []) or []
    }

    for anomaly in anomalies:
        start_idx = anomaly["start_idx"]

        if start_idx >= len(parsed_logs):
            continue

        log_entry = parsed_logs.iloc[start_idx]
        window_id = anomaly["window_id"]
        window_iocs = [
            ioc
            for ioc in state.get("iocs_extracted", []) or []
            if ioc.get("window_id") == window_id
        ]
        threat_evidence = []
        for ioc in window_iocs:
            evidence = supporting_by_ioc.get(
                (str(ioc.get("type") or "").lower(), str(ioc.get("value") or ""))
            )
            if evidence:
                threat_evidence.append(evidence)

        confidence = max(
            [float(item.get("confidence") or 0.0) for item in threat_evidence]
            or [0.0]
        )
        event_template = anomaly["actual_event"]
        description = build_timeline_description(anomaly)
        timeline.append(
            {
                "window_id": window_id,
                "timestamp": resolve_timeline_timestamp(log_entry, anomaly),
                "event": event_template,
                "event_template": event_template,
                "severity": "high" if anomaly.get("is_anomaly") else "normal",
                "description": description,
                "details": description,
                "log_evidence": {
                    "window_id": window_id,
                    "event_id": log_entry.get("event_id"),
                    "event_template": event_template,
                },
                "ioc": window_iocs,
                "threat_evidence": threat_evidence,
                "interpretation": timeline_interpretation(threat_evidence),
                "confidence": round(confidence, 3),
                "source_window": window_id,
                "evidence_reference": f"window:{window_id}",
            }
        )

    timeline.sort(key=lambda item: item["window_id"])
    return timeline
