"""Evidence-bound report v2 section builders."""

import re
from typing import Any, Dict, List

_WEB_PORT_RE = re.compile(r"destination_port[=:]?\s*(80|443|8080|8443)\b")
_ANOMALY_EVIDENCE_CAP = 30

from modules.report_modules import common as report_common


def add_report_v2_sections(
    report: Dict[str, Any],
    session_id: str,
    file_name: str,
    generated_at: str,
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    raw_timeline: List[Dict[str, Any]],
    attack_timeline: List[Dict[str, Any]],
    total_extracted_iocs: int = 0,
) -> None:
    """Augment the legacy report object with evidence-bound v2 sections."""
    evidence_provenance = build_evidence_provenance(
        file_name, anomalies, tool_results, raw_timeline
    )
    evidence_items = evidence_provenance["items"]
    report.update(
        {
            "report_version": "2.0",
            "standards_profile": build_standards_profile(),
            "case_overview": build_case_overview(
                session_id,
                file_name,
                generated_at,
                report["metadata"].get("severity", "LOW"),
            ),
            "objectives_scope": build_objectives_scope(file_name),
            "methodology": build_methodology(),
            "evidence_provenance": evidence_provenance,
            "detection_analysis": build_detection_analysis(
                anomalies,
                ioc_analysis,
                tool_results,
                report.get("technical_findings", []),
                evidence_items,
                total_extracted_iocs,
            ),
            "mitre_attack_mapping": build_mitre_attack_mapping(
                anomalies, ioc_analysis, evidence_items
            ),
            "impact_assessment": build_impact_assessment(),
            "limitations_confidence": build_limitations_confidence(
                anomalies,
                ioc_analysis,
                tool_results,
                raw_timeline,
            ),
            "appendices": build_appendices(
                ioc_analysis,
                raw_timeline,
                attack_timeline,
                generated_at,
                evidence_items,
            ),
        }
    )


def build_standards_profile() -> Dict[str, Any]:
    """Build report v2 standards metadata."""
    return {
        "profile_name": "Evidence-bound DFIR report v2",
        "certification_status": "Not certified",
        "references": [
            "MITRE ATT&CK Enterprise technique taxonomy",
            "NIST SP 800-61 incident handling lifecycle",
            "Evidence-first DFIR reporting controls",
        ],
    }


def build_case_overview(
    session_id: str,
    file_name: str,
    generated_at: str,
    severity: str,
) -> Dict[str, Any]:
    """Build report v2 case overview."""
    return {
        "session_id": session_id,
        "log_file": file_name,
        "generated_at": generated_at,
        "severity": severity,
        "case_status": "Not assessed",
        "assessment_basis": "Generated from available investigation_state only",
    }


def build_objectives_scope(file_name: str) -> Dict[str, Any]:
    """Build report v2 objectives and scope."""
    return {
        "objectives": [
            "Summarize observed anomaly and IOC evidence without unsupported claims.",
            "Preserve stable evidence identifiers for analyst review.",
            "Map only supported ATT&CK techniques with medium or high confidence.",
        ],
        "scope": f"Analysis is limited to uploaded log file `{file_name}` and enrichment results available in the investigation state.",
        "out_of_scope": [
            "Attribution, impact, and data exposure conclusions not directly supported by evidence.",
        ],
    }


def build_methodology() -> Dict[str, Any]:
    """Build report v2 methodology details."""
    return {
        "validation_status": "Generated from available investigation_state only",
        "tools": [
            "Drain",
            "DeepLog",
            "LLM anomaly gate",
            "LangGraph DFIRAgent",
            "threat-intel enrichment",
            "report generator",
        ],
        "steps_performed": [
            {"step": "Drain parsing normalized raw log events into templates."},
            {"step": "DeepLog identified anomaly windows for triage."},
            {"step": "LLM anomaly gate reviewed candidate anomaly context."},
            {"step": "LangGraph DFIRAgent correlated anomalies with IOC context."},
            {"step": "threat-intel enrichment added available external reputation data."},
            {"step": "report generator produced evidence-bound JSON and Markdown output."},
        ],
    }


def select_evidenced_anomalies(
    anomalies: List[Dict[str, Any]],
    cap: int = _ANOMALY_EVIDENCE_CAP,
    score_extra: int = 15,
) -> List[Dict[str, Any]]:
    """Anomalies that get stable evidence IDs.

    Anomalies arrive in chronological (window) order, so the first ``cap`` cover
    the timeline. But 'Strongest Compromise Indicators' ranks anomalies by score
    and can surface high-score windows far down the list (e.g. window 100+); if
    those are not evidenced they render as 'Evidence IDs: Not available' and any
    claim about them becomes unverifiable. So also evidence the top ``score_extra``
    highest-scoring anomalies from beyond the chronological head.
    """
    head = list(anomalies[:cap])
    tail_high_signal = [
        item
        for item in anomalies[cap:]
        if bool(item.get("strict_is_anomaly")) or numeric_anomaly_score(item) >= 0.75
    ]
    tail_ranked = sorted(tail_high_signal, key=lambda item: -numeric_anomaly_score(item))
    return head + tail_ranked[:score_extra]


def select_evidenced_tool_results(
    tool_results: List[Dict[str, Any]],
    cap: int = _ANOMALY_EVIDENCE_CAP,
    positive_extra: int = 15,
) -> List[Dict[str, Any]]:
    """Tool results that get stable evidence IDs.

    Positive (malicious/suspicious) verdicts drive severity and recommendations,
    so a malicious result sitting beyond the first ``cap`` would let the report
    flag an IOC as malicious with no citable evidence. Always evidence the
    positive verdicts in the tail alongside the first ``cap``.
    """
    head = list(tool_results[:cap])
    tail_positive = [
        result
        for result in tool_results[cap:]
        if report_common.is_malicious_result(result)
        or report_common.is_suspicious_result(result)
    ]
    return head + tail_positive[:positive_extra]


def build_evidence_provenance(
    file_name: str,
    anomalies: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build stable report v2 evidence identifiers."""
    items: List[Dict[str, Any]] = []
    sequence = 1

    for anomaly in select_evidenced_anomalies(anomalies):
        reference = anomaly_reference(anomaly)
        items.append(
            {
                "evidence_id": f"EV-LOG-{sequence:03d}",
                "type": "log_window",
                "reference": reference,
                "description": report_common.clean_text(
                    f"Anomalous window with event '{anomaly.get('actual_event', 'unknown')}'"
                ),
                "timestamp": timestamp_for_reference(reference, timeline),
                "hash": "Not available",
            }
        )
        sequence += 1

    meaningful_tool_results = [
        result for result in tool_results if not report_common.is_skipped_result(result)
    ]
    for result in select_evidenced_tool_results(meaningful_tool_results):
        target = tool_result_target(result)
        items.append(
            {
                "evidence_id": f"EV-TOOL-{sequence:03d}",
                "type": "tool_result",
                "reference": f"{result.get('tool', 'tool')}:{target}",
                "description": report_common.summarize_tool_result(result),
                "timestamp": "Not available",
                "hash": "Not available",
            }
        )
        sequence += 1

    return {
        "sources": [
            {
                "source_id": "SRC-001",
                "name": file_name,
                "type": "log_file",
                "hashes": {"sha256": "Not available"},
            }
        ],
        "chain_of_custody": [],
        "items": items,
    }


def build_detection_analysis(
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    technical_findings: List[Dict[str, Any]],
    evidence_items: List[Dict[str, Any]],
    total_extracted_iocs: int = 0,
) -> Dict[str, Any]:
    """Build report v2 detection analysis."""
    log_evidence_ids = [
        item["evidence_id"] for item in evidence_items if item.get("type") == "log_window"
    ]
    tool_evidence_ids = [
        item["evidence_id"] for item in evidence_items if item.get("type") == "tool_result"
    ]
    findings = []
    for index, finding in enumerate(technical_findings, start=1):
        title = str(finding.get("title", "Finding"))
        if title == "Deteksi anomali utama":
            evidence_ids = log_evidence_ids
        elif title in {
            "IOC terkurasi",
            "Korelasi threat intelligence",
            "Keterbatasan enrichment",
        }:
            evidence_ids = tool_evidence_ids
        else:
            evidence_ids = (log_evidence_ids + tool_evidence_ids)[:5]

        findings.append(
            {
                "finding_id": f"DF-{index:03d}",
                "title": title,
                "detail": finding.get("detail", "Not available"),
                "evidence_ids": evidence_ids,
            }
        )

    meaningful_tool_results = [
        result for result in tool_results if not report_common.is_skipped_result(result)
    ]
    return {
        "anomaly_count": len(anomalies),
        "ioc_count": len(ioc_analysis),
        "ioc_count_total_extracted": total_extracted_iocs,
        "tool_result_count": len(meaningful_tool_results),
        "strongest_compromise_indicators": build_strongest_compromise_indicators(
            anomalies,
            ioc_analysis,
            evidence_items,
        ),
        "findings": findings,
    }


def build_strongest_compromise_indicators(
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    evidence_items: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Rank the clearest compromise indicators without making unsupported claims."""
    reference_to_ids = reference_to_evidence_ids(evidence_items)
    candidates: List[Dict[str, Any]] = []

    for ioc in ioc_analysis:
        threat_level = str(ioc.get("threat_level") or "low").lower()
        if threat_level not in {"high", "medium"}:
            continue

        value = str(ioc.get("value") or "")
        evidence_ids = evidence_ids_for_ioc(value, evidence_items)
        source_window = ioc.get("source_window")
        if source_window is not None:
            evidence_ids.extend(reference_to_ids.get(f"window:{source_window}", []))

        strength_rank = 4 if threat_level == "high" else 3
        candidates.append(
            {
                "indicator": ioc.get("indicator")
                or report_common.format_ioc_indicator(ioc.get("type", "ioc"), value),
                "category": "threat-intel IOC",
                "strength": "high" if threat_level == "high" else "medium",
                "reason": (
                    f"{ioc.get('indicator') or value} memiliki threat level {threat_level} "
                    f"dari enrichment threat-intel: {ioc.get('threat_intel', 'Not available')}."
                ),
                "evidence_ids": dedupe_preserve_order(evidence_ids),
                "_rank": strength_rank,
            }
        )

    for anomaly in anomalies:
        score = numeric_anomaly_score(anomaly)
        context = mitre_context(anomaly)
        has_compromise_context = any(
            marker in context
            for marker in [
                "powershell",
                "cmd.exe",
                "eventid=3",
                "eventid=13",
                "destination_ip",
                "registry",
                "target_object",
                "command_line",
            ]
        )
        is_strict = bool(anomaly.get("strict_is_anomaly"))
        if score < 0.75 and not is_strict and not has_compromise_context:
            continue

        reference = anomaly_reference(anomaly)
        anomaly_evidence_ids = reference_to_ids.get(reference, [])
        # Only surface anomalies that are actually evidenced. An anomaly without
        # an EV-LOG id cannot be cited or verified, so listing it as a
        # highest-signal window (with "Evidence IDs: Not available") is an
        # unsupported claim the report should not make.
        if not anomaly_evidence_ids:
            continue
        score_text = f"{score:.4f}" if score else "Not available"
        event = report_common.clean_text(anomaly.get("actual_event") or "Anomalous event")
        window_id = anomaly.get("window_id", "unknown")
        strength = "high" if is_strict or score >= 0.9 else "medium"
        candidates.append(
            {
                "indicator": f"Window {window_id}: {event[:120]}",
                "category": "DeepLog anomaly",
                "strength": strength,
                "reason": (
                    f"window {window_id} memiliki DeepLog score {score_text}"
                    + (" dan strict anomaly flag" if is_strict else "")
                    + format_key_indicator_reason(anomaly)
                    + "."
                ),
                "evidence_ids": anomaly_evidence_ids,
                "_rank": 4 if strength == "high" else 2,
                "_score": score,
            }
        )

    # Sort by rank then numeric score (descending) -- NOT by the indicator
    # string, which would order "Window 100" before "Window 2" alphabetically
    # and surface arbitrary high-numbered windows instead of the top-scoring
    # (and evidenced) ones.
    ranked = sorted(
        candidates,
        key=lambda item: (-item["_rank"], -item.get("_score", 0.0), item["category"]),
    )
    for item in ranked:
        item.pop("_rank", None)
        item.pop("_score", None)
    return ranked[:5]


def evidence_ids_for_ioc(value: str, evidence_items: List[Dict[str, Any]]) -> List[str]:
    """Find enrichment evidence ids that refer to an IOC value."""
    if not value:
        return []
    lowered_value = value.lower()
    matches = []
    for item in evidence_items:
        reference = str(item.get("reference") or "").lower()
        evidence_id = str(item.get("evidence_id") or "")
        if evidence_id and reference.endswith(f":{lowered_value}"):
            matches.append(evidence_id)
    return matches


def numeric_anomaly_score(anomaly: Dict[str, Any]) -> float:
    """Return a float score from supported anomaly score fields."""
    score = anomaly.get("anomaly_score") or anomaly.get("score") or 0
    try:
        return float(score)
    except (TypeError, ValueError):
        return 0.0


def format_key_indicator_reason(anomaly: Dict[str, Any]) -> str:
    """Format compact anomaly field context for indicator reasoning."""
    values = []
    anomalous_line = anomaly.get("anomalous_line") or {}
    if isinstance(anomalous_line, dict):
        fields = anomalous_line.get("important_fields") or {}
        if isinstance(fields, dict):
            for key in ["image", "command_line", "destination_ip", "target_object", "user"]:
                value = fields.get(key)
                if value:
                    values.append(f"{key}={value}")

    indicators = anomaly.get("window_key_indicators") or {}
    if isinstance(indicators, dict):
        for key in ["destination_ip", "query_name", "image", "target_object"]:
            for value in indicators.get(key) or []:
                if value:
                    values.append(f"{key}={value}")

    deduped = dedupe_preserve_order([str(value) for value in values])[:4]
    return f" dengan konteks {', '.join(deduped)}" if deduped else ""


def dedupe_preserve_order(values: List[str]) -> List[str]:
    """Deduplicate strings while preserving first-seen order."""
    deduped = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def build_mitre_attack_mapping(
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    evidence_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build conservative MITRE ATT&CK mappings from supported evidence."""
    _ = ioc_analysis
    if not anomalies:
        return {"status": "Not assessed", "techniques": [], "tactics": []}

    reference_to_ids = reference_to_evidence_ids(evidence_items)
    mapped: Dict[str, Dict[str, Any]] = {}

    for anomaly in anomalies:
        reference = anomaly_reference(anomaly)
        evidence_ids = reference_to_ids.get(reference, [])
        if not evidence_ids:
            continue

        context = mitre_context(anomaly)
        if "powershell" in context:
            record_mitre_mapping(
                mapped,
                technique_id="T1059.001",
                tactic="Execution",
                technique_name="PowerShell",
                confidence="high",
                evidence_ids=evidence_ids,
                rationale=f"PowerShell execution evidence observed in {reference}.",
            )
        elif "cmd.exe" in context or "eventid=1" in context:
            record_mitre_mapping(
                mapped,
                technique_id="T1059",
                tactic="Execution",
                technique_name="Command and Scripting Interpreter",
                confidence="medium",
                evidence_ids=evidence_ids,
                rationale=f"Command execution evidence observed in {reference}.",
            )

        # Require an actual web destination port, not merely the substring
        # "http" anywhere in context: a scheduled-task/registry field can carry
        # an XML schema namespace URL (e.g. http://schemas.microsoft.com/...),
        # which is not Command-and-Control network traffic. Real web C2 over
        # Sysmon/Security network events always carries destination_port.
        has_web_destination = bool(_WEB_PORT_RE.search(context))
        if (
            "eventid=3" in context
            or "network" in context
            or "destination_ip" in context
        ) and has_web_destination:
            record_mitre_mapping(
                mapped,
                technique_id="T1071",
                tactic="Command and Control",
                technique_name="Application Layer Protocol",
                confidence="medium",
                evidence_ids=evidence_ids,
                rationale=f"Network protocol evidence observed in {reference}.",
            )

        if "eventid=13" in context and any(
            marker in context for marker in ["registry", "hkcu", "hklm", "target_object"]
        ):
            record_mitre_mapping(
                mapped,
                technique_id="T1112",
                tactic="Defense Evasion",
                technique_name="Modify Registry",
                confidence="medium",
                evidence_ids=evidence_ids,
                rationale=f"Registry modification evidence observed in {reference}.",
            )

    techniques = [mapped[key] for key in sorted(mapped)]
    tactics = []
    for technique in techniques:
        tactic = technique["tactic"]
        if tactic not in tactics:
            tactics.append(tactic)

    return {
        "status": "Mapped" if techniques else "No supported mappings",
        "techniques": techniques,
        "tactics": tactics,
    }


def record_mitre_mapping(
    mapped: Dict[str, Dict[str, Any]],
    *,
    technique_id: str,
    tactic: str,
    technique_name: str,
    confidence: str,
    evidence_ids: List[str],
    rationale: str,
) -> None:
    """Add or merge a supported ATT&CK mapping."""
    if confidence not in {"medium", "high"} or not evidence_ids:
        return

    deduped_ids = []
    for evidence_id in evidence_ids:
        if evidence_id not in deduped_ids:
            deduped_ids.append(evidence_id)

    existing = mapped.get(technique_id)
    if existing:
        for evidence_id in deduped_ids:
            if evidence_id not in existing["evidence_ids"]:
                existing["evidence_ids"].append(evidence_id)
        if confidence == "high":
            existing["confidence"] = "high"
        return

    mapped[technique_id] = {
        "technique_id": technique_id,
        "tactic": tactic,
        "technique_name": technique_name,
        "confidence": confidence,
        "evidence_ids": deduped_ids,
        "rationale": rationale,
    }


def build_impact_assessment() -> Dict[str, Any]:
    """Build safe default impact assessment."""
    return {
        "status": "Not assessed",
        "business_impact": "Not assessed",
        "operational_impact": "Not assessed",
        "data_exposure": "Not assessed",
        "service_disruption": "Not assessed",
        "recoverability": "Not assessed",
    }


def build_limitations_confidence(
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build report v2 limitations and confidence statement."""
    limitations: List[str] = []

    if not ioc_analysis:
        limitations.append("No IOC was available after curation for this report.")
    if not anomalies:
        limitations.append("No anomaly windows were available for this report.")
    if not anomalies or not ioc_analysis or not tool_results:
        limitations.append(
            "Low-evidence condition: conclusions must be validated with additional host, SIEM, and EDR context."
        )

    for result in tool_results:
        if report_common.is_skipped_result(result) or not result.get("error"):
            continue
        sanitized = report_common.sanitize_tool_error(result)
        if sanitized not in limitations:
            limitations.append(sanitized)

    if any(not item.get("timestamp") for item in timeline):
        limitations.append("One or more timeline timestamps are missing or unavailable.")

    return {
        "confidence_level": "Low",
        "limitations": limitations,
    }


def build_appendices(
    ioc_analysis: List[Dict[str, Any]],
    raw_timeline: List[Dict[str, Any]],
    attack_timeline: List[Dict[str, Any]],
    fallback_timestamp: str,
    evidence_items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build report v2 appendices."""
    reference_to_first_id = reference_to_first_evidence_id(evidence_items)
    timeline_rows = []
    # Evidence & Provenance only assigns stable IDs to the first
    # _ANOMALY_EVIDENCE_CAP anomalies (see build_evidence_provenance). Showing
    # every raw timeline row here would print "Evidence ID: Not available" for
    # the remainder (up to hundreds of rows on high-anomaly-volume cases), so
    # cap the visible timeline to what's actually evidenced and disclose the
    # truncation instead of silently dropping it.
    visible_timeline = raw_timeline[:_ANOMALY_EVIDENCE_CAP]
    for index, item in enumerate(visible_timeline):
        normalized = attack_timeline[index] if index < len(attack_timeline) else {}
        reference = timeline_reference(item)
        evidence_id = (
            reference_to_first_id.get(reference, "Not available")
            if reference != "Not available"
            else "Not available"
        )
        timeline_rows.append(
            {
                "timestamp": item.get("timestamp") or fallback_timestamp,
                "event": normalized.get("event")
                or item.get("event")
                or item.get("event_template")
                or "Anomalous event",
                "details": normalized.get("details")
                or report_common.clean_text(
                    item.get("details") or item.get("description") or "No details available"
                ),
                "evidence_reference": reference,
                "evidence_id": evidence_id,
            }
        )

    remaining = len(raw_timeline) - len(visible_timeline)
    if remaining > 0:
        timeline_rows.append(
            {
                "timestamp": "Not available",
                "event": f"... and {remaining} additional anomalous event(s) not individually listed",
                "details": (
                    f"Truncated for report length; {len(visible_timeline)} of "
                    f"{len(raw_timeline)} total timeline events shown above with "
                    "stable evidence IDs. Remaining events are available in the "
                    "raw investigation data."
                ),
                "evidence_reference": "Not available",
                "evidence_id": "Not available",
            }
        )

    return {
        "ioc_table": ioc_analysis,
        "timeline": timeline_rows,
        "raw_references": [],
    }


def anomaly_reference(anomaly: Dict[str, Any]) -> str:
    """Return a stable anomaly evidence reference."""
    window_id = anomaly.get("window_id")
    return f"window:{window_id if window_id is not None else 'unknown'}"


def tool_result_target(result: Dict[str, Any]) -> str:
    """Return the target represented by a tool result."""
    target = (
        result.get("ioc")
        or result.get("ip")
        or result.get("url")
        or result.get("hash")
        or result.get("domain")
        or "unknown"
    )
    return str(target)


def timeline_reference(item: Dict[str, Any]) -> str:
    """Resolve a timeline item to a stable evidence reference."""
    explicit_reference = item.get("evidence_reference")
    if explicit_reference:
        return str(explicit_reference)
    source_window = item.get("source_window")
    if source_window is None:
        source_window = item.get("window_id")
    if source_window is not None:
        return f"window:{source_window}"
    return "Not available"


def timestamp_for_reference(reference: str, timeline: List[Dict[str, Any]]) -> str:
    """Return first timeline timestamp matching an evidence reference."""
    for item in timeline:
        if timeline_reference(item) == reference and item.get("timestamp"):
            return str(item.get("timestamp"))
    return "Not available"


def reference_to_evidence_ids(
    evidence_items: List[Dict[str, Any]]
) -> Dict[str, List[str]]:
    """Map evidence references to all evidence ids."""
    references: Dict[str, List[str]] = {}
    for item in evidence_items:
        reference = str(item.get("reference") or "")
        evidence_id = str(item.get("evidence_id") or "")
        if not reference or not evidence_id:
            continue
        references.setdefault(reference, []).append(evidence_id)
    return references


def reference_to_first_evidence_id(evidence_items: List[Dict[str, Any]]) -> Dict[str, str]:
    """Map evidence references to their first evidence id."""
    first_ids: Dict[str, str] = {}
    for item in evidence_items:
        reference = str(item.get("reference") or "")
        evidence_id = str(item.get("evidence_id") or "")
        if reference and evidence_id and reference not in first_ids:
            first_ids[reference] = evidence_id
    return first_ids


def mitre_context(anomaly: Dict[str, Any]) -> str:
    """Build a lowercase context string for conservative MITRE mapping."""
    values = [str(anomaly.get("actual_event") or "")]
    anomalous_line = anomaly.get("anomalous_line") or {}
    if isinstance(anomalous_line, dict):
        fields = anomalous_line.get("important_fields") or {}
        if isinstance(fields, dict):
            for key, value in fields.items():
                values.append(str(key))
                values.append(str(value))
    indicators = anomaly.get("window_key_indicators") or {}
    if isinstance(indicators, dict):
        for key, entries in indicators.items():
            values.append(str(key))
            if isinstance(entries, list):
                values.extend(str(entry) for entry in entries)
            else:
                values.append(str(entries))
    return " ".join(values).lower()
