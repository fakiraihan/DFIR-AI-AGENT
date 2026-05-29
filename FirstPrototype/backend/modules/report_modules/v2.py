"""Evidence-bound report v2 section builders."""

from typing import Any, Dict, List

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


def build_evidence_provenance(
    file_name: str,
    anomalies: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build stable report v2 evidence identifiers."""
    items: List[Dict[str, Any]] = []
    sequence = 1

    for anomaly in anomalies[:30]:
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
    for result in meaningful_tool_results[:30]:
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
        "tool_result_count": len(meaningful_tool_results),
        "findings": findings,
    }


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

        if (
            "eventid=3" in context
            or "network" in context
            or "destination_ip" in context
        ) and any(marker in context for marker in ["http", "https", "443", "80"]):
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
    for index, item in enumerate(raw_timeline):
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
