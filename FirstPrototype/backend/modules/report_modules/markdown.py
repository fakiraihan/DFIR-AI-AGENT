"""Markdown rendering for structured DFIR reports."""

from typing import Any, Dict


def to_markdown(report: Dict[str, Any]) -> str:
    """Render a structured report dictionary as Markdown."""
    metadata = report.get("metadata", {})
    case_overview = report.get("case_overview", {})
    standards = report.get("standards_profile", {})
    objectives_scope = report.get("objectives_scope", {})
    methodology = report.get("methodology", {})
    evidence = report.get("evidence_provenance", {})
    detection = report.get("detection_analysis", {})
    mitre = report.get("mitre_attack_mapping", {})
    impact = report.get("impact_assessment", {})
    limitations = report.get("limitations_confidence", {})
    appendices = report.get("appendices", {})

    lines = [
        "# DFIR Investigation Report",
        "",
        "## Metadata & Case Overview",
        f"- Report Version: {report.get('report_version', '-')}",
        f"- Standards Profile: {standards.get('profile_name', '-')}",
        f"- Report ID: {metadata.get('report_id', '-')}",
        f"- Session ID: {case_overview.get('session_id', metadata.get('session_id', '-'))}",
        f"- Timestamp: {metadata.get('timestamp', '-')}",
        f"- Log File: {case_overview.get('log_file', metadata.get('log_file', '-'))}",
        f"- Severity: {metadata.get('severity', '-')}",
        f"- Case Status: {case_overview.get('case_status', '-')}",
        "",
        "## Executive Summary",
        report.get("executive_summary", "No summary available."),
        "",
        "## Objectives & Scope",
    ]

    for objective in objectives_scope.get("objectives", []):
        lines.append(f"- Objective: {objective}")
    if objectives_scope.get("scope"):
        lines.append(f"- Scope: {objectives_scope.get('scope')}")
    for item in objectives_scope.get("out_of_scope", []):
        lines.append(f"- Out of scope: {item}")

    lines.append("")
    lines.append("## Methodology & Tools")
    lines.append(f"- Validation Status: {methodology.get('validation_status', '-')}")
    for tool in methodology.get("tools", []):
        lines.append(f"- Tool: {tool}")
    for step in methodology.get("steps_performed", []):
        lines.append(f"- Step: {step.get('step', '-')}")

    lines.append("")
    lines.append("## Evidence & Provenance")
    for source in evidence.get("sources", []):
        lines.append(
            f"- Source {source.get('source_id', '-')}: {source.get('name', '-')} | type={source.get('type', '-')} | sha256={source.get('hashes', {}).get('sha256', '-')}"
        )
    for item in evidence.get("items", []):
        lines.append(
            f"- {item.get('evidence_id', '-')} | {item.get('type', '-')} | {item.get('reference', '-')} | timestamp={item.get('timestamp', '-')} | hash={item.get('hash', '-')} | {item.get('description', '-')}"
        )

    lines.append("")
    lines.append("## Detection & Analysis Findings")
    lines.append(f"- Anomaly Count: {detection.get('anomaly_count', 0)}")
    ioc_count = detection.get("ioc_count", 0)
    ioc_total_extracted = detection.get("ioc_count_total_extracted", 0)
    if ioc_total_extracted > ioc_count:
        lines.append(
            f"- IOC Count: {ioc_count} curated of {ioc_total_extracted} total extracted"
        )
    else:
        lines.append(f"- IOC Count: {ioc_count}")
    lines.append(f"- Tool Result Count: {detection.get('tool_result_count', 0)}")
    strongest = detection.get("strongest_compromise_indicators", [])
    if strongest:
        lines.append("")
        lines.append("### Highest-Signal Anomaly Windows")
        for item in strongest:
            evidence_ids = ", ".join(item.get("evidence_ids", [])) or "Not available"
            lines.append(
                f"- {item.get('indicator', '-')} | category={item.get('category', '-')} | strength={item.get('strength', '-')} | Evidence IDs: {evidence_ids} | {item.get('reason', '-')}"
            )
        lines.append("")
    for finding in detection.get("findings", []):
        evidence_ids = ", ".join(finding.get("evidence_ids", [])) or "Not available"
        lines.append(
            f"- {finding.get('finding_id', '-')} | {finding.get('title', 'Finding')}: {finding.get('detail', '-')} | Evidence IDs: {evidence_ids}"
        )

    lines.append("")
    lines.append("## MITRE ATT&CK Mapping")
    lines.append(f"- Status: {mitre.get('status', '-')}")
    for technique in mitre.get("techniques", []):
        evidence_ids = ", ".join(technique.get("evidence_ids", [])) or "Not available"
        lines.append(
            f"- {technique.get('technique_id', '-')} | {technique.get('technique_name', '-')} | {technique.get('tactic', '-')} | confidence={technique.get('confidence', '-')} | Evidence IDs: {evidence_ids} | {technique.get('rationale', '-')}"
        )

    lines.append("")
    lines.append("## Incident Timeline")
    for event in appendices.get("timeline", []):
        lines.append(
            f"- {event.get('timestamp', '-')} | {event.get('event', '-')} | {event.get('details', '-')} | Evidence ID: {event.get('evidence_id', 'Not available')}"
        )

    lines.append("")
    lines.append("## Impact Assessment")
    for key, value in impact.items():
        lines.append(f"- {key.replace('_', ' ').title()}: {value}")

    lines.append("")
    lines.append("## Recommendations")
    for index, recommendation in enumerate(report.get("recommendations", []), start=1):
        lines.append(f"{index}. {recommendation}")

    lines.append("")
    lines.append("## Limitations & Confidence")
    lines.append(f"- Confidence Level: {limitations.get('confidence_level', '-')}")
    for limitation in limitations.get("limitations", []):
        lines.append(f"- {limitation}")

    lines.append("")
    lines.append("## Appendices")
    lines.append("### IOC Table")
    if appendices.get("ioc_table"):
        for ioc in appendices.get("ioc_table", []):
            lines.append(
                f"- {ioc.get('indicator') or ioc.get('value', '-')} | type={ioc.get('indicator_type', ioc.get('type', 'unknown'))} | threat={ioc.get('threat_level', 'low')} | source_line={ioc.get('source_line', '-')} | source_window={ioc.get('source_window', '-')} | intel={ioc.get('threat_intel', '-')}"
            )
    else:
        lines.append("- No curated IOC entries.")

    lines.append("### Raw References")
    raw_references = appendices.get("raw_references", [])
    if raw_references:
        for reference in raw_references:
            lines.append(f"- {reference}")
    else:
        lines.append("- Not available")

    return "\n".join(lines) + "\n"
