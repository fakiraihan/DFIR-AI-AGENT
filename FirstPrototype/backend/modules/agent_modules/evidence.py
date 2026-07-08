"""Threat-intel evidence normalization helpers for the DFIR agent."""

from typing import Any, Callable, Dict, List, Mapping

from modules.agent_modules import tooling


IdentifyIocType = Callable[[str], str | None]
ToolResultPredicate = Callable[[Dict[str, Any]], bool]
PositiveCount = Callable[[Any], int]
NormalizeResult = Callable[[Mapping[str, Any]], Dict[str, Any]]


def normalize_tool_result(
    tool_result: Mapping[str, Any],
    *,
    aliases: Mapping[str, str],
    identify_ioc_type: IdentifyIocType,
    is_malicious_tool_result: ToolResultPredicate,
    is_suspicious_tool_result: ToolResultPredicate,
    safe_positive_count: PositiveCount,
) -> Dict[str, Any]:
    """Normalize provider-specific threat-intel output into an auditable schema."""
    tool_name = tooling.normalize_tool_name(
        tool_result.get("tool_call") or tool_result.get("tool"), aliases
    )
    source = tool_name or str(tool_result.get("tool") or "unknown")
    ioc = tooling.extract_tool_result_ioc(tool_result)
    ioc_type = str(tool_result.get("ioc_type") or "").lower()
    if not ioc_type and ioc:
        ioc_type = identify_ioc_type(ioc) or "unknown"

    raw_status = str(tool_result.get("status") or "unknown")
    verdict = "unknown"
    confidence = 0.2
    summary_parts: List[str] = []

    if tool_result.get("skipped") or raw_status == "skipped":
        verdict = "error"
        confidence = 0.0
        summary_parts.append(str(tool_result.get("reason") or "tool call skipped"))
    elif tool_result.get("error") or raw_status == "error":
        verdict = "error"
        confidence = 0.0
        summary_parts.append(str(tool_result.get("error") or "tool returned error"))
    elif is_malicious_tool_result(dict(tool_result)):
        verdict = "malicious"
        confidence = 0.85
    elif is_suspicious_tool_result(dict(tool_result)):
        verdict = "suspicious"
        confidence = 0.65
    elif str(tool_result.get("classification") or "").lower() in {
        "benign",
        "clean",
        "riot",
    }:
        verdict = "benign"
        confidence = 0.6

    malicious_count = safe_positive_count(tool_result.get("malicious"))
    suspicious_count = safe_positive_count(tool_result.get("suspicious"))
    harmless_count = safe_positive_count(tool_result.get("harmless"))
    if malicious_count > 0:
        verdict = "malicious"
        confidence = min(1.0, 0.75 + malicious_count * 0.03)
        summary_parts.append(f"malicious detections={malicious_count}")
    elif suspicious_count > 0:
        verdict = "suspicious"
        confidence = min(0.85, 0.55 + suspicious_count * 0.05)
        summary_parts.append(f"suspicious detections={suspicious_count}")
    elif harmless_count > 0 and verdict == "unknown":
        verdict = "benign"
        confidence = 0.55
        summary_parts.append(f"harmless detections={harmless_count}")

    if source == "threatfox_lookup":
        if tool_result.get("malware_family") or tool_result.get("threat_type"):
            verdict = "malicious"
            confidence = max(
                confidence, coerce_confidence(tool_result.get("confidence_level"), 0.8)
            )
        summary_parts.extend(
            present_values(
                [tool_result.get("malware_family"), tool_result.get("threat_type")]
            )
        )
    elif source == "malwarebazaar_lookup":
        if tool_result.get("signature") or tool_result.get("data"):
            verdict = "malicious"
            confidence = max(confidence, 0.8)
        summary_parts.extend(
            present_values([tool_result.get("signature"), tool_result.get("file_type")])
        )
    elif source == "urlhaus_lookup":
        if tool_result.get("threat") or str(tool_result.get("url_status") or "").lower() in {
            "online",
            "offline",
        }:
            verdict = (
                "malicious"
                if str(tool_result.get("url_status") or "").lower() == "online"
                else "suspicious"
            )
            confidence = max(confidence, 0.75 if verdict == "malicious" else 0.6)
        summary_parts.extend(
            present_values([tool_result.get("url_status"), tool_result.get("threat")])
        )
    elif source == "alienvault_otx_lookup":
        pulse_count = safe_positive_count(tool_result.get("pulse_count"))
        if pulse_count > 0:
            verdict = "suspicious"
            confidence = min(0.85, 0.55 + pulse_count * 0.04)
            summary_parts.append(f"pulse_count={pulse_count}")
    elif source == "greynoise_lookup":
        classification = str(tool_result.get("classification") or "").lower()
        if classification in {"malicious", "suspicious", "benign"}:
            verdict = classification
            confidence = max(confidence, 0.65 if classification != "benign" else 0.6)
        summary_parts.extend(
            present_values([tool_result.get("classification"), tool_result.get("message")])
        )
    elif source == "shodan_internetdb_lookup":
        vulns = tool_result.get("vulns") or []
        ports = tool_result.get("ports") or []
        tags = tool_result.get("tags") or []
        if vulns:
            verdict = "suspicious"
            confidence = max(confidence, min(0.85, 0.55 + min(len(vulns), 6) * 0.05))
            summary_parts.append(f"shodan_vulns={len(vulns)}")
        elif ports or tags:
            summary_parts.append(
                f"shodan_ports={len(ports)} tags={len(tags)}"
            )
        else:
            raw_status_l = str(tool_result.get("status") or "").lower()
            if raw_status_l == "not_found":
                summary_parts.append("not in shodan dataset")
    elif source == "abuseipdb_lookup":
        score = safe_positive_count(tool_result.get("abuse_confidence_score"))
        reports = safe_positive_count(tool_result.get("total_reports"))
        if score >= 75:
            verdict = "malicious"
            confidence = max(confidence, min(1.0, 0.75 + (score - 75) * 0.005))
        elif score >= 25:
            verdict = "suspicious"
            confidence = max(confidence, min(0.85, 0.55 + (score - 25) * 0.006))
        elif tool_result.get("is_whitelisted"):
            verdict = "benign"
            confidence = max(confidence, 0.6)
        if score or reports:
            summary_parts.append(
                f"abuseipdb_score={score} reports={reports}"
            )
        if tool_result.get("is_tor"):
            summary_parts.append("tor_exit_node")

    if not summary_parts and tool_result.get("data"):
        summary_parts.append("provider response available")
    if not summary_parts:
        summary_parts.append("no explicit threat signal")

    return {
        "ioc": ioc,
        "ioc_type": ioc_type or "unknown",
        "source": source,
        "verdict": verdict
        if verdict in {"malicious", "suspicious", "benign", "unknown", "error"}
        else "unknown",
        "confidence": max(0.0, min(float(confidence), 1.0)),
        "evidence_summary": "; ".join(summary_parts[:4]),
        "raw_status": raw_status,
        "raw_reference": tool_result_raw_reference(tool_result, source, ioc),
    }


def aggregate_ioc_evidence(
    normalized_evidence: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Aggregate successful normalized evidence per IOC deterministically."""
    priority = {"malicious": 4, "suspicious": 3, "benign": 2, "unknown": 1, "error": 0}
    aggregated: Dict[str, Dict[str, Any]] = {}
    for item in normalized_evidence:
        if not normalized_evidence_succeeded(item):
            continue
        ioc = str(item.get("ioc") or "")
        ioc_type = str(item.get("ioc_type") or "unknown")
        if not ioc:
            continue
        key = f"{ioc_type}:{ioc}"
        existing = aggregated.get(key)
        verdict = str(item.get("verdict") or "unknown")
        confidence = float(item.get("confidence") or 0.0)
        if existing is None:
            aggregated[key] = {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "verdict": verdict,
                "confidence": confidence,
                "sources": [item.get("source")],
                "evidence": [item],
                "evidence_count": 1,
            }
            continue
        existing_sources = {
            str(source)
            for source in existing.get("sources", [])
            if source not in (None, "")
        }
        source = item.get("source")
        if source not in (None, ""):
            existing_sources.add(str(source))
        existing["sources"] = sorted(existing_sources)
        existing["evidence"].append(item)
        existing["evidence_count"] = len(existing["evidence"])
        if (priority.get(verdict, 0), confidence) > (
            priority.get(str(existing.get("verdict") or "unknown"), 0),
            float(existing.get("confidence") or 0.0),
        ):
            existing["verdict"] = verdict
            existing["confidence"] = confidence
    return aggregated


def build_evidence_state_update(
    state: Mapping[str, Any],
    new_results: List[Dict[str, Any]],
    normalize_result: NormalizeResult,
) -> Dict[str, Any]:
    """Build additive state updates from new threat-intel observations."""
    normalized_new = [normalize_result(result) for result in new_results]
    all_normalized = list(state.get("normalized_evidence") or []) + normalized_new
    aggregated = aggregate_ioc_evidence(all_normalized)
    supporting = supporting_evidence_from_aggregation(aggregated)
    confidence, factors = derive_investigation_confidence(supporting, all_normalized)
    return {
        "normalized_evidence": normalized_new,
        "aggregated_ioc_evidence": aggregated,
        "supporting_evidence": supporting,
        "investigation_confidence": confidence,
        "confidence_factors": factors,
        "investigation_status": "evidence_collected"
        if supporting
        else state.get("investigation_status", "inconclusive"),
    }


def supporting_evidence_from_aggregation(
    aggregated: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Return successful normalized evidence records in stable IOC-key order."""
    supporting = []
    for key in sorted(aggregated):
        item = aggregated[key]
        for evidence_item in item.get("evidence", []):
            if normalized_evidence_succeeded(evidence_item):
                supporting.append(evidence_item)
    return supporting


def derive_investigation_confidence(
    supporting: List[Dict[str, Any]],
    all_normalized: List[Dict[str, Any]],
) -> tuple[float, List[str]]:
    """Derive bounded confidence and explanatory factors from normalized evidence."""
    if not supporting:
        return 0.0, ["No successful non-skipped enrichment evidence was available"]
    max_confidence = max(float(item.get("confidence") or 0.0) for item in supporting)
    source_count = len({item.get("source") for item in supporting})
    ioc_count = len({(item.get("ioc_type"), item.get("ioc")) for item in supporting})
    error_count = len([item for item in all_normalized if item.get("verdict") == "error"])
    confidence = min(1.0, max_confidence + min(source_count, 3) * 0.03)
    if error_count:
        confidence = max(0.0, confidence - min(error_count, 5) * 0.02)
    factors = [
        f"{len(supporting)} successful evidence records",
        f"{source_count} enrichment sources",
        f"{ioc_count} IOC(s) with evidence",
    ]
    if error_count:
        factors.append(f"{error_count} error/skipped records excluded from supporting evidence")
    return round(confidence, 3), factors


def has_successful_normalized_evidence(
    state: Mapping[str, Any], normalize_result: NormalizeResult
) -> bool:
    """Return true when state contains any usable normalized evidence."""
    normalized = list(state.get("normalized_evidence") or [])
    if not normalized:
        normalized = [
            normalize_result(result) for result in state.get("tool_results", []) or []
        ]
    return any(normalized_evidence_succeeded(item) for item in normalized)


def normalized_evidence_succeeded(evidence: Mapping[str, Any]) -> bool:
    """Return true when a normalized evidence item should support findings."""
    if evidence.get("verdict") == "error":
        return False
    if str(evidence.get("raw_status") or "").lower() in {"skipped", "error"}:
        return False
    return bool(evidence.get("ioc"))


def coerce_confidence(value: Any, default: float) -> float:
    """Coerce confidence values from provider payloads into the 0.0-1.0 range."""
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    if numeric > 1.0:
        numeric = numeric / 100.0
    return max(0.0, min(numeric, 1.0))


def present_values(values: List[Any]) -> List[str]:
    """Return provider values that are useful for compact evidence summaries."""
    return [str(value) for value in values if value not in (None, "", [], {})]


def tool_result_raw_reference(
    tool_result: Mapping[str, Any], source: str, ioc: str
) -> str:
    """Build a stable-ish raw provider reference string for audit traces."""
    timestamp = tool_result.get("timestamp") or "no_timestamp"
    return f"{source}:{ioc or 'unknown'}:{timestamp}"
