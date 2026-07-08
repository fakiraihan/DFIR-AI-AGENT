from typing import Any, Dict, List, Mapping


def build_structured_correlation(
    agent: Any,
    state: Mapping[str, Any],
    correlation_text: str,
) -> Dict[str, Any]:
    supporting = list(state.get("supporting_evidence") or [])
    normalized = [
        item
        for item in state.get("normalized_evidence") or []
        if agent._normalized_evidence_succeeded(item)
    ]
    malicious = [
        item for item in normalized if str(item.get("verdict") or "") == "malicious"
    ]
    suspicious = [
        item for item in normalized if str(item.get("verdict") or "") == "suspicious"
    ]

    verdict = "inconclusive"
    confidence = "low"
    if malicious:
        verdict = "confirmed_threat"
        confidence = "high" if len(malicious) > 1 else "medium"
    elif suspicious:
        verdict = "suspicious"
        confidence = "medium"
    elif supporting:
        verdict = "likely_false_positive"
        confidence = "low"

    evidence_gaps: List[str] = []
    if not supporting:
        evidence_gaps.append("No successful supporting evidence was available.")
    elif not malicious and not suspicious:
        evidence_gaps.append("Evidence did not contain malicious or suspicious verdicts.")
    if "insufficient" in correlation_text.lower() or "kurang bukti" in correlation_text.lower():
        evidence_gaps.append("Correlation analysis explicitly reported an evidence gap.")

    follow_up_requests = [
        {
            "ioc": ioc.get("value") or ioc.get("ioc"),
            "ioc_type": ioc.get("type") or ioc.get("ioc_type"),
            "reason": "Additional enrichment is needed to close evidence gaps.",
        }
        for ioc in state.get("iocs_extracted") or []
        if evidence_gaps
    ]

    return {
        "verdict": verdict,
        "confidence": confidence,
        "correlation_findings": _correlation_findings(supporting),
        "evidence_gaps": evidence_gaps,
        "follow_up_requests": follow_up_requests[:5],
        "threat_summary": _threat_summary(verdict, malicious, suspicious),
    }


def _correlation_findings(supporting: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    for item in supporting[:5]:
        findings.append(
            {
                "ioc": item.get("ioc"),
                "ioc_type": item.get("ioc_type"),
                "source": item.get("source"),
                "verdict": item.get("verdict"),
                "confidence": item.get("confidence"),
                "summary": item.get("evidence_summary"),
            }
        )
    return findings


def _threat_summary(
    verdict: str,
    malicious: List[Dict[str, Any]],
    suspicious: List[Dict[str, Any]],
) -> str:
    if verdict == "confirmed_threat":
        return f"{len(malicious)} malicious evidence item(s) support the threat hypothesis."
    if verdict == "suspicious":
        return f"{len(suspicious)} suspicious evidence item(s) require follow-up."
    if verdict == "likely_false_positive":
        return "Available evidence does not currently support a malicious verdict."
    return "Evidence is insufficient for a conclusive threat verdict."
