"""Executive summary helpers for structured DFIR reports."""

from typing import Any, Dict, List
import re

from . import common


def build_executive_summary(
    summary_text: str,
    severity: str,
    file_name: str,
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
    recommendations: List[str],
) -> str:
    """Build or repair the executive summary section."""
    cleaned_summary = common.clean_text(summary_text)
    if (
        cleaned_summary
        and not is_low_quality_summary(cleaned_summary)
        and summary_matches_evidence(
            cleaned_summary,
            anomalies,
            ioc_analysis,
            tool_results,
            timeline,
        )
    ):
        return cleaned_summary

    executed_tool_results = [
        item for item in tool_results if not common.is_skipped_result(item)
    ]
    malicious_hits = common.count_malicious_hits(tool_results)
    suspicious_hits = common.count_suspicious_hits(tool_results)
    top_iocs = [ioc["value"] for ioc in ioc_analysis[:3]]
    top_events = common.top_anomalous_events(anomalies)
    verdict = common.derive_verdict(
        severity, malicious_hits, suspicious_hits, anomalies
    )
    top_action = (
        "; ".join(recommendations[:3])
        if recommendations
        else "Lakukan validasi manual lebih lanjut"
    )
    top_action = top_action.rstrip(" .;")

    lines = [
        "### 1. Ringkasan Insiden",
        f"Investigasi terhadap file log `{file_name}` menemukan {len(anomalies)} window anomali yang perlu ditriase lebih lanjut. Severity saat ini diklasifikasikan sebagai **{severity}** dengan verdict awal: **{verdict}**.",
        "",
        "### 2. Temuan Utama",
        f"Sistem mengekstrak {len(ioc_analysis)} IOC terkurasi dari artefak anomali. Korelasi threat intelligence menunjukkan {malicious_hits} indikator malicious dan {suspicious_hits} indikator suspicious dari total {len(executed_tool_results)} hasil enrichment.",
        "",
        "### 3. Aktivitas yang Teramati",
        f"Aktivitas dominan yang muncul dalam window anomali adalah: {top_events or 'belum ada pola event dominan yang kuat'}. Timeline investigasi saat ini memuat {len(timeline)} kejadian penting yang dapat dijadikan dasar triase lanjutan.",
        "",
        "### 4. IOC Prioritas",
        f"IOC yang paling relevan untuk ditinjau terlebih dahulu: {', '.join(top_iocs) if top_iocs else 'belum ada IOC prioritas yang cukup kuat'}.",
        "",
        "### 5. Tindak Lanjut Disarankan",
        top_action + ".",
    ]

    return "\n".join(lines).strip()


def is_low_quality_summary(text: str) -> bool:
    """Return true when an LLM summary looks like a template or placeholder."""
    raw_error_patterns = [
        r"traceback \(most recent call last\)",
        r"\bfile\s+\"[^\"]+\",\s+line\s+\d+",
        r"\b(?:runtime|value|type|key|index|attribute|http|connection|timeout|ssl)error\s*:",
        r"\b[a-z_][\w]*(?:\.[a-z_][\w]*)+\.[a-z_]*error\s*:",
        r"\b\d{3}\s+(?:server|client)\s+error\b",
    ]
    placeholder_patterns = [
        r"\[[^\]]+\]",
        r"\[tanggal\]",
        r"\[jumlah\]",
        r"\[severity level\]",
        r"\[confidence level\]",
        r"error generating summary",
        r"final review and formatting",
        r"mitre att&ck mapping",
        r"appendix \(jika perlu\)",
        r"tanggal serangan\s*:",
        r"jenis serangan\s*:\s*malware atau phishing",
        r"nama korban\s*:",
        r"data sensitif dicuri",
        r"windows server 2019",
    ]
    lowered = text.lower()
    if len(text.strip()) < 80:
        return True
    if any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in raw_error_patterns):
        return True
    template_headings = [
        "mitre att&ck mapping",
        "final review and formatting",
    ]
    heading_matches = sum(1 for heading in template_headings if heading in lowered)
    if heading_matches >= 2:
        return True
    return any(
        re.search(pattern, lowered, flags=re.IGNORECASE)
        for pattern in placeholder_patterns
    )


def summary_matches_evidence(
    text: str,
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
) -> bool:
    """Return true when a summary references observed evidence."""
    evidence_terms = summary_evidence_terms(
        anomalies, ioc_analysis, tool_results, timeline
    )
    if not evidence_terms:
        return True

    lowered = text.lower()
    observed_ips = {
        term for term in evidence_terms if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", term)
    }
    summary_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    if any(ip not in observed_ips for ip in summary_ips):
        return False

    matched_terms = [term for term in evidence_terms if term.lower() in lowered]
    return len(matched_terms) >= 1


def summary_evidence_terms(
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
) -> List[str]:
    """Collect report evidence terms used to validate summaries."""
    terms: List[str] = []

    for anomaly in anomalies:
        window_id = anomaly.get("window_id")
        if window_id is not None:
            terms.append(f"window {window_id}")
        actual_event = str(anomaly.get("actual_event") or "").strip()
        if actual_event:
            terms.append(actual_event)

        anomalous_line = anomaly.get("anomalous_line") or {}
        if isinstance(anomalous_line, dict):
            fields = anomalous_line.get("important_fields") or {}
            if isinstance(fields, dict):
                terms.extend(str(value).strip() for value in fields.values() if value)

        indicators = anomaly.get("window_key_indicators") or {}
        if isinstance(indicators, dict):
            for values in indicators.values():
                if isinstance(values, list):
                    terms.extend(str(value).strip() for value in values if value)

    for ioc in ioc_analysis:
        value = str(ioc.get("value") or "").strip()
        if value:
            terms.append(value)

    for result in tool_results:
        for key in ["ioc", "ip", "url", "hash", "domain"]:
            value = str(result.get(key) or "").strip()
            if value:
                terms.append(value)

    for event in timeline:
        for key in ["event", "event_template", "description", "details"]:
            value = str(event.get(key) or "").strip()
            if value:
                terms.append(value)

    deduped = []
    seen = set()
    for term in terms:
        cleaned = re.sub(r"\s+", " ", term).strip(" `.,;:()[]{}")
        if len(cleaned) < 4:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cleaned)

    return deduped[:80]
