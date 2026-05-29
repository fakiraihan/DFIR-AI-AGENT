"""Technical findings, timeline, and evidence section builders."""

from collections import Counter
from typing import Any, Dict, List

from . import common


def build_technical_findings(
    anomalies: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build concise technical findings for the report."""
    findings: List[Dict[str, Any]] = []
    top_events = common.top_anomalous_events(anomalies)
    malicious_hits = common.count_malicious_hits(tool_results)
    suspicious_hits = common.count_suspicious_hits(tool_results)
    unavailable_hits = sum(1 for item in tool_results if item.get("error"))

    if anomalies:
        findings.append(
            {
                "title": "Deteksi anomali utama",
                "detail": f"DeepLog menandai {len(anomalies)} window anomali. Event yang paling sering muncul pada window tersebut adalah {top_events or 'belum ada pola dominan'}.",
            }
        )

    if ioc_analysis:
        type_counter = Counter(ioc.get("type", "unknown") for ioc in ioc_analysis)
        distribution = ", ".join(
            f"{count} {ioc_type}" for ioc_type, count in type_counter.most_common(4)
        )
        findings.append(
            {
                "title": "IOC terkurasi",
                "detail": f"Sebanyak {len(ioc_analysis)} IOC bernilai analitis berhasil dipertahankan untuk investigasi lanjutan, dengan distribusi utama: {distribution}.",
            }
        )

    if malicious_hits or suspicious_hits:
        findings.append(
            {
                "title": "Korelasi threat intelligence",
                "detail": f"Hasil enrichment menunjukkan {malicious_hits} IOC dengan indikasi malicious dan {suspicious_hits} IOC dengan indikasi suspicious. Prioritaskan validasi IOC dengan threat level tertinggi terlebih dahulu.",
            }
        )
    elif unavailable_hits:
        findings.append(
            {
                "title": "Keterbatasan enrichment",
                "detail": f"Sebagian lookup threat intelligence belum tersedia atau belum terkonfigurasi ({unavailable_hits} hasil). Kesimpulan saat ini lebih banyak bertumpu pada pola anomali log dibanding reputasi eksternal.",
            }
        )

    if not findings:
        findings.append(
            {
                "title": "Belum ada pola ancaman yang kuat",
                "detail": "Belum ditemukan kombinasi anomali dan enrichment yang cukup kuat untuk mengonfirmasi aktivitas malicious. Investigasi lanjutan tetap disarankan untuk menutup kemungkinan false negative.",
            }
        )

    return findings


def build_timeline(
    timeline: List[Dict[str, Any]], fallback_timestamp: str
) -> List[Dict[str, Any]]:
    """Normalize timeline entries for report output."""
    normalized = []
    for item in timeline:
        normalized.append(
            {
                "timestamp": item.get("timestamp") or fallback_timestamp,
                "event": item.get("event")
                or item.get("event_template")
                or "Anomalous event",
                "details": common.clean_text(
                    item.get("details")
                    or item.get("description")
                    or "No details available"
                ),
            }
        )
    return normalized


def build_evidence_references(
    anomalies: List[Dict[str, Any]], tool_results: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Build report evidence references from anomalies and tool results."""
    evidence: List[Dict[str, Any]] = []

    for anomaly in anomalies[:30]:
        evidence.append(
            {
                "type": "log_window",
                "reference": f"window:{anomaly.get('window_id')}",
                "description": f"Anomalous window with event '{anomaly.get('actual_event', 'unknown')}'",
            }
        )

    meaningful_tool_results = [
        result for result in tool_results if not common.is_skipped_result(result)
    ]

    for result in meaningful_tool_results[:30]:
        target = (
            result.get("ioc")
            or result.get("ip")
            or result.get("url")
            or result.get("hash")
            or "unknown"
        )
        evidence.append(
            {
                "type": "tool_result",
                "reference": f"{result.get('tool', 'tool')}:{target}",
                "description": common.summarize_tool_result(result),
            }
        )

    return evidence
