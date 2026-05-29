"""Recommendation and assessment helpers for the DFIR agent."""

import re
from typing import Any, Callable, Dict, List, Mapping


AnomalySummarizer = Callable[[Dict[str, Any]], str]


def extract_recommendations(llm_response: str) -> List[str]:
    """Extract actionable recommendations from an LLM report response."""
    recommendations = []
    mojibake_bullet = "\u00e2\u20ac\u00a2"

    recommendation_header = re.compile(
        r"\b(REKOMENDASI|RECOMMENDATIONS?|TINDAKAN\s+PERBAIKAN|LANGKAH\s+PERBAIKAN|LANGKAH\s+MITIGASI)\b",
        re.IGNORECASE,
    )
    if recommendation_header.search(llm_response):
        lines = llm_response.split("\n")
        in_recommendations = False

        for line in lines:
            if recommendation_header.search(line):
                in_recommendations = True
                continue

            if in_recommendations and line.strip().startswith("#"):
                break

            if in_recommendations:
                stripped = line.strip()
                if stripped and (
                    stripped[0].isdigit()
                    or stripped.startswith(("-", mojibake_bullet, "*"))
                ):
                    rec = stripped.lstrip(f"0123456789.-{mojibake_bullet}* ")
                    if len(rec) > 10:
                        recommendations.append(rec)

    return recommendations[:10]


def generate_default_recommendations(
    state: Mapping[str, Any],
    summarize_anomaly_details: AnomalySummarizer,
) -> List[str]:
    """Generate evidence-based fallback recommendations from current findings."""
    anomalies = state.get("anomalies", []) or []
    tool_results = state.get("tool_results", []) or []
    iocs = state.get("iocs_extracted", []) or []
    timeline = state.get("attack_timeline", []) or []
    recommendations = []

    malicious_results = [
        result for result in tool_results if is_malicious_tool_result(result)
    ]
    suspicious_results = [
        result
        for result in tool_results
        if not is_malicious_tool_result(result) and is_suspicious_tool_result(result)
    ]
    priority_anomaly = select_priority_anomaly(anomalies)
    anomaly_context = format_anomaly_recommendation_context(priority_anomaly)
    artifact_context = format_anomaly_artifacts(
        priority_anomaly, summarize_anomaly_details
    )
    top_iocs = format_ioc_sample(iocs)

    if malicious_results:
        recommendations.append(
            f"Segera containment aset yang terkait dengan IOC malicious {format_tool_result_targets(malicious_results[:5])}; korelasikan dengan {anomaly_context}."
        )
        recommendations.append(
            "Blokir IOC malicious pada firewall, proxy, DNS sinkhole, EDR, dan SIEM lalu hunt kemunculan ulang pada host lain."
        )

    if suspicious_results:
        recommendations.append(
            f"Validasi IOC suspicious {format_tool_result_targets(suspicious_results[:5])} menggunakan log internal sebelum menaikkan verdict menjadi confirmed incident."
        )

    if priority_anomaly:
        recommendations.append(
            f"Triase {anomaly_context}; periksa raw log, process tree, user, parent process, command line, dan event sebelum/sesudah window tersebut."
        )

    if artifact_context:
        recommendations.append(
            f"Kumpulkan artefak forensik yang relevan dengan {artifact_context}, termasuk event log lengkap, prefetch/process execution, registry autorun, dan koneksi jaringan."
        )

    if top_iocs and not malicious_results:
        recommendations.append(
            f"Enrich dan korelasikan IOC terkurasi {top_iocs} dengan EDR, DNS, proxy, asset inventory, dan threat intelligence tambahan."
        )

    if timeline:
        recommendations.append(
            f"Gunakan {len(timeline)} item timeline untuk memastikan urutan kejadian dan menentukan apakah aktivitas ini merupakan chain serangan atau anomali terpisah."
        )

    if anomalies and not malicious_results and not suspicious_results:
        recommendations.append(
            f"Validasi {len(anomalies)} anomali DeepLog terhadap baseline operasional; jangan langsung tuning model sebelum window prioritas dan artefaknya dinyatakan false positive."
        )

    if not recommendations:
        recommendations.append(
            "Tidak ada deteksi prioritas yang cukup kuat; simpan hasil sebagai baseline dan lanjutkan monitoring pada pola log yang sama."
        )

    return recommendations[:10]


def is_malicious_tool_result(result: Dict[str, Any]) -> bool:
    """Return true when a provider result contains malicious signal."""
    if not result or result.get("status") == "skipped" or result.get("skipped"):
        return False
    return (
        result.get("classification") == "malicious"
        or bool(result.get("malware_family"))
        or safe_positive_count(result.get("malicious")) > 0
    )


def is_suspicious_tool_result(result: Dict[str, Any]) -> bool:
    """Return true when a provider result contains suspicious signal."""
    if not result or result.get("status") == "skipped" or result.get("skipped"):
        return False
    return (
        result.get("classification") == "suspicious"
        or safe_positive_count(result.get("suspicious")) > 0
    )


def safe_positive_count(value: Any) -> int:
    """Coerce provider count values into non-negative integers."""
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def select_priority_anomaly(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Select the highest-scoring anomaly with strict anomaly as tie-breaker."""
    if not anomalies:
        return {}

    def priority(anomaly: Dict[str, Any]):
        score = anomaly.get("anomaly_score") or anomaly.get("score") or 0
        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            numeric_score = 0.0
        return numeric_score, int(bool(anomaly.get("strict_is_anomaly")))

    return max(anomalies, key=priority)


def format_anomaly_recommendation_context(anomaly: Dict[str, Any]) -> str:
    """Format the priority anomaly as concise recommendation context."""
    if not anomaly:
        return "window anomali prioritas"

    parts = [f"window DeepLog {anomaly.get('window_id', '-')}"]
    score = anomaly.get("anomaly_score") or anomaly.get("score")
    if score is not None:
        try:
            parts.append(f"score {float(score):.3f}")
        except (TypeError, ValueError):
            parts.append(f"score {score}")

    event = str(anomaly.get("actual_event") or "").strip()
    if event:
        parts.append(f"event `{event[:120]}`")

    return " / ".join(parts)


def format_anomaly_artifacts(
    anomaly: Dict[str, Any], summarize_anomaly_details: AnomalySummarizer
) -> str:
    """Format anomaly artifact context for collection recommendations."""
    if not anomaly:
        return ""
    return summarize_anomaly_details(anomaly)


def format_tool_result_targets(results: List[Dict[str, Any]]) -> str:
    """Format IOC targets from provider results for recommendation text."""
    targets = []
    for result in results:
        target = (
            result.get("ioc")
            or result.get("ip")
            or result.get("url")
            or result.get("hash")
        )
        if target:
            targets.append(f"`{target}`")
    return ", ".join(targets) if targets else "yang ditemukan threat intelligence"


def format_ioc_sample(iocs: List[Dict[str, Any]]) -> str:
    """Format up to five extracted IOCs for recommendation text."""
    values = []
    for ioc in iocs[:5]:
        value = ioc.get("value")
        ioc_type = ioc.get("type", "ioc")
        if value:
            values.append(f"{ioc_type} `{value}`")
    return ", ".join(values)


def extract_severity(llm_response: str) -> str:
    """Extract severity classification from LLM response."""
    severity_terms = [
        ("CRITICAL", r"\b(CRITICAL|KRITIS)\b"),
        ("HIGH", r"\b(HIGH|TINGGI)\b"),
        ("MEDIUM", r"\b(MEDIUM|SEDANG)\b"),
        ("LOW", r"\b(LOW|RENDAH)\b"),
    ]
    negation_pattern = re.compile(
        r"\b(no|not|none|without|tidak|bukan|tanpa|nihil)\b", re.IGNORECASE
    )

    severity_lines = [
        line
        for line in llm_response.splitlines()
        if re.search(
            r"\b(severity|tingkat\s+keparahan|risk\s+level)\b",
            line,
            re.IGNORECASE,
        )
    ]
    search_spaces = severity_lines or llm_response.splitlines() or [llm_response]
    for text in search_spaces:
        for severity, pattern in severity_terms:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if not match:
                continue
            prefix = text[max(0, match.start() - 24) : match.start()]
            if negation_pattern.search(prefix):
                continue
            return severity

    return "MEDIUM"
