"""Recommendation builders for structured DFIR reports."""

from typing import Any, Dict, List, Tuple
import re

from . import common


def build_contextual_recommendations(
    severity: str,
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
) -> List[str]:
    """Build evidence-aware remediation recommendations."""
    recommendations: List[str] = []
    malicious_iocs = [
        ioc for ioc in ioc_analysis if ioc.get("threat_level") == "high"
    ]
    suspicious_iocs = [
        ioc for ioc in ioc_analysis if ioc.get("threat_level") == "medium"
    ]
    top_anomaly = select_priority_anomaly(anomalies)
    anomaly_context = format_anomaly_context(top_anomaly)
    affected_artifacts = collect_affected_artifacts(anomalies)

    if severity in {"CRITICAL", "HIGH"} and (malicious_iocs or anomalies):
        scope = format_ioc_values(malicious_iocs[:3]) or anomaly_context
        recommendations.append(
            f"Segera lakukan containment pada aset yang terkait dengan {scope} karena severity laporan berada pada level {severity}."
        )

    if malicious_iocs:
        recommendations.append(
            f"Blokir dan hunt IOC malicious berikut pada firewall, proxy, EDR, dan SIEM: {format_ioc_values(malicious_iocs[:5])}."
        )

    if suspicious_iocs:
        recommendations.append(
            f"Validasi IOC suspicious berikut sebelum eskalasi: {format_ioc_values(suspicious_iocs[:5])}; korelasikan dengan host, user, dan timestamp pada window sumbernya."
        )

    if top_anomaly:
        recommendations.append(
            f"Triase window DeepLog prioritas {anomaly_context}; cek process tree, user, parent process, command line, dan raw event di sekitar window tersebut."
        )

    if affected_artifacts:
        recommendations.append(
            f"Kumpulkan artefak host yang terkait dengan {affected_artifacts}: event log lengkap, process execution evidence, registry/persistence keys, dan network connection history."
        )

    if timeline:
        recommendations.append(
            f"Rekonstruksi urutan kejadian dari {len(timeline)} item timeline untuk memastikan apakah aktivitas anomali membentuk rantai serangan atau kejadian terpisah."
        )

    if anomalies and not malicious_iocs and not suspicious_iocs:
        recommendations.append(
            f"Karena belum ada IOC dengan reputasi malicious/suspicious, validasi {len(anomalies)} anomali DeepLog terhadap baseline operasional agar false positive bisa dipisahkan dari aktivitas baru yang belum dikenal threat intel."
        )

    if tool_results and not any(
        common.is_malicious_result(result) or common.is_suspicious_result(result)
        for result in tool_results
    ):
        recommendations.append(
            "Perluas enrichment IOC dengan sumber internal seperti EDR, DNS, proxy, dan asset inventory karena lookup eksternal belum memberi konfirmasi kuat."
        )

    if not recommendations:
        recommendations.append(
            "Tidak ada deteksi prioritas pada data saat ini; simpan laporan sebagai baseline dan lanjutkan monitoring rutin terhadap pola log yang sama."
        )

    return recommendations


def default_recommendations(severity: str) -> List[str]:
    """Return minimal fallback recommendations."""
    if severity in {"CRITICAL", "HIGH"}:
        return [
            f"Prioritaskan containment dan validasi forensik karena severity laporan adalah {severity}.",
            "Korelasikan anomali utama dengan host, user, proses, dan koneksi jaringan sebelum menutup insiden.",
        ]
    return [
        "Validasi anomali utama terhadap baseline operasional sebelum menyatakan false positive.",
        "Pertahankan log dan artefak terkait agar triase lanjutan tetap dapat diaudit.",
    ]


def normalize_recommendations(
    recommendations: List[str],
    severity: str,
    anomalies: List[Dict[str, Any]],
    ioc_analysis: List[Dict[str, Any]],
) -> List[str]:
    """Clean, deduplicate, and cap report recommendations."""
    normalized: List[str] = []
    seen = set()
    for recommendation in recommendations:
        cleaned = clean_recommendation(recommendation)
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(cleaned)

    if not normalized:
        normalized = default_recommendations(severity)

    if anomalies and all("manual" not in item.lower() for item in normalized):
        normalized.append(
            "Lakukan validasi manual pada window anomali prioritas untuk memastikan konteks proses, user, dan parent process."
        )
    if ioc_analysis and all("ioc" not in item.lower() for item in normalized):
        normalized.append(
            "Prioritaskan pengecekan IOC dengan threat level tertinggi pada endpoint, firewall, proxy, atau kontrol deteksi yang tersedia."
        )

    return normalized[:8]


def select_priority_anomaly(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Select the highest-scoring anomaly, preferring strict anomalies on ties."""
    if not anomalies:
        return {}

    def priority(anomaly: Dict[str, Any]) -> Tuple[float, int]:
        score = anomaly.get("anomaly_score") or anomaly.get("score") or 0
        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            numeric_score = 0.0
        return numeric_score, int(bool(anomaly.get("strict_is_anomaly")))

    return max(anomalies, key=priority)


def format_anomaly_context(anomaly: Dict[str, Any]) -> str:
    """Format an anomaly as concise report recommendation context."""
    if not anomaly:
        return "window anomali prioritas"

    parts = [f"window {anomaly.get('window_id', '-')}"]
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


def collect_affected_artifacts(anomalies: List[Dict[str, Any]]) -> str:
    """Collect high-value artifact hints from anomaly metadata."""
    values: List[str] = []
    keys = [
        "image",
        "command_line",
        "parent_image",
        "target_object",
        "destination_ip",
        "query_name",
        "user",
    ]

    for anomaly in anomalies:
        anomalous_line = anomaly.get("anomalous_line") or {}
        if isinstance(anomalous_line, dict):
            fields = anomalous_line.get("important_fields") or {}
            if isinstance(fields, dict):
                for key in keys:
                    value = fields.get(key)
                    if value:
                        values.append(f"{key}={value}")

        indicators = anomaly.get("window_key_indicators") or {}
        if isinstance(indicators, dict):
            for key in keys:
                for value in indicators.get(key) or []:
                    if value:
                        values.append(f"{key}={value}")

    deduped = []
    seen = set()
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(value)
        if len(deduped) >= 4:
            break

    return ", ".join(deduped)


def format_ioc_values(iocs: List[Dict[str, Any]]) -> str:
    """Format IOC values for recommendation prose."""
    values = []
    for ioc in iocs:
        ioc_type = ioc.get("type", "ioc")
        value = ioc.get("value")
        if value:
            values.append(f"{ioc_type} `{value}`")
    return ", ".join(values)


def clean_recommendation(text: str) -> str:
    """Normalize a recommendation sentence from LLM or fallback content."""
    cleaned = common.clean_text(text)
    cleaned = re.sub(r"^[^A-Za-z\u00c0-\u00ff0-9]+", "", cleaned).strip()
    cleaned = cleaned.replace("persist ence", "persistence")
    replacements = {
        "Verify sistem": "Verifikasi sistem",
        "Collect additional context": "Kumpulkan konteks tambahan",
        "Enhance logging": "Tingkatkan logging",
        "Review anomali DeepLog": "Tinjau anomali DeepLog",
        "Monitor sistem": "Monitor sistem",
    }
    for source, target in replacements.items():
        if cleaned.startswith(source):
            cleaned = cleaned.replace(source, target, 1)
    return cleaned
