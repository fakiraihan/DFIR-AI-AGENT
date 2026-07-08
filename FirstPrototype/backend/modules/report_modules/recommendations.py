"""Recommendation builders for structured DFIR reports."""

from typing import Any, Dict, List, Tuple
import re

from . import common

_VALUE_TOKEN_RE = re.compile(r"`[^`]*`|\b\d+(?:\.\d+)*\b|\b[0-9a-f]{8,}\b")
_STOPWORDS = {
    "dan", "atau", "yang", "pada", "dengan", "untuk", "dari", "ke", "di",
    "sebelum", "agar", "bisa", "serta", "berikut", "ini", "itu", "the", "and",
}

NIST_PHASE_KEYWORDS: List[Tuple[str, Tuple[str, ...]]] = [
    ("Containment", ("containment", "isolasi", "isolir", "blokir", "block", "hunt", "sinkhole", "quarantine")),
    ("Eradication", ("eradication", "hapus", "karantina", "remove", "bersihkan", "cabut akses")),
    ("Recovery", ("recovery", "pulihkan", "restore", "reimage", "recover")),
    ("Detection & Analysis", ("validasi", "triase", "kumpulkan", "rekonstruksi", "korelasikan", "monitor", "review", "analisis")),
]


def nist_phase_for(text: str) -> str:
    """Map a recommendation sentence to the closest NIST SP 800-61 phase."""
    lowered = text.lower()
    for phase, keywords in NIST_PHASE_KEYWORDS:
        if any(keyword in lowered for keyword in keywords):
            return phase
    return "Detection & Analysis"


def _similarity_key(text: str) -> frozenset:
    """Word-set key with IOC values/numbers stripped, for near-duplicate detection."""
    stripped = _VALUE_TOKEN_RE.sub(" ", text.lower())
    words = {word for word in re.findall(r"[a-z]+", stripped) if word not in _STOPWORDS and len(word) > 2}
    return frozenset(words)


def _is_near_duplicate(candidate_key: frozenset, kept_keys: List[frozenset], threshold: float = 0.65) -> bool:
    for kept in kept_keys:
        if not candidate_key or not kept:
            continue
        overlap = len(candidate_key & kept)
        union = len(candidate_key | kept)
        if union and overlap / union >= threshold:
            return True
    return False


# Each rule requires ALL keywords in the tuple to be present (AND), so a
# generic verb like "validasi" alone can't collide with an unrelated but
# specific recommendation (e.g. "Validasi ... unquoted service path" is not
# IOC validation just because it contains the word "validasi").
_ACTION_CATEGORY_RULES: List[Tuple[str, Tuple[str, ...]]] = [
    ("ioc_block", ("ioc", "blokir")),
    ("ioc_block", ("ioc", "block")),
    ("ioc_validate", ("ioc", "validasi")),
    ("ioc_enrich", ("ioc", "enrich")),
    ("artifact_collection", ("kumpulkan", "artefak")),
    ("window_triage", ("triase", "window")),
    ("timeline_reconstruction", ("timeline",)),
    # NOTE: no bare "containment" rule -- severity-triggered full containment
    # and the proportional short-term containment for suspicious-only IOCs
    # are legitimately distinct recommendations that happen to share the
    # word "containment"; a single-keyword category here would collapse them.
]


def _action_category(text: str) -> str | None:
    """Coarse action-intent bucket, to cap same-intent recommendations at one.

    Same-intent recommendations restated by the LLM in different words (mixed
    Indonesian/English paraphrase) share too little raw vocabulary for the
    Jaccard near-duplicate check above to catch them, so this pass groups by
    the underlying action verb + object instead. Rules require all keywords
    to co-occur to avoid collapsing unrelated recommendations that merely
    share one generic verb.
    """
    lowered = text.lower()
    for category, keywords in _ACTION_CATEGORY_RULES:
        if all(keyword in lowered for keyword in keywords):
            return category
    return None


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
        # Proportionate short-term containment for suspicious (not yet
        # confirmed-malicious) IOCs: NIST 800-61 treats enhanced monitoring /
        # rate-limiting as a legitimate light-touch containment strategy,
        # distinct from full block/isolate which would overclaim compromise
        # on suspicious-only evidence.
        recommendations.append(
            f"Sebagai containment jangka pendek yang proporsional, terapkan monitoring intensif dan rate-limiting sementara pada IOC suspicious berikut hingga statusnya terkonfirmasi, tanpa tindakan pemutusan akses permanen: {format_ioc_values(suspicious_iocs[:5])}."
        )

    if malicious_iocs:
        recommendations.append(
            "Pasca penanganan temuan malicious di atas, periksa integritas host terkait sebelum kembali ke operasi normal (recovery); pertimbangkan reimage bila ditemukan mekanisme persistence tambahan pada host tersebut."
        )

    if top_anomaly:
        recommendations.append(
            f"Triase window DeepLog prioritas {anomaly_context}; cek process tree, user, parent process, command line, dan raw event di sekitar window tersebut."
        )

    if affected_artifacts:
        recommendations.append(
            f"Kumpulkan artefak host yang terkait dengan {affected_artifacts}: event log lengkap, process execution evidence, registry/persistence keys, dan network connection history."
        )
        first_artifact = affected_artifacts.split(",")[0].strip()
        recommendations.append(
            f"Jalankan query EDR/SIEM dengan filter {first_artifact} pada rentang waktu insiden untuk memvalidasi eksekusi, proses induk, dan koneksi jaringan terkait sebelum menyimpulkan false positive/positive."
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
    """Clean, deduplicate near-duplicates, tag NIST phase, and cap report recommendations."""
    normalized: List[str] = []
    seen: set = set()
    kept_keys: List[frozenset] = []
    seen_categories: set = set()
    for recommendation in recommendations:
        cleaned = clean_recommendation(recommendation)
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        category = _action_category(cleaned)
        if category is not None and category in seen_categories:
            continue
        similarity_key = _similarity_key(cleaned)
        if _is_near_duplicate(similarity_key, kept_keys):
            continue
        seen.add(key)
        kept_keys.append(similarity_key)
        if category is not None:
            seen_categories.add(category)
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

    tagged = [f"[{nist_phase_for(item)}] {item}" for item in normalized[:8]]
    return tagged


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
            parts.append(f"score {float(score):.4f}")
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
