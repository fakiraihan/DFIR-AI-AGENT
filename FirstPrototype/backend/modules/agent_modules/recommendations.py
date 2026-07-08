"""Recommendation and assessment helpers for the DFIR agent."""

import re
from typing import Any, Callable, Dict, List, Mapping, Sequence


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
    tactic = extract_eval_tactic(state)
    priority_anomaly = select_tactic_priority_anomaly(anomalies, tactic) or select_priority_anomaly(anomalies)
    anomaly_context = format_anomaly_recommendation_context(priority_anomaly)
    artifact_context = format_anomaly_artifacts(
        priority_anomaly, summarize_anomaly_details
    )
    top_iocs = format_ioc_sample(iocs)

    recommendations.extend(
        generate_tactic_specific_recommendations(
            state,
            summarize_anomaly_details=summarize_anomaly_details,
            tactic=tactic,
        )
    )

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

    return dedupe_recommendations(recommendations)[:10]


def extract_eval_tactic(state: Mapping[str, Any]) -> str:
    """Read the current evaluation tactic from explicit state/brief context."""
    direct = str(state.get("tactic_folder") or state.get("tactic") or "").strip()
    if direct:
        return direct

    brief = str(state.get("evaluation_evidence_brief") or "")
    for pattern in (
        r"tactic_folder:\s*([^\n]+)",
        r"Tactic lock:\s*analyze this case as\s*([^\n.]+)",
    ):
        match = re.search(pattern, brief, flags=re.IGNORECASE)
        if match:
            return _compact_text(match.group(1), max_chars=80)
    return ""


def select_tactic_priority_anomaly(
    anomalies: Sequence[Dict[str, Any]], tactic: str
) -> Dict[str, Any]:
    """Select a tactic-relevant anomaly before falling back to score priority."""
    tactic_key = str(tactic or "").strip().lower()
    if not anomalies or not tactic_key:
        return {}

    event_priorities: list[str] = []
    if "defense evasion" in tactic_key:
        event_priorities = ["1102", "4663", "5156"]
    elif "discovery" in tactic_key:
        event_priorities = ["4661", "5145", "5140", "4672", "5158"]
    elif "privilege escalation" in tactic_key:
        event_priorities = ["11", "12", "13", "1"]

    for event_id in event_priorities:
        matches = [
            anomaly
            for anomaly in anomalies
            if _anomaly_has_event_id(anomaly, event_id)
        ]
        if matches:
            return max(matches, key=_tactic_priority_score)
    return {}


def generate_tactic_specific_recommendations(
    state: Mapping[str, Any],
    *,
    summarize_anomaly_details: AnomalySummarizer,
    tactic: str | None = None,
) -> List[str]:
    """Build next actions that are specific to the selected ATT&CK tactic."""
    anomalies = list(state.get("anomalies", []) or [])
    tactic_text = tactic or extract_eval_tactic(state)
    tactic_key = str(tactic_text or "").strip().lower()
    if not anomalies or not tactic_key:
        return []

    if "defense evasion" in tactic_key:
        return _defense_evasion_recommendations(anomalies)
    if "discovery" in tactic_key:
        return _discovery_recommendations(anomalies)
    if "privilege escalation" in tactic_key:
        return _privilege_escalation_recommendations(anomalies)
    return []


def dedupe_recommendations(recommendations: Sequence[str]) -> List[str]:
    """Deduplicate recommendations while preserving order."""
    deduped: List[str] = []
    seen = set()
    for recommendation in recommendations:
        cleaned = re.sub(r"\s+", " ", str(recommendation or "")).strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cleaned)
    return deduped


def _defense_evasion_recommendations(anomalies: Sequence[Dict[str, Any]]) -> List[str]:
    recommendations: List[str] = []
    cleared_log = _find_anomaly_by_event(anomalies, "1102")
    registry_access = _find_anomaly_by_event(
        anomalies,
        "4663",
        required_tokens=("registry", "lsa"),
    ) or _find_anomaly_by_event(anomalies, "4663")

    if cleared_log:
        host = _field(cleared_log, "computer", "domain") or "host terkait"
        recommendations.append(
            "Triase Defense Evasion EventID 1102 pada "
            f"{host}; verifikasi akun/proses yang melakukan security log cleared, "
            f"korelasikan {_window_reference(cleared_log)} dengan event sebelum/sesudah, "
            "dan pastikan audit policy serta Windows Event Log service tidak dimodifikasi."
        )

    if registry_access:
        object_name = _field(registry_access, "object_name", "objectname") or "registry key terkait"
        process_name = _field(registry_access, "process_name", "processname") or "process terkait"
        user = _field(registry_access, "subject_user", "subjectusername", "user") or "user terkait"
        recommendations.append(
            "Review EventID 4663 registry access pada "
            f"{object_name} oleh {user} melalui {process_name}; validasi akses ke "
            "Lsa/FipsAlgorithmPolicy sebagai perubahan sah atau indikasi audit/log tampering."
        )

    return recommendations


def _discovery_recommendations(anomalies: Sequence[Dict[str, Any]]) -> List[str]:
    recommendations: List[str] = []
    directory_access = _find_anomaly_by_event(
        anomalies,
        "4661",
        preferred_tokens=("administrator", "sam_domain", "dc=example"),
    ) or _find_anomaly_by_event(anomalies, "4661")
    samr_access = _find_anomaly_by_event(
        anomalies,
        "5145",
        preferred_tokens=("samr", "ipc$"),
    )

    if directory_access:
        user = _field(directory_access, "subject_user", "subjectusername", "user") or "akun terkait"
        object_name = _field(directory_access, "object_name", "objectname") or "directory object terkait"
        object_type = _field(directory_access, "object_type", "objecttype") or "object"
        access_mask = _field(directory_access, "access_mask", "accessmask") or "access mask tidak tersedia"
        process_name = _field(directory_access, "process_name", "processname") or "process terkait"
        recommendations.append(
            "Validasi Discovery EventID 4661: tentukan apakah "
            f"{user} berwenang melakukan enumerasi {object_type} {object_name} "
            f"dengan AccessMask {access_mask} melalui {process_name}; cocokkan dengan membership "
            "Domain Admins, change ticket, dan baseline administrasi direktori."
        )

    if samr_access:
        user = _field(samr_access, "subject_user", "subjectusername", "user") or "akun terkait"
        share = _field(samr_access, "share_name", "sharename") or "share terkait"
        target = _field(samr_access, "relative_target_name", "relativetargetname") or "target terkait"
        source = _field(samr_access, "destination_ip", "ipaddress") or "alamat sumber/tujuan terkait"
        recommendations.append(
            "Korelasikan akses SAMR/IPC Discovery dari "
            f"{user} ke {share}\\{target} pada {source}; verifikasi apakah enumerasi group/object "
            "tersebut berasal dari aktivitas administrasi sah atau reconnaissance."
        )

    return recommendations


def _privilege_escalation_recommendations(
    anomalies: Sequence[Dict[str, Any]]
) -> List[str]:
    recommendations: List[str] = []
    file_create = _find_anomaly_by_event(
        anomalies,
        "11",
        preferred_tokens=("c:\\program.exe", "unquoted", "cmd.exe"),
    ) or _find_anomaly_by_event(anomalies, "11")
    process_context = _find_anomaly_by_event(
        anomalies,
        "1",
        preferred_tokens=("services.exe", "svchost.exe", "system"),
    )

    if file_create:
        target = (
            _first_path_token(anomalies, "program.exe")
            or _field(file_create, "target_object", "targetfilename", "target_path")
            or _first_field_value(anomalies, "target_object", "targetfilename", "target_path")
            or "path target terkait"
        )
        image = _field(file_create, "image", "process_name", "processname") or "process terkait"
        user = _field(file_create, "user") or "user terkait"
        recommendations.append(
            "Validasi Privilege Escalation unquoted service path: cek Sysmon EventID 11 "
            f"untuk file {target} yang dibuat oleh {image} sebagai {user}; pastikan service ImagePath "
            "sudah quoted, tidak ada write permission tidak sah pada root/service directory, dan file tersebut dikarantina bila tidak sah."
        )

    if process_context or file_create:
        source = process_context or file_create
        parent = _field(source, "parent_image", "parentimage") or "parent process terkait"
        image = _field(source, "image", "process_name", "processname") or "process terkait"
        process_guid = _field(source, "process_guid", "processguid") or "process guid terkait"
        recommendations.append(
            "Uji privilege boundary dengan memetakan "
            f"{image}, parent {parent}, dan {process_guid}; bandingkan dengan konfigurasi service, "
            "ACL direktori, serta baseline service control manager sebelum menyimpulkan eskalasi berhasil."
        )

    return recommendations


def _find_anomaly_by_event(
    anomalies: Sequence[Dict[str, Any]],
    event_id: str,
    *,
    required_tokens: Sequence[str] = (),
    preferred_tokens: Sequence[str] = (),
) -> Dict[str, Any]:
    matches = [
        anomaly
        for anomaly in anomalies
        if _anomaly_has_event_id(anomaly, event_id)
    ]
    if required_tokens:
        matches = [
            anomaly
            for anomaly in matches
            if all(token.lower() in _anomaly_text(anomaly).lower() for token in required_tokens)
        ]
    if not matches:
        return {}

    if preferred_tokens:
        preferred = [
            anomaly
            for anomaly in matches
            if any(token.lower() in _anomaly_text(anomaly).lower() for token in preferred_tokens)
        ]
        if preferred:
            matches = preferred
    return max(matches, key=_tactic_priority_score)


def _tactic_priority_score(anomaly: Dict[str, Any]) -> tuple[int, float]:
    text = _anomaly_text(anomaly).lower()
    artifact_bonus = int(
        any(
            token in text
            for token in (
                "administrator",
                "domain admins",
                "sam_domain",
                "samr",
                "fipsalgorithmpolicy",
                "security log",
                "c:\\program.exe",
                "unquoted",
            )
        )
    )
    score = anomaly.get("anomaly_score") or anomaly.get("score") or 0
    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        numeric_score = 0.0
    return artifact_bonus, numeric_score


def _anomaly_has_event_id(anomaly: Dict[str, Any], event_id: str) -> bool:
    return bool(re.search(rf"\beventid\s*=?\s*{re.escape(str(event_id))}\b", _anomaly_text(anomaly), flags=re.I))


def _anomaly_text(anomaly: Dict[str, Any]) -> str:
    line = anomaly.get("anomalous_line") or {}
    parts = [
        str(anomaly.get("actual_event") or ""),
        str(line.get("raw_line") or ""),
    ]
    for mapping_name in ("important_fields", "parameters"):
        mapping = line.get(mapping_name) or {}
        if isinstance(mapping, Mapping):
            parts.extend(str(value) for value in mapping.values() if value is not None)
    return " ".join(parts)


def _field(anomaly: Dict[str, Any], *names: str) -> str:
    wanted = {name.lower().replace("_", "") for name in names}
    line = anomaly.get("anomalous_line") or {}
    for mapping_name in ("important_fields", "parameters"):
        mapping = line.get(mapping_name) or {}
        if not isinstance(mapping, Mapping):
            continue
        for key, value in mapping.items():
            normalized = str(key).lower().replace("_", "")
            if normalized in wanted and value not in (None, ""):
                return _compact_text(value, max_chars=120)
    return ""


def _first_field_value(anomalies: Sequence[Dict[str, Any]], *names: str) -> str:
    for anomaly in anomalies:
        value = _field(anomaly, *names)
        if value:
            return value
    return ""


def _first_path_token(anomalies: Sequence[Dict[str, Any]], filename: str) -> str:
    pattern = re.compile(
        rf"[A-Za-z]:\\[^\s,;`\"']*{re.escape(filename)}",
        flags=re.I,
    )
    for anomaly in anomalies:
        match = pattern.search(_anomaly_text(anomaly))
        if match:
            return _compact_text(match.group(0), max_chars=120)
    return ""


def _window_reference(anomaly: Dict[str, Any]) -> str:
    return f"window DeepLog {anomaly.get('window_id', '-')}"


def _compact_text(value: Any, *, max_chars: int = 180) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


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
