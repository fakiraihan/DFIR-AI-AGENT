"""Shared report helper functions."""

from collections import Counter
from typing import Any, Callable, Dict, List
import re


ToolResultPredicate = Callable[[Dict[str, Any]], bool]


def clean_text(text: Any) -> str:
    """Normalize generated or extracted text for report output."""
    if text is None:
        return ""
    cleaned = str(text)
    cleaned = cleaned.replace("<|reserved_special_token_103|>", "")
    cleaned = cleaned.replace("persist ence", "persistence")
    cleaned = re.sub(r"\r\n?", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def normalize_ioc_value(value: Any) -> str:
    """Normalize an IOC value for comparison and display."""
    return str(value).strip() if value is not None else ""


def safe_positive_count(value: Any) -> int:
    """Coerce provider count values into non-negative integers."""
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def is_skipped_result(tool_result: Dict[str, Any]) -> bool:
    """Return true when a tool result was intentionally skipped."""
    if not tool_result:
        return False
    return tool_result.get("status") == "skipped" or bool(tool_result.get("skipped"))


def is_malicious_result(tool_result: Dict[str, Any]) -> bool:
    """Return true when a tool result contains a malicious signal."""
    if not tool_result:
        return False
    return (
        tool_result.get("classification") == "malicious"
        or safe_positive_count(tool_result.get("malicious")) > 0
    )


def is_suspicious_result(tool_result: Dict[str, Any]) -> bool:
    """Return true when a tool result contains a suspicious signal."""
    if not tool_result or is_malicious_result(tool_result):
        return False
    return (
        tool_result.get("classification") == "suspicious"
        or safe_positive_count(tool_result.get("suspicious")) > 0
    )


def count_unique_hits(
    tool_results: List[Dict[str, Any]], predicate: ToolResultPredicate
) -> int:
    """Count unique IOC hits matching a predicate."""
    seen = set()
    for result in tool_results:
        if not predicate(result):
            continue

        ioc_value = normalize_ioc_value(
            result.get("ioc")
            or result.get("ip")
            or result.get("url")
            or result.get("hash")
            or result.get("domain")
        )
        key = ioc_value.lower() if ioc_value else f"__result__:{id(result)}"
        seen.add(key)
    return len(seen)


def count_malicious_hits(tool_results: List[Dict[str, Any]]) -> int:
    """Count unique malicious IOC hits."""
    return count_unique_hits(tool_results, is_malicious_result)


def count_suspicious_hits(tool_results: List[Dict[str, Any]]) -> int:
    """Count unique suspicious IOC hits."""
    return count_unique_hits(tool_results, is_suspicious_result)


def calculate_severity(
    tool_results: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]
) -> str:
    """Calculate report severity from threat-intel and anomaly evidence."""
    malicious_hits = count_malicious_hits(tool_results)

    if malicious_hits >= 3:
        return "HIGH"
    if malicious_hits >= 1 or len(anomalies) >= 10:
        return "MEDIUM"
    return "LOW"


def infer_threat_level(tool_result: Dict[str, Any]) -> str:
    """Map a tool result to report threat-level text."""
    if not tool_result:
        return "low"
    if is_malicious_result(tool_result):
        return "high"
    if is_suspicious_result(tool_result):
        return "medium"
    return "low"


def sanitize_tool_error(tool_result: Dict[str, Any]) -> str:
    """Convert provider errors into report-friendly wording."""
    tool_name = str(tool_result.get("tool", "tool")).upper()
    error_text = str(tool_result.get("error", "")).lower()

    if "api key required" in error_text or "not configured" in error_text:
        return f"{tool_name}: layanan enrichment belum terkonfigurasi"
    if "404" in error_text or "not found" in error_text:
        return f"{tool_name}: tidak ada reputasi publik yang relevan untuk IOC ini"
    if "timeout" in error_text:
        return f"{tool_name}: permintaan enrichment melebihi batas waktu"
    return f"{tool_name}: enrichment sementara tidak tersedia"


def summarize_tool_result(tool_result: Dict[str, Any]) -> str:
    """Summarize a provider result for report sections."""
    if not tool_result:
        return "Belum ada data enrichment eksternal untuk IOC ini"

    if tool_result.get("error"):
        return sanitize_tool_error(tool_result)

    tool_name = str(tool_result.get("tool", "tool")).upper()
    parts: List[str] = [tool_name]

    classification = tool_result.get("classification")
    if classification:
        parts.append(f"classification={classification}")

    malicious = tool_result.get("malicious")
    if malicious is not None:
        parts.append(f"malicious={malicious}")

    suspicious = tool_result.get("suspicious")
    if suspicious is not None:
        parts.append(f"suspicious={suspicious}")

    pulse_count = tool_result.get("pulse_count")
    if pulse_count is not None:
        parts.append(f"pulse_count={pulse_count}")

    return (
        ", ".join(parts)
        if len(parts) > 1
        else f"{tool_name}: tidak ada indikator reputasi yang menonjol"
    )


def tool_result_priority(tool_result: Dict[str, Any]) -> int:
    """Rank tool-result usefulness for IOC analysis."""
    if is_skipped_result(tool_result):
        return 0
    if is_malicious_result(tool_result):
        return 3
    if is_suspicious_result(tool_result):
        return 2
    if tool_result and not tool_result.get("error"):
        return 1
    return 0


def derive_verdict(
    severity: str,
    malicious_hits: int,
    suspicious_hits: int,
    anomalies: List[Dict[str, Any]],
) -> str:
    """Derive a concise investigation verdict for the executive summary."""
    if malicious_hits > 0:
        return "indikasi ancaman aktif perlu diprioritaskan"
    if suspicious_hits > 0 or severity == "MEDIUM":
        return "aktivitas mencurigakan memerlukan validasi manual"
    if anomalies:
        return "anomali terdeteksi namun belum ada konfirmasi threat intelligence yang kuat"
    return "tidak ada indikasi ancaman yang cukup kuat pada data saat ini"


def ioc_priority(ioc_type: str, tool_info: Dict[str, Any]) -> int:
    """Rank IOC usefulness for report display."""
    base = {"ip": 5, "url": 4, "sha256": 4, "md5": 3, "domain": 2}.get(ioc_type, 1)
    if is_malicious_result(tool_info):
        base += 5
    elif is_suspicious_result(tool_info):
        base += 3
    elif tool_info and not tool_info.get("error") and not is_skipped_result(tool_info):
        base += 1
    return base


def ioc_type_label(ioc_type: str) -> str:
    """Return a concise user-facing IOC type label."""
    labels = {
        "ip": "IP",
        "domain": "Domain",
        "url": "URL",
        "sha256": "SHA256",
        "md5": "MD5",
    }
    return labels.get(str(ioc_type or "").lower(), "IOC")


def format_ioc_indicator(ioc_type: str, value: str) -> str:
    """Format an IOC with its type so analysts can scan it quickly."""
    return f"{ioc_type_label(ioc_type)}: {value}"


def is_low_signal_ioc(ioc_type: str, value: str) -> bool:
    """Filter low-signal IOC-like values from report IOC analysis."""
    lowered = value.lower()
    if not lowered:
        return True
    if ioc_type == "domain":
        if lowered.endswith(
            (".exe", ".dll", ".tmp", ".sys", ".dat", ".bat", ".cmd", ".ps1", ".vbs")
        ):
            return True
        if lowered in {"localhost", "microsoft.net"}:
            return True
    return False


def top_anomalous_events(anomalies: List[Dict[str, Any]]) -> str:
    """Format the most common anomalous event templates."""
    events = [
        str(item.get("actual_event", "")).strip()
        for item in anomalies
        if item.get("actual_event")
    ]
    if not events:
        return ""
    counts = Counter(events)
    return ", ".join(
        f"{event} ({count}x)" for event, count in counts.most_common(3)
    )
