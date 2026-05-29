"""IOC analysis section builder."""

from typing import Any, Dict, List, Tuple

from . import common


def build_ioc_analysis(
    iocs: List[Dict[str, Any]], tool_results: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Merge IOC list with curated threat context."""
    result_by_ioc: Dict[str, Dict[str, Any]] = {}
    for item in tool_results:
        if common.is_skipped_result(item):
            continue

        ioc_value = common.normalize_ioc_value(
            item.get("ioc") or item.get("ip") or item.get("url") or item.get("hash")
        )
        normalized_key = ioc_value.lower()
        if not normalized_key:
            continue

        existing = result_by_ioc.get(normalized_key)
        if existing is None or common.tool_result_priority(
            item
        ) > common.tool_result_priority(existing):
            result_by_ioc[normalized_key] = item

    curated: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for ioc in iocs:
        ioc_type = str(ioc.get("type", "unknown")).lower()
        value = common.normalize_ioc_value(ioc.get("value"))
        if not value or common.is_low_signal_ioc(ioc_type, value):
            continue

        key = (ioc_type, value.lower())
        tool_info = result_by_ioc.get(value.lower(), {})
        candidate = {
            "type": ioc_type,
            "value": value,
            "threat_level": common.infer_threat_level(tool_info),
            "threat_intel": common.summarize_tool_result(tool_info),
            "source_line": ioc.get("source_line"),
            "source_window": ioc.get("window_id"),
            "_priority": common.ioc_priority(ioc_type, tool_info),
        }

        existing = curated.get(key)
        if existing is None or candidate["_priority"] > existing["_priority"]:
            curated[key] = candidate

    ranked = sorted(
        curated.values(),
        key=lambda item: (-item["_priority"], item["type"], item["value"]),
    )

    for item in ranked:
        item.pop("_priority", None)

    return ranked[:25]
