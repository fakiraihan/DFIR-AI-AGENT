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
            item.get("ioc")
            or item.get("ip")
            or item.get("url")
            or item.get("hash")
            or item.get("domain")
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
            "indicator_type": common.ioc_type_label(ioc_type),
            "value": value,
            "indicator": common.format_ioc_indicator(ioc_type, value),
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

    selected = _select_type_diverse(ranked, limit=25)

    for item in selected:
        item.pop("_priority", None)

    return selected


def _select_type_diverse(
    ranked: List[Dict[str, Any]], limit: int
) -> List[Dict[str, Any]]:
    """Pick up to ``limit`` IOCs while preserving type diversity.

    A flat priority sort collapses to a single type when one type outranks the
    others (e.g. sha256 base-priority beats md5), so a capped slice can drop an
    entire type — e.g. keeping 25 sha256 and dropping 52 md5. Round-robin across
    types (each already priority-sorted) keeps the curated set representative of
    the extracted mix.
    """
    if len(ranked) <= limit:
        return ranked

    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for item in ranked:
        by_type.setdefault(item["type"], []).append(item)

    # Type order follows the highest-priority representative of each type.
    type_order = sorted(
        by_type,
        key=lambda t: (-by_type[t][0]["_priority"], t),
    )

    selected: List[Dict[str, Any]] = []
    cursors = {t: 0 for t in type_order}
    while len(selected) < limit:
        progressed = False
        for ioc_type in type_order:
            cursor = cursors[ioc_type]
            if cursor < len(by_type[ioc_type]):
                selected.append(by_type[ioc_type][cursor])
                cursors[ioc_type] = cursor + 1
                progressed = True
                if len(selected) >= limit:
                    break
        if not progressed:
            break
    return selected
