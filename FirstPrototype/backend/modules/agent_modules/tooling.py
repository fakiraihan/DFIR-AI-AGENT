"""Threat-intel tool-call helpers for the DFIR agent."""

from typing import Any, Callable, Dict, List, Mapping, Optional


IdentifyIocType = Callable[[str], Optional[str]]
ToolResultPredicate = Callable[[Dict[str, Any]], bool]
ToolCallKey = tuple[str, str, str]


def normalize_tool_name(tool_name: Any, aliases: Mapping[str, str]) -> str:
    """Normalize provider/result aliases into executable agent tool names."""
    normalized = str(tool_name or "").strip().lower()
    return aliases.get(normalized, normalized)


def extract_tool_result_ioc(result: Mapping[str, Any]) -> str:
    """Return the IOC value from any supported provider result shape."""
    return str(
        result.get("ioc")
        or result.get("ip")
        or result.get("domain")
        or result.get("url")
        or result.get("hash")
        or ""
    )


def tool_call_key(call: Mapping[str, Any], aliases: Mapping[str, str]) -> ToolCallKey:
    """Build the canonical key for a requested tool call."""
    tool_name = normalize_tool_name(call.get("tool"), aliases)
    ioc_type = str(call.get("ioc_type") or "").lower()
    ioc_value = str(call.get("ioc") or "")
    return (tool_name, ioc_type, ioc_value)


def tool_result_key(
    result: Mapping[str, Any],
    aliases: Mapping[str, str],
    identify_ioc_type: IdentifyIocType,
) -> Optional[ToolCallKey]:
    """Build the canonical key for an observed tool result."""
    tool_name = normalize_tool_name(result.get("tool_call") or result.get("tool"), aliases)
    ioc_value = extract_tool_result_ioc(result)
    ioc_type = str(result.get("ioc_type") or "").lower()
    if not ioc_type and ioc_value:
        ioc_type = identify_ioc_type(ioc_value) or ""

    if not tool_name or not ioc_type or not ioc_value:
        return None
    return (tool_name, ioc_type, str(ioc_value))


def attempted_tool_call_keys(
    state: Mapping[str, Any],
    aliases: Mapping[str, str],
    identify_ioc_type: IdentifyIocType,
) -> set[ToolCallKey]:
    """Return tool/IOC combinations that already produced an observation."""
    keys = set()
    for result in state.get("tool_results") or []:
        key = tool_result_key(result, aliases, identify_ioc_type)
        if key:
            keys.add(key)
    return keys


def build_tool_call(
    ioc: Any,
    ioc_type: Any,
    tool: Any,
    aliases: Mapping[str, str],
    *,
    selection_source: str = "fallback_heuristic",
    selection_reason: str = "static IOC-to-tool mapping",
    expected_evidence: str = "IOC reputation and provider status",
) -> Dict[str, Any]:
    """Create a traceable threat-intel tool call without changing core keys."""
    source = (
        selection_source
        if selection_source in {"llm", "fallback_heuristic"}
        else "fallback_heuristic"
    )
    return {
        "ioc": str(ioc or ""),
        "ioc_type": str(ioc_type or "").lower(),
        "tool": normalize_tool_name(tool, aliases),
        "selection_source": source,
        "selection_reason": selection_reason or "static IOC-to-tool mapping",
        "expected_evidence": expected_evidence or "IOC reputation and provider status",
    }


def dedupe_tool_calls(
    tool_calls: List[Dict[str, Any]],
    tool_to_ioc_types: Mapping[str, set[str]],
    aliases: Mapping[str, str],
) -> List[Dict[str, Any]]:
    """Normalize and deduplicate executable tool calls while preserving order."""
    deduped = []
    seen = set()

    for call in tool_calls:
        tool_name = normalize_tool_name(call.get("tool"), aliases)
        ioc_type = str(call.get("ioc_type") or "").lower()
        ioc_value = str(call.get("ioc") or "")
        if not tool_name or not ioc_type or not ioc_value:
            continue
        if tool_name not in tool_to_ioc_types:
            continue
        if ioc_type not in tool_to_ioc_types.get(tool_name, set()):
            continue

        normalized_call = build_tool_call(
            ioc_value,
            ioc_type,
            tool_name,
            aliases,
            selection_source=str(call.get("selection_source") or "fallback_heuristic"),
            selection_reason=str(call.get("selection_reason") or "validated tool call"),
            expected_evidence=str(
                call.get("expected_evidence") or "IOC reputation and provider status"
            ),
        )
        key = tool_call_key(normalized_call, aliases)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(normalized_call)

    return deduped


def tool_selection_trace(tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build additive audit records for selected tool calls."""
    trace = []
    for index, call in enumerate(tool_calls, start=1):
        trace.append(
            {
                "sequence": index,
                "tool": call.get("tool"),
                "ioc": call.get("ioc"),
                "ioc_type": call.get("ioc_type"),
                "selection_source": call.get("selection_source", "fallback_heuristic"),
                "selection_reason": call.get("selection_reason", "validated tool call"),
                "expected_evidence": call.get(
                    "expected_evidence", "IOC reputation and provider status"
                ),
                "status": "selected",
            }
        )
    return trace


def memory_strategy_tool_names(
    strategy: Mapping[str, Any], memory_tool_to_agent_tool: Mapping[str, str]
) -> List[str]:
    """Convert ProceduralMemory primary/fallback tool keys to agent tool names."""
    tool_names = []
    raw_tools = [strategy.get("primary")] + list(strategy.get("fallback") or [])

    for raw_tool in raw_tools:
        tool_name = agent_tool_name(raw_tool, memory_tool_to_agent_tool)
        if not tool_name or tool_name in tool_names:
            continue
        tool_names.append(tool_name)

    return tool_names


def agent_tool_name(
    memory_tool_name: Any, memory_tool_to_agent_tool: Mapping[str, str]
) -> Optional[str]:
    """Convert a memory tool key into an executable agent tool name."""
    normalized = str(memory_tool_name or "").strip().lower()
    if not normalized:
        return None
    return memory_tool_to_agent_tool.get(normalized)


def memory_tool_name(
    agent_tool_name_value: Any,
    aliases: Mapping[str, str],
    agent_tool_to_memory_tool: Mapping[str, str],
) -> str:
    """Convert an executable agent tool name into a memory tool key."""
    normalized = normalize_tool_name(agent_tool_name_value, aliases)
    return agent_tool_to_memory_tool.get(normalized, normalized)


def tool_result_succeeded(result: Mapping[str, Any]) -> bool:
    """Return true when a provider result is a usable observation."""
    if result.get("error") or result.get("status") == "error":
        return False
    if result.get("status") == "skipped" or result.get("skipped"):
        return False
    return True


def get_tool_call_skip_reason(
    tool_name: str,
    ioc: str,
    ioc_type: str,
    tool_to_ioc_types: Mapping[str, set[str]],
    ioc_types: set[str],
    identify_ioc_type: IdentifyIocType,
) -> Optional[str]:
    """Validate whether a requested tool call should be skipped."""
    supported_ioc_types = tool_to_ioc_types.get(tool_name)
    if supported_ioc_types is None:
        return f"unsupported tool '{tool_name}'"

    normalized_ioc_type = str(ioc_type or "").lower()
    if not str(ioc or "").strip():
        return "empty IOC value"
    if normalized_ioc_type not in ioc_types:
        return f"unsupported IOC type '{ioc_type}'"

    if normalized_ioc_type not in supported_ioc_types:
        return f"tool '{tool_name}' does not support IOC type '{ioc_type}'"

    identified_ioc_type = identify_ioc_type(ioc)
    if identified_ioc_type is None:
        return "IOC value failed validation"

    if identified_ioc_type != normalized_ioc_type:
        return (
            f"IOC value matches type '{identified_ioc_type}', not '{normalized_ioc_type}'"
        )

    return None


def validate_tool_call_for_audit(
    call: Mapping[str, Any],
    default_status: str,
    aliases: Mapping[str, str],
    tool_to_ioc_types: Mapping[str, set[str]],
    ioc_types: set[str],
    identify_ioc_type: IdentifyIocType,
) -> Dict[str, Any]:
    """Return a deterministic validation record for a proposed tool call."""
    tool_name = normalize_tool_name(call.get("tool"), aliases)
    ioc = str(call.get("ioc") or "")
    ioc_type = str(call.get("ioc_type") or "").lower()
    reason = get_tool_call_skip_reason(
        tool_name, ioc, ioc_type, tool_to_ioc_types, ioc_types, identify_ioc_type
    )
    status = "rejected" if reason else default_status
    return {
        "tool": tool_name,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "status": status,
        "reason": reason or "validated",
        "selection_source": call.get("selection_source", "fallback_heuristic"),
        "selection_reason": call.get("selection_reason", "validated tool call"),
        "expected_evidence": call.get(
            "expected_evidence", "IOC reputation and provider status"
        ),
    }


def select_new_tool_calls(
    state: Mapping[str, Any],
    state_key: str,
    tool_to_ioc_types: Mapping[str, set[str]],
    aliases: Mapping[str, str],
    identify_ioc_type: IdentifyIocType,
) -> List[Dict[str, Any]]:
    """Return queued calls that have not produced observations yet."""
    tool_calls = state.get(state_key) or []
    if not tool_calls:
        return []

    attempted_keys = attempted_tool_call_keys(state, aliases, identify_ioc_type)
    return [
        call
        for call in dedupe_tool_calls(tool_calls, tool_to_ioc_types, aliases)
        if tool_call_key(call, aliases) not in attempted_keys
    ]


def fallback_tool_selection(
    iocs: List[Dict[str, Any]],
    static_fallback_tools: Mapping[str, List[str]],
    aliases: Mapping[str, str],
) -> List[Dict[str, Any]]:
    """Fallback tool selection using static IOC-to-tool heuristics."""
    tool_calls = []

    for ioc in iocs:
        ioc_type = ioc["type"]
        ioc_value = ioc["value"]
        if ioc_type == "ip":
            reason = "IP IOC static enrichment playbook"
        elif ioc_type == "domain":
            reason = "Domain IOC static enrichment playbook"
        elif ioc_type == "url":
            reason = "URL IOC static enrichment playbook"
        elif ioc_type in ["md5", "sha256"]:
            reason = "Hash IOC static enrichment playbook"
        else:
            continue

        for tool_name in static_fallback_tools[ioc_type]:
            tool_calls.append(
                build_tool_call(
                    ioc_value,
                    ioc_type,
                    tool_name,
                    aliases,
                    selection_source="fallback_heuristic",
                    selection_reason=reason,
                )
            )

    return tool_calls


def parse_tool_selections(
    llm_response: str,
    iocs: List[Dict[str, Any]],
    tool_to_ioc_types: Mapping[str, set[str]],
    static_fallback_tools: Mapping[str, List[str]],
    aliases: Mapping[str, str],
) -> List[Dict[str, Any]]:
    """Parse LLM response for tool selections."""
    tool_calls = []
    allowed_tools = set(tool_to_ioc_types)
    valid_iocs = {
        (str(ioc.get("type", "")).lower(), str(ioc.get("value", ""))) for ioc in iocs
    }

    lines = llm_response.split("\n")
    for line in lines:
        if "->" not in line:
            continue
        try:
            ioc_part, tool_name = line.split("->")
            ioc_type, ioc_value = ioc_part.strip().split(":", 1)
            ioc_type = ioc_type.strip().lower()
            ioc_value = ioc_value.strip()
            tool_name = tool_name.strip().lower()

            if tool_name not in allowed_tools:
                continue
            if ioc_type not in tool_to_ioc_types.get(tool_name, set()):
                continue
            if (ioc_type, ioc_value) not in valid_iocs:
                continue

            tool_calls.append(
                build_tool_call(
                    ioc_value,
                    ioc_type,
                    tool_name,
                    aliases,
                    selection_source="llm",
                    selection_reason="LLM selected supported tool for extracted IOC",
                    expected_evidence="Provider reputation verdict, status, and detection counts where available",
                )
            )
        except (TypeError, ValueError):
            continue

    if not tool_calls:
        tool_calls = fallback_tool_selection(iocs, static_fallback_tools, aliases)

    return tool_calls


def follow_up_ioc_keys(
    state: Mapping[str, Any],
    identify_ioc_type: IdentifyIocType,
    is_malicious_tool_result: ToolResultPredicate,
    is_suspicious_tool_result: ToolResultPredicate,
) -> set[tuple[str, str]]:
    """Return IOC keys that deserve another enrichment round."""
    keys = set()
    for result in state.get("tool_results") or []:
        if not (is_malicious_tool_result(result) or is_suspicious_tool_result(result)):
            continue

        ioc_value = extract_tool_result_ioc(result)
        if not ioc_value:
            continue

        ioc_type = str(result.get("ioc_type") or "").lower()
        if not ioc_type:
            ioc_type = identify_ioc_type(ioc_value) or ""
        if ioc_type:
            keys.add((ioc_type, str(ioc_value)))

    return keys


def select_follow_up_tool_calls(
    state: Mapping[str, Any],
    static_fallback_tools: Mapping[str, List[str]],
    aliases: Mapping[str, str],
    identify_ioc_type: IdentifyIocType,
    is_malicious_tool_result: ToolResultPredicate,
    is_suspicious_tool_result: ToolResultPredicate,
) -> List[Dict[str, Any]]:
    """Select unqueried enrichment tools for IOCs with suspicious observations."""
    iocs = state.get("iocs_extracted") or []
    follow_up_keys = follow_up_ioc_keys(
        state, identify_ioc_type, is_malicious_tool_result, is_suspicious_tool_result
    )
    if not iocs or not follow_up_keys:
        return []

    candidate_iocs = [
        ioc
        for ioc in iocs
        if (str(ioc.get("type", "")).lower(), str(ioc.get("value", "")))
        in follow_up_keys
    ]
    attempted_keys = attempted_tool_call_keys(state, aliases, identify_ioc_type)
    selected_calls = []
    selected_keys = set()

    for call in fallback_tool_selection(candidate_iocs, static_fallback_tools, aliases):
        key = tool_call_key(call, aliases)
        if key in attempted_keys or key in selected_keys:
            continue
        selected_calls.append(call)
        selected_keys.add(key)

    return selected_calls
