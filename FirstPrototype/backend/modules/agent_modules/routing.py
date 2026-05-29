"""Graph routing helpers for the DFIR agent."""

from typing import Any, Callable, Dict, List, Mapping


CoerceInt = Callable[[Any, int], int]
StatePredicate = Callable[[Mapping[str, Any]], bool]
FollowUpSelector = Callable[[Mapping[str, Any]], List[Dict[str, Any]]]


def route_after_ioc_extraction(state: Mapping[str, Any]) -> str:
    """Route directly to a safe context-only result when no valid IOC exists."""
    if state.get("iocs_extracted"):
        print("IOC extraction routing: has_iocs")
        return "has_iocs"
    print("IOC extraction routing: no_iocs")
    return "no_iocs"


def decide_next_step(
    state: Mapping[str, Any],
    *,
    default_max_tool_execution_rounds: int,
    coerce_int: CoerceInt,
    has_successful_normalized_evidence: StatePredicate,
    select_follow_up_tool_calls: FollowUpSelector,
) -> str:
    """Route the graph based on observations from the latest tool round."""
    iocs = state.get("iocs_extracted") or []
    if not iocs:
        print("Routing decision: no_iocs (no extracted IOCs to enrich)")
        return "no_iocs"

    current_round = coerce_int(state.get("tool_execution_round"), 0)
    max_rounds = coerce_int(
        state.get("max_tool_execution_rounds"), default_max_tool_execution_rounds
    )
    if current_round >= max_rounds:
        print(
            "Routing decision: sufficient_intel "
            f"(tool round limit reached: {current_round}/{max_rounds})"
        )
        return "sufficient_intel"

    if current_round > 0 and not has_successful_normalized_evidence(state):
        print(
            "Routing decision: no_successful_evidence "
            "(no successful non-skipped enrichment evidence)"
        )
        return "no_successful_evidence"

    follow_up_calls = select_follow_up_tool_calls(state)
    if follow_up_calls:
        print(
            "Routing decision: needs_more_intel "
            f"({len(follow_up_calls)} unqueried enrichment tools available)"
        )
        return "needs_more_intel"

    print("Routing decision: sufficient_intel (no follow-up tools needed)")
    return "sufficient_intel"


def decide_post_correlation_step(
    state: Mapping[str, Any],
    *,
    default_max_reflection_rounds: int,
    coerce_int: CoerceInt,
    select_new_reflection_tool_calls: FollowUpSelector,
) -> str:
    """Route after reflection without changing the existing tool-executor router."""
    if not state.get("iocs_extracted"):
        print("Reflection routing: no_iocs")
        return "no_iocs"

    current_round = coerce_int(state.get("reflection_round"), 0)
    max_rounds = coerce_int(
        state.get("max_reflection_rounds"), default_max_reflection_rounds
    )
    if current_round > max_rounds:
        print(
            "Reflection routing: sufficient_after_reflection "
            f"(limit reached: {current_round}/{max_rounds})"
        )
        return "sufficient_after_reflection"

    follow_up_calls = select_new_reflection_tool_calls(state)
    if follow_up_calls:
        print(
            "Reflection routing: more_intel_needed "
            f"({len(follow_up_calls)} targeted follow-up calls)"
        )
        return "more_intel_needed"

    print("Reflection routing: sufficient_after_reflection")
    return "sufficient_after_reflection"
