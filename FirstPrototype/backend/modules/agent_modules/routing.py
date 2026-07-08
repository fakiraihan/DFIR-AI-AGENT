"""Graph routing helpers for the DFIR agent."""

from typing import Any, Callable, Dict, List, Mapping


CoerceInt = Callable[[Any, int], int]
FollowUpSelector = Callable[[Mapping[str, Any]], List[Dict[str, Any]]]


def route_after_ioc_extraction(state: Mapping[str, Any]) -> str:
    """Route directly to a safe context-only result when no valid IOC exists."""
    if state.get("iocs_extracted"):
        print("IOC extraction routing: has_iocs")
        return "has_iocs"
    print("IOC extraction routing: no_iocs")
    return "no_iocs"


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
            "Reflection routing: ready_to_report "
            f"(limit reached: {current_round}/{max_rounds})"
        )
        return "ready_to_report"

    follow_up_calls = select_new_reflection_tool_calls(state)
    if follow_up_calls:
        print(
            "Reflection routing: needs_follow_up "
            f"({len(follow_up_calls)} targeted follow-up calls)"
        )
        return "needs_follow_up"

    print("Reflection routing: ready_to_report")
    return "ready_to_report"
